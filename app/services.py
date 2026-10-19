"""Service checks (HTTP, TCP port, DNS) with a result history, like a small Uptime Kuma.

A check is stored in `service_checks`; every run adds a row to `service_results` and updates the check's current
state. A state change needs two identical results in a row (so one lost packet is not an outage) and is logged as a
`service_down` / `service_up` event, which the notification channels and Home Assistant pick up.
"""

from __future__ import annotations

import asyncio
import threading
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app import tsdb
from app.db import add_event, connect, utcnow

log = logging.getLogger(__name__)

KINDS = ("http", "tcp", "dns", "cert", "process")
MIN_INTERVAL, MAX_INTERVAL = 15, 86400
MAX_TIMEOUT = 30
RESULT_RETENTION_DAYS = 30
MAX_CONCURRENT = 10
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
NAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?$")


class CheckError(ValueError):
    """The definition of a check is not valid."""


@dataclass
class Result:
    up: bool
    ms: float | None
    detail: str
    metrics: dict[str, float] | None = None       # more numbers worth a graph (days left of a certificate)


# ----------------------------------------------------------------------------- validation
def validate_check(data: dict[str, Any]) -> dict[str, Any]:
    """Normalise a check definition from the API; raises CheckError with a message for the user."""
    kind = data.get("kind")
    if kind not in KINDS:
        raise CheckError(f"kind must be one of {', '.join(KINDS)}")
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 100:
        raise CheckError("give the check a name (up to 100 characters)")
    host = str(data.get("host") or "").strip()
    if not HOST_RE.match(host):
        raise CheckError("host must be a hostname or an IP address")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None  # a hostname
    if addr is not None and (addr.is_link_local or addr.is_multicast or addr.is_unspecified):
        raise CheckError("that address cannot be checked")
    port = data.get("port")
    path = str(data.get("path") or "").strip()
    expect = str(data.get("expect") or "").strip()
    if len(expect) > 200 or len(path) > 300:
        raise CheckError("path or expected text is too long")
    if kind == "cert":
        port = 443 if port in (None, "") else port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CheckError("port must be a number from 1 to 65535")
        if expect and not re.fullmatch(r"\d{1,3}|auto|manual", expect):
            raise CheckError("expect is auto (renews itself, warns below 14 days), manual (warns below 30 days) or a number of days; empty picks auto for Let's Encrypt and similar, manual for the rest")
        path = ""
    elif kind == "process":
        from app.hostmetrics.service import PROCESS_RE

        port = None
        if not PROCESS_RE.match(path):
            raise CheckError("put the name of the process or service in the path field (for example nginx, sshd or postgresql)")
        expect = ""
    elif kind in ("http", "tcp"):
        default = 80 if kind == "http" else None
        port = default if port in (None, "") else port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CheckError("port must be a number from 1 to 65535")
    else:
        port = 53 if port in (None, "") else port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CheckError("port must be a number from 1 to 65535")
        if not NAME_RE.match(path):
            raise CheckError("for a DNS check, put the name to look up in the path field (for example example.com)")
    if kind == "http":
        if path and not path.startswith("/"):
            path = "/" + path
        if expect and not re.fullmatch(r"\d{3}|alive|text:.{1,150}", expect):
            raise CheckError("expect is a status code such as 200, alive (any answer below 500) or text:<words that must appear in the page>")
    if kind == "tcp":
        path = ""
    interval = data.get("interval_s", 60)
    timeout = data.get("timeout_s", 5)
    if isinstance(interval, bool) or not isinstance(interval, int) or not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise CheckError(f"interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        raise CheckError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    return {
        "kind": kind, "name": name, "host": host, "port": port, "path": path, "expect": expect,
        "interval_s": interval, "timeout_s": timeout, "enabled": 1 if data.get("enabled", True) else 0,
    }


def describe(check: dict[str, Any]) -> str:
    """Short text for the target of a check."""
    if check["kind"] == "http":
        scheme = "https" if check["port"] in (443, 8443) else "http"
        return f"{scheme}://{check['host']}:{check['port']}{check['path'] or '/'}" + (f" via {check['via']}" if check.get("via") else "")
    if check["kind"] == "dns":
        return f"{check['path']} @ {check['host']}:{check['port']}"
    if check["kind"] == "cert":
        return f"certificate of {check['host']}:{check['port']}"
    if check["kind"] == "process":
        return f"process {check['path']} on {check['host']}"
    return f"{check['host']}:{check['port']}"


# ----------------------------------------------------------------------------- the checks themselves
async def check_tcp(host: str, port: int, timeout: float) -> Result:
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return Result(False, None, f"no answer within {timeout:g} s")
    except OSError as exc:
        return Result(False, None, exc.strerror or str(exc))
    ms = (time.monotonic() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return Result(True, round(ms, 1), "port open")


def _http_get(url: str, timeout: float) -> tuple[int, str]:
    context = ssl.create_default_context()
    context.check_hostname = False  # devices on a LAN usually have self-signed certificates
    context.verify_mode = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # a redirect is an answer too
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": "Netlens-service-check"})
    try:
        with opener.open(request, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536).decode("utf-8", errors="replace")


def _http_get_via(host: str, via: str, port: int, path: str, scheme: str, timeout: float) -> tuple[int, str]:
    """GET http(s)://host/path but connect to `via`: how a site behind a reverse proxy is asked for without depending on DNS."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if scheme == "https":
        class Connection(http.client.HTTPSConnection):
            def connect(self):  # the name goes into the TLS handshake (SNI), the address is the proxy's
                self.sock = context.wrap_socket(socket.create_connection((via, port), timeout), server_hostname=host)

        conn = Connection(via, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(via, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": host, "User-Agent": "Netlens-service-check"})
        resp = conn.getresponse()
        return resp.status, resp.read(65536).decode("utf-8", errors="replace")
    finally:
        conn.close()


async def check_http(check: dict[str, Any], timeout: float) -> Result:
    scheme = "https" if check["port"] in (443, 8443) else "http"
    url = f"{scheme}://{check['host']}:{check['port']}{check['path'] or '/'}"
    start = time.monotonic()
    try:
        if check.get("via"):
            fetch = asyncio.to_thread(_http_get_via, check["host"], check["via"], check["port"], check["path"] or "/", scheme, timeout)
        else:
            fetch = asyncio.to_thread(_http_get, url, timeout)
        status, body = await asyncio.wait_for(fetch, timeout + 1)
    except asyncio.TimeoutError:
        return Result(False, None, f"no answer within {timeout:g} s")
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        reason = getattr(exc, "reason", exc)
        return Result(False, None, str(reason)[:200])
    ms = round((time.monotonic() - start) * 1000, 1)
    expect = check["expect"]
    if expect.startswith("text:"):
        ok = 200 <= status < 400 and expect[5:] in body
        return Result(ok, ms, f"HTTP {status}" + ("" if ok else f", text not found" if 200 <= status < 400 else ""))
    if expect == "alive":     # the site answered; only the proxy's own errors (502, 504 ...) count as down
        return Result(status < 500, ms, f"HTTP {status}")
    if expect:
        return Result(str(status) == expect, ms, f"HTTP {status}" + ("" if str(status) == expect else f" (expected {expect})"))
    return Result(200 <= status < 400, ms, f"HTTP {status}")


def build_dns_query(name: str, ident: int = 0x4E4C) -> bytes:
    header = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    return header + question


def _skip_name(data: bytes, pos: int) -> int:
    """Position after a (possibly compressed) DNS name."""
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length >= 0xC0:
            return pos + 2
        pos += 1 + length


def parse_dns_answer(data: bytes, ident: int = 0x4E4C) -> tuple[int, list[str]]:
    """(response code, IPv4 addresses in the answer). Raises ValueError for something that is not a DNS answer."""
    if len(data) < 12:
        raise ValueError("answer too short")
    got, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if got != ident or not flags & 0x8000:
        raise ValueError("not an answer to our question")
    rcode = flags & 0xF
    pos = 12
    for _ in range(qd):
        pos = _skip_name(data, pos) + 4
    addresses = []
    for _ in range(an):
        pos = _skip_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            addresses.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += rdlen
    return rcode, addresses


async def check_dns(check: dict[str, Any], timeout: float) -> Result:
    query = build_dns_query(check["path"])
    loop = asyncio.get_running_loop()
    start = time.monotonic()
    try:
        family = socket.AF_INET6 if ":" in check["host"] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (check["host"], check["port"]))
            await loop.sock_sendall(sock, query)
            data = await asyncio.wait_for(loop.sock_recv(sock, 1500), timeout)
        finally:
            sock.close()
    except asyncio.TimeoutError:
        return Result(False, None, f"no answer within {timeout:g} s")
    except OSError as exc:
        return Result(False, None, exc.strerror or str(exc))
    ms = round((time.monotonic() - start) * 1000, 1)
    try:
        rcode, addresses = parse_dns_answer(data)
    except (ValueError, IndexError, struct.error) as exc:
        return Result(False, ms, f"bad DNS answer: {exc}")
    if rcode != 0:
        return Result(False, ms, {1: "format error", 2: "server failure", 3: "name does not exist", 5: "refused"}.get(rcode, f"error {rcode}"))
    if not addresses:
        return Result(False, ms, "no address in the answer")
    if check["expect"] and check["expect"] not in addresses:
        return Result(False, ms, f"got {', '.join(addresses)}, expected {check['expect']}")
    return Result(True, ms, ", ".join(addresses))


def _read_certificate(host: str, port: int, timeout: float) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False      # what is measured is how long the certificate lasts, not who vouches for it
    context.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(host)
        name = None                     # no SNI for a bare address
    except ValueError:
        name = host
    with socket.create_connection((host, port), timeout) as raw:
        with context.wrap_socket(raw, server_hostname=name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("the server sent no certificate")
    return der


async def check_cert(check: dict[str, Any], timeout: float) -> Result:
    """Days left of the certificate a TLS service presents (a web site, a mail server, an RDP host ...)."""
    from cryptography import x509

    start = time.monotonic()
    try:
        der = await asyncio.wait_for(asyncio.to_thread(_read_certificate, check["host"], check["port"], timeout), timeout + 1)
        cert = x509.load_der_x509_certificate(der)
    except asyncio.TimeoutError:
        return Result(False, None, f"no answer within {timeout:g} s")
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Result(False, None, (getattr(exc, "strerror", None) or str(exc))[:200])
    ms = round((time.monotonic() - start) * 1000, 1)
    ends = cert.not_valid_after_utc
    days = (ends - datetime.now(timezone.utc)).total_seconds() / 86400
    when = ends.strftime("%Y-%m-%d")
    issuer = _issuer_name(cert)
    style, warn_days = cert_policy(check.get("expect") or "", issuer)
    metrics = {"cert_days": round(days, 1)}
    if days < 0:
        return Result(False, ms, f"expired {int(-days)} day{'s' if int(-days) != 1 else ''} ago ({when})" + (", the automatic renewal did not happen" if style == "auto" else ""), metrics)
    if days < warn_days:
        why = ", it should have renewed itself by now" if style == "auto" else ""
        return Result(False, ms, f"ends in {int(days)} day{'s' if int(days) != 1 else ''} ({when}){why}, limit {warn_days}", metrics)
    return Result(True, ms, f"valid for {int(days)} more days (until {when})" + (f", {issuer}" if issuer else ""), metrics)


AUTO_ISSUERS = ("let's encrypt", "lets encrypt", "zerossl", "google trust", "buypass", "isrg", "sectigo acme")


def _issuer_name(cert) -> str:
    from cryptography.x509.oid import NameOID

    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        found = cert.issuer.get_attributes_for_oid(oid)
        if found:
            return str(found[0].value)[:60]
    return ""


def cert_policy(expect: str, issuer: str) -> tuple[str, int]:
    """(renewal style, warn below this many days). A number is taken as given; auto and manual pick their own limit.

    Certificates that renew themselves (Let's Encrypt through Nginx Proxy Manager and the like) are renewed about
    30 days before the end, so fewer than 14 days left means the renewal is stuck. A certificate renewed by hand
    needs a month of notice.
    """
    if expect.isdigit():
        return "custom", int(expect)
    style = expect if expect in ("auto", "manual") else ("auto" if any(a in issuer.lower() for a in AUTO_ISSUERS) else "manual")
    return style, 14 if style == "auto" else 30


async def run_check(check: dict[str, Any], db_path: str | None = None) -> Result:
    timeout = float(check["timeout_s"])
    try:
        if check["kind"] == "cert":
            return await check_cert(check, timeout)
        if check["kind"] == "process":
            if db_path is None:
                return Result(False, None, "a process check needs the database")
            from app.hostmetrics.service import check_process

            running, detail, ms = await check_process(db_path, check.get("device_id"), check["path"], timeout)
            return Result(running, ms, detail)
        if check["kind"] == "tcp":
            return await check_tcp(check["host"], check["port"], timeout)
        if check["kind"] == "http":
            return await check_http(check, timeout)
        return await check_dns(check, timeout)
    except Exception as exc:  # noqa: BLE001 - a broken check must never stop the others
        log.exception("service check %s crashed", check.get("name"))
        return Result(False, None, f"check failed: {exc}")


# ----------------------------------------------------------------------------- storage and scheduling
def record_result(conn, check: dict[str, Any], result: Result, now: str | None = None) -> str | None:
    """Store a result, update the check's state and log an event when the state really changed.

    Returns "down", "up" or None. A change needs this result and the one before to agree.
    """
    now = now or utcnow()
    previous = conn.execute("SELECT up FROM service_results WHERE check_id = ? ORDER BY id DESC LIMIT 1", (check["id"],)).fetchone()
    conn.execute("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (?, ?, ?, ?, ?)", (check["id"], now, int(result.up), result.ms, result.detail[:300]))
    confirmed = check.get("last_up")
    flipped = None
    new_state = int(result.up)
    if confirmed is None:
        confirmed_next, since = new_state, now  # the first result is the starting point
    elif new_state != confirmed and previous is not None and previous["up"] == new_state:
        confirmed_next, since = new_state, now
        flipped = "up" if new_state else "down"
    else:
        confirmed_next, since = confirmed, check.get("since") or now
    conn.execute(
        "UPDATE service_checks SET last_ts = ?, last_up = ?, last_ms = ?, last_detail = ?, since = ? WHERE id = ?",
        (now, confirmed_next, result.ms, result.detail[:300], since, check["id"]),
    )
    store = tsdb.for_conn(conn)
    if store is not None:
        points = [("service", check["id"], "up", new_state, "", "state")]
        if result.ms is not None:
            points.append(("service", check["id"], "response_ms", result.ms, "", "ms"))
        for metric, value in (result.metrics or {}).items():
            points.append(("service", check["id"], metric, value, "", "days" if metric == "cert_days" else ""))
        store.record(points, ts=int(_parse(now).timestamp()))
    if flipped:
        text = f"{check['name']} ({describe(check)}) is {flipped}" + (f": {result.detail}" if flipped == "down" else "")
        add_event(conn, f"service_{flipped}", text, device_id=check.get("device_id"), now=now, subject=f"service:{check['id']}")
    conn.commit()
    return flipped


def due_checks(conn, now: str | None = None) -> list[dict[str, Any]]:
    now = now or utcnow()
    out = []
    for row in conn.execute("SELECT * FROM service_checks WHERE enabled = 1"):
        c = dict(row)
        if c["last_ts"] is None or (_parse(now) - _parse(c["last_ts"])).total_seconds() >= c["interval_s"]:
            out.append(c)
    return out


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


async def run_due_checks(db_path: str, now: str | None = None) -> int:
    """Run every check that is due (a few at a time) and store the results. Returns how many ran."""
    conn = connect(db_path)
    try:
        due = due_checks(conn, now)
    finally:
        conn.close()
    if not due:
        return 0
    gate = asyncio.Semaphore(MAX_CONCURRENT)

    async def one(check: dict[str, Any]) -> None:
        async with gate:
            result = await run_check(check, db_path)
        c = connect(db_path)
        try:
            fresh = c.execute("SELECT * FROM service_checks WHERE id = ?", (check["id"],)).fetchone()
            if fresh is not None:  # it may have been deleted while it ran
                record_result(c, dict(fresh), result, now)
        finally:
            c.close()

    await asyncio.gather(*(one(c) for c in due))
    return len(due)


def prune_results(conn, now: str | None = None) -> None:
    cutoff = (_parse(now or utcnow()) - timedelta(days=RESULT_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM service_results WHERE ts < ?", (cutoff,))
    conn.commit()


def _housekeeping_checks(conn, data_dir=None) -> None:
    """Once an hour: look for a newer Netlens and newer plugins (each answers from its own cache for a day / six hours), install the plugin
    updates that were switched on for automatic updating, and note whether Netlens itself was upgraded since the last look."""
    from app import updates
    from app.plugins import autoupdate
    from app.plugins import index as plugin_index

    try:
        updates.check(conn)
        plugin_index.get_index(conn)
    except Exception:  # noqa: BLE001 - offline is normal
        log.debug("update check failed", exc_info=True)
    try:
        conn.execute("PRAGMA optimize")        # lets SQLite refresh its query statistics when a table has changed a lot (cheap when nothing changed)
    except Exception:  # noqa: BLE001
        log.debug("PRAGMA optimize failed", exc_info=True)
    try:
        from app import openrouter

        openrouter.watch(conn)        # looks at OpenRouter at most once a day, and only when a free model of theirs was chosen
    except Exception:  # noqa: BLE001 - offline is normal
        log.debug("watching the chosen language model failed", exc_info=True)
    try:
        from app import licence

        licence.notify(conn)
    except Exception:  # noqa: BLE001
        log.debug("licence check failed", exc_info=True)
    try:
        from app.plugins import moved

        if data_dir is not None:
            moved.run(conn, data_dir)
    except Exception:  # noqa: BLE001 - offline is normal; it is tried again in an hour
        log.debug("installing the plugins that moved out of Netlens failed", exc_info=True)
    try:
        autoupdate.note_version(conn)
        if data_dir is not None:
            autoupdate.run(conn, data_dir)
    except Exception:  # noqa: BLE001 - a broken plugin folder must not stop the other checks
        log.warning("automatic plugin update failed", exc_info=True)


def _startup_checks(db_path: str) -> None:
    """Right after a start: look for a newer Netlens and newer plugins, so the About page is not showing a day-old answer."""
    conn = connect(db_path)
    try:
        _housekeeping_checks(conn, Path(db_path).resolve().parent)
    finally:
        conn.close()


def _maintain_metrics(db_path: str, prune: bool) -> None:
    try:
        store = tsdb.for_path(db_path)
        store.rollup()
        if prune:
            store.prune()
    except Exception:  # noqa: BLE001 - the graphs are a convenience, never a reason to stop the checks
        log.exception("metrics maintenance failed")


def _expire_snoozes(db_path: str) -> bool:
    from app import snooze

    conn = connect(db_path)
    try:
        return bool(snooze.expire(conn))
    except Exception:  # noqa: BLE001
        log.exception("ending snoozes failed")
        return False
    finally:
        conn.close()


def _check_probes(db_path: str) -> bool:
    from app import probes

    conn = connect(db_path)
    try:
        return bool(probes.check_silent(conn))
    except Exception:  # noqa: BLE001
        log.exception("remote site check failed")
        return False
    finally:
        conn.close()


async def service_loop(db_path: str, interval: float = 10.0) -> None:
    """Background task: run due checks every few seconds, prune old results hourly."""
    last_prune = 0.0
    last_rollup = 0.0
    startup = asyncio.ensure_future(asyncio.to_thread(_startup_checks, db_path))      # does not hold the loop up when the internet is slow
    startup.add_done_callback(lambda f: f.exception())                                  # never an unhandled error
    while True:
        try:
            if await run_due_checks(db_path):
                from app.notify.channels import process_channels  # a service going down should not wait for the next scan

                await process_channels(db_path)
            if time.monotonic() - last_rollup > 60:       # fold the new samples of the graphs into the coarser tiers
                last_rollup = time.monotonic()
                await asyncio.to_thread(_maintain_metrics, db_path, time.monotonic() - last_prune > 3600)
                if await asyncio.to_thread(_expire_snoozes, db_path):      # a snooze ended and its problem is still there
                    from app.notify.channels import process_channels

                    await process_channels(db_path)
                if await asyncio.to_thread(_check_probes, db_path):       # a remote site stopped reporting
                    from app.notify.channels import process_channels

                    await process_channels(db_path)
            if time.monotonic() - last_prune > 3600:
                last_prune = time.monotonic()
                conn = connect(db_path)
                try:
                    prune_results(conn)
                    try:
                        from app import audit

                        audit.prune(conn)
                    except Exception:  # noqa: BLE001
                        log.exception("pruning the audit log failed")
                    try:
                        from app import forecast

                        if await asyncio.to_thread(forecast.check, conn):          # a disk is on course to fill up
                            from app.notify.channels import process_channels

                            await process_channels(db_path)
                    except Exception:  # noqa: BLE001 - a forecast is a convenience
                        log.exception("capacity forecast failed")
                    try:
                        from app import reports

                        await reports.send_weekly(db_path)                      # only when it is due
                        await reports.send_monthly(db_path)                     # likewise
                    except Exception:  # noqa: BLE001
                        log.exception("weekly or monthly report failed")
                    from app import backup_schedule

                    outcome = await asyncio.to_thread(backup_schedule.run_if_due, conn, db_path)
                    if outcome and not outcome["ok"]:
                        from app.notify.channels import process_channels

                        await process_channels(db_path)
                    from app import netchecks
                    from app.api import vendor_db as vendor_db_api

                    if vendor_db_api.due(conn):  # the IEEE vendor registry, once a month; offline is normal
                        try:
                            await asyncio.to_thread(vendor_db_api.refresh_now, conn, Path(db_path).resolve().parent)
                        except Exception:  # noqa: BLE001
                            log.debug("vendor registry refresh failed", exc_info=True)

                    if netchecks.dhcp_due(conn):
                        checked = await netchecks.check_dhcp(conn)
                        if checked["rogue"]:
                            from app.notify.channels import process_channels

                            await process_channels(db_path)
                    await asyncio.to_thread(_housekeeping_checks, conn, Path(db_path).resolve().parent)
                    from app import speedtest

                    if speedtest.due(conn) and speedtest.PROGRESS.start("internet", "Cloudflare"):  # about 20 seconds: in its own thread, the checks go on
                        threading.Thread(target=speedtest.run_and_record, args=(db_path, speedtest.PROGRESS), daemon=True).start()
                finally:
                    conn.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("service check loop failed")
        await asyncio.sleep(interval)
