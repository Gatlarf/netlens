"""Service checks (HTTP, TCP port, DNS) with a result history, like a small Uptime Kuma.

A check is stored in `service_checks`; every run adds a row to `service_results` and updates the check's current
state. A state change needs two identical results in a row (so one lost packet is not an outage) and is logged as a
`service_down` / `service_up` event, which the notification channels and Home Assistant pick up.
"""

from __future__ import annotations

import asyncio
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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event, connect, utcnow

log = logging.getLogger(__name__)

KINDS = ("http", "tcp", "dns")
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
    if kind in ("http", "tcp"):
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
        if expect and not re.fullmatch(r"\d{3}|text:.{1,150}", expect):
            raise CheckError("expect is a status code such as 200, or text:<words that must appear in the page>")
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
        return f"http://{check['host']}:{check['port']}{check['path'] or '/'}"
    if check["kind"] == "dns":
        return f"{check['path']} @ {check['host']}:{check['port']}"
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


async def check_http(check: dict[str, Any], timeout: float) -> Result:
    scheme = "https" if check["port"] in (443, 8443) else "http"
    url = f"{scheme}://{check['host']}:{check['port']}{check['path'] or '/'}"
    start = time.monotonic()
    try:
        status, body = await asyncio.wait_for(asyncio.to_thread(_http_get, url, timeout), timeout + 1)
    except asyncio.TimeoutError:
        return Result(False, None, f"no answer within {timeout:g} s")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return Result(False, None, str(reason)[:200])
    ms = round((time.monotonic() - start) * 1000, 1)
    expect = check["expect"]
    if expect.startswith("text:"):
        ok = 200 <= status < 400 and expect[5:] in body
        return Result(ok, ms, f"HTTP {status}" + ("" if ok else f", text not found" if 200 <= status < 400 else ""))
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


async def run_check(check: dict[str, Any]) -> Result:
    timeout = float(check["timeout_s"])
    try:
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
    if flipped:
        text = f"{check['name']} ({describe(check)}) is {flipped}" + (f": {result.detail}" if flipped == "down" else "")
        add_event(conn, f"service_{flipped}", text, device_id=check.get("device_id"), now=now)
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
            result = await run_check(check)
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


async def service_loop(db_path: str, interval: float = 10.0) -> None:
    """Background task: run due checks every few seconds, prune old results hourly."""
    last_prune = 0.0
    while True:
        try:
            if await run_due_checks(db_path):
                from app.notify.channels import process_channels  # a service going down should not wait for the next scan
                from app.notify.service import process_notifications

                await process_channels(db_path)
                await process_notifications(db_path)
            if time.monotonic() - last_prune > 3600:
                last_prune = time.monotonic()
                conn = connect(db_path)
                try:
                    prune_results(conn)
                finally:
                    conn.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("service check loop failed")
        await asyncio.sleep(interval)
