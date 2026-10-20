"""Report to a central Netlens: this installation is a remote site (a "probe") of another one.

It keeps scanning and checking its own network exactly as before, and every minute sends what it knows to the central
Netlens: its devices, service checks, health problems and the measurements made since the last report. The connection
always goes out from here; nothing at this site has to be reachable from outside. The token is made on the central side
(Monitoring -> Remote sites -> Add a remote site) and is stored encrypted here.
"""

from __future__ import annotations

import asyncio
import gzip
import ipaddress
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from app import tsdb
from app.db import connect, get_setting, set_setting, utcnow
from app.version import VERSION

log = logging.getLogger(__name__)

LINK_KEY = "central.link"
STATUS_KEY = "central.status"
MARK_KEY = "central.pushed_ts"
REV_KEY = "central.config_rev"
DEFAULT_INTERVAL = 60
MAX_BODY = 8 * 1024 * 1024
TIMEOUT = 25.0


class LinkError(ValueError):
    pass


# ----------------------------------------------------------------------------- the setting
def get_link(conn) -> dict[str, Any]:
    try:
        data = json.loads(get_setting(conn, LINK_KEY) or "{}")
    except ValueError:
        data = {}
    return {"url": str(data.get("url") or ""), "token": str(data.get("token") or ""), "enabled": bool(data.get("enabled")),
            "interval_s": int(data.get("interval_s") or DEFAULT_INTERVAL), "accept_config": bool(data.get("accept_config"))}


def public_link(conn) -> dict[str, Any]:
    link = get_link(conn)
    try:
        status = json.loads(get_setting(conn, STATUS_KEY) or "{}")
    except ValueError:
        status = {}
    return {"url": link["url"], "has_token": bool(link["token"]), "enabled": link["enabled"], "interval_s": link["interval_s"], "accept_config": link["accept_config"],
            "config_rev": get_config_rev(conn), "status": status}


def _check_url(url: str) -> str:
    url = url.strip().rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LinkError("the address must start with https:// (or http:// for a server on your own network)")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise LinkError("give only the address of the central Netlens, for example https://netlens.example.com")
    if parts.scheme == "http":
        host = parts.hostname
        try:
            ip = ipaddress.ip_address(host)
            private = ip.is_private or ip.is_loopback
        except ValueError:
            private = host == "localhost" or host.endswith(".local") or "." not in host
        if not private:
            raise LinkError("a plain http:// address is only accepted for a server on your own network; use https:// across the internet")
    return f"{parts.scheme}://{parts.netloc}"


def set_link(conn, data: dict[str, Any]) -> dict[str, Any]:
    cur = get_link(conn)
    url = _check_url(str(data.get("url", cur["url"]) or "")) if (data.get("url", cur["url"]) or data.get("enabled")) else ""
    token = data.get("token")
    token = cur["token"] if token in (None, "") else str(token).strip()
    interval = data.get("interval_s", cur["interval_s"])
    if isinstance(interval, bool) or not isinstance(interval, int) or not 15 <= interval <= 3600:
        raise LinkError("the interval must be between 15 and 3600 seconds")
    enabled = bool(data.get("enabled", cur["enabled"]))
    accept = bool(data.get("accept_config", cur["accept_config"]))
    if enabled and not (url and token):
        raise LinkError("enter the address of the central Netlens and the token it gave you")
    set_setting(conn, LINK_KEY, json.dumps({"url": url, "token": token, "enabled": enabled, "interval_s": interval, "accept_config": accept}))
    return public_link(conn)


def get_config_rev(conn) -> int:
    value = get_setting(conn, REV_KEY)
    return int(value) if value and value.isdigit() else 0


# ----------------------------------------------------------------------------- what is reported
def _key(row) -> str:
    return row["mac"] or f"ip:{row['primary_ip']}"


def snapshot(conn, since_ts: int, now_ts: float | None = None) -> dict[str, Any]:
    """The report: everything the central side needs to show this site, plus the measurements newer than `since_ts`."""
    from app.api.monitors import _latest
    from app.hostmetrics import service as hm
    from app.services import describe

    now_ts = now_ts if now_ts is not None else time.time()
    devices, keys = [], {}
    ports: dict[int, list[int]] = {}
    for r in conn.execute("SELECT device_id, port FROM ports WHERE state = 'open'"):
        ports.setdefault(r["device_id"], []).append(r["port"])
    for r in conn.execute(
        "SELECT id, mac, primary_ip, hostname, custom_name, vendor, os_name, device_type, type_override, online, always_on, first_seen, last_seen FROM devices"):
        key = _key(r)
        keys[r["id"]] = key
        devices.append({
            "key": key, "mac": r["mac"], "ip": r["primary_ip"], "name": r["custom_name"] or r["hostname"] or r["primary_ip"] or key, "vendor": r["vendor"],
            "type": r["type_override"] or r["device_type"], "os": r["os_name"], "online": bool(r["online"]), "always_on": bool(r["always_on"]),
            "ports": sorted(ports.get(r["id"], []))[:60], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
        })
    services, svc_keys = [], {}
    for r in conn.execute("SELECT * FROM service_checks WHERE enabled = 1"):
        c = dict(r)
        key = f"svc:{c['id']}"
        svc_keys[c["id"]] = key
        services.append({"key": key, "name": c["name"], "kind": c["kind"], "target": describe(c), "state": None if c["last_up"] is None else ("up" if c["last_up"] else "down"),
                         "ms": c["last_ms"], "detail": c["last_detail"], "since": c["since"], "checked": c["last_ts"]})
    store = tsdb.for_conn(conn)
    problems = []
    for p in hm.problems(conn):
        problems.append({**p, "device_key": keys.get(p["device_id"])})
    monitors = []
    for m in conn.execute("SELECT m.*, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE m.enabled = 1"):
        level = "ok"
        for p in problems:
            if p["device_id"] == m["device_id"]:
                level = "critical" if "critical" in (level, p["level"]) else "warning"
        monitors.append({"device_key": keys.get(m["device_id"]), "device": m["name"], "method": m["method"], "ok": None if m["last_ok"] is None else bool(m["last_ok"]),
                         "error": m["last_error"], "level": level, "latest": _latest(store, m["device_id"])})
    samples = []
    if store is not None:
        for ts, entity, ident, metric, label, value, unit in store.export_since(since_ts):
            ref = keys.get(ident) if entity == "device" else svc_keys.get(ident)
            if ref:
                samples.append({"ts": ts, "entity": entity, "ref": ref, "metric": metric, "label": label, "value": value, "unit": unit})
    from app import guestbackups, vulns

    scan = conn.execute("SELECT finished, hosts_found FROM scans WHERE status = 'done' ORDER BY id DESC LIMIT 1").fetchone()
    running = conn.execute("SELECT 1 FROM scans WHERE status = 'running' LIMIT 1").fetchone()
    return {"version": VERSION, "sent": utcnow(), "devices": devices, "services": services, "problems": problems, "monitors": monitors, "samples": samples, "backups": guestbackups.report(conn), "vulns": vulns.report(conn),
            "scan": {"finished": scan["finished"] if scan else None, "hosts": scan["hosts_found"] if scan else None, "running": bool(running)}}


# ----------------------------------------------------------------------------- sending
def send(url: str, token: str, payload: dict[str, Any], timeout: float = TIMEOUT) -> dict[str, Any]:
    """POST the report. Raises LinkError with a sentence for the user."""
    body = gzip.compress(json.dumps(payload, separators=(",", ":")).encode())
    if len(body) > MAX_BODY:
        raise LinkError("the report is too large to send")
    request = urllib.request.Request(
        url + "/api/probe/push", data=body, method="POST",
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip", "Authorization": f"Bearer {token}", "User-Agent": f"Netlens/{VERSION}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - scheme checked when the link was saved
            return json.loads(resp.read(2 * 1024 * 1024).decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise LinkError("the central Netlens refused the token: it was removed or replaced there") from None
        if exc.code == 429:
            raise LinkError("the central Netlens says too many attempts; wait a little") from None
        raise LinkError(f"the central Netlens answered with an error ({exc.code})") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise LinkError(f"cannot reach the central Netlens: {reason}") from None


def _skew(central_time: Any) -> int | None:
    """Seconds this clock is ahead (+) or behind (-) of the central Netlens, from the time in its reply."""
    try:
        theirs = datetime.strptime(central_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None
    return int(round(time.time() - theirs))


async def run_commands(status: dict[str, Any], scan_manager) -> list[str]:
    """Do what the central Netlens asked for in its reply. Returns what was started."""
    from app.scanner.orchestrator import ScanBusy

    started = []
    for command in status.get("commands") or []:
        try:
            await scan_manager.start("deep" if command == "scan_deep" else "quick")
            started.append(command)
        except ScanBusy:
            log.info("the central Netlens asked for a scan, but one is already running")
        except Exception:  # noqa: BLE001 - a command must never stop the reports
            log.exception("could not start the scan the central Netlens asked for")
    return started


def push_once(db_path: str, now_ts: float | None = None, force: bool = False) -> dict[str, Any]:
    """One report. Returns the status that was stored."""
    now_ts = now_ts if now_ts is not None else time.time()
    conn = connect(db_path)
    try:
        link = get_link(conn)
        if not (link["enabled"] or force) or not link["url"] or not link["token"]:
            return {}
        mark = get_setting(conn, MARK_KEY)
        since = int(mark) if mark and mark.isdigit() else int(now_ts) - 3600     # a first report does not replay a week
        payload = snapshot(conn, since, now_ts)
        payload["interval_s"] = link["interval_s"]
        payload["accepts_config"] = link["accept_config"]
        payload["config_rev"] = get_config_rev(conn)
        newest = max([s["ts"] for s in payload["samples"]] + [since])
        try:
            reply = send(link["url"], link["token"], payload)
            status = {"ts": utcnow(), "ok": True, "error": None, "devices": len(payload["devices"]), "services": len(payload["services"]),
                      "samples": len(payload["samples"]), "central_events": reply.get("events"), "skew_s": _skew(reply.get("time"))}
            commands = [c for c in (reply.get("commands") or []) if c in ("scan", "scan_deep")] if link["accept_config"] else []
            if commands:
                status["commands"] = commands
            set_setting(conn, MARK_KEY, str(newest))
            config = reply.get("config") if link["accept_config"] and isinstance(reply, dict) else None
            if isinstance(config, dict) and isinstance(config.get("rev"), int) and not isinstance(config.get("rev"), bool):
                from app import probe_config

                try:
                    status["config"] = probe_config.apply(conn, config)
                    set_setting(conn, REV_KEY, str(config["rev"]))
                except Exception:  # noqa: BLE001 - a bad configuration must not stop the reports
                    log.exception("applying the configuration of the central Netlens failed")
                    status["config"] = {"error": "the configuration could not be applied"}
        except LinkError as exc:
            status = {"ts": utcnow(), "ok": False, "error": str(exc), "devices": len(payload["devices"]), "services": len(payload["services"]), "samples": 0}
        set_setting(conn, STATUS_KEY, json.dumps(status))
        return status
    finally:
        conn.close()


async def loop(db_path: str, scan_manager=None) -> None:
    """Background task: report to the central Netlens at the chosen interval (when it is switched on)."""
    await asyncio.sleep(20)
    last = 0.0
    while True:
        try:
            conn = connect(db_path)
            try:
                link = get_link(conn)
            finally:
                conn.close()
            if link["enabled"] and link["url"] and link["token"] and time.monotonic() - last >= link["interval_s"]:
                last = time.monotonic()
                status = await asyncio.to_thread(push_once, db_path)
                if scan_manager is not None and status.get("commands"):
                    await run_commands(status, scan_manager)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failing report must never stop the scans
            log.exception("report to the central Netlens failed")
        await asyncio.sleep(5)
