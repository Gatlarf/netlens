"""Remote sites: other Netlens instances ("probes") that report what they see to this one.

A probe is a normal Netlens running at another location. It scans and checks its own network, and every minute it sends
what it knows (devices, service checks, health problems, new measurements) to this Netlens, using a token that was made
here. The probe always connects out; this side never needs to reach into the remote network.

Remote devices are kept apart from the local ones (`remote_devices`): the two networks may use the same address ranges, and
none of the local logic (scans, hierarchy, DNS) should mix them up. What this side adds is the overview, the history graphs,
and alerts: a remote device going offline, a service down, a health problem, or a probe that stopped reporting.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app import tsdb
from app.db import add_event, utcnow

log = logging.getLogger(__name__)

TOKEN_PREFIX = "nlp_"
MAX_DEVICES, MAX_SERVICES, MAX_SAMPLES, MAX_PROBLEMS = 3000, 500, 30000, 200
SILENT_AFTER_S = 240              # a probe that has not reported for this long is "not heard from"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
NAME_RE = re.compile(r"^[^\x00-\x1f]{1,60}$")
# the measurements a site may report: the names Netlens itself produces, so a misbehaving site cannot fill the store with its own
ALLOWED_METRICS = frozenset({"up", "rtt_ms", "response_ms", "cert_days", "cpu_pct", "load1", "mem_pct", "swap_pct", "disk_pct", "disk_free_b", "net_rx_bps",
                             "net_tx_bps", "if_util_pct", "if_err_ps", "if_up", "storage_status", "temp_c", "fan_rpm", "voltage_v", "sensor_fault", "ups_load_pct", "uptime_s", "supply_pct", "battery_pct", "battery_minutes", "on_battery", "service_stopped"})


class LicenceLimit(ValueError):
    """More remote sites than the licence allows (the API answers 402)."""


class ProbeError(ValueError):
    pass


# ----------------------------------------------------------------------------- tokens and records
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def clean_name(value: Any) -> str:
    name = str(value or "").strip()
    if not NAME_RE.match(name):
        raise ProbeError("give the site a name of up to 60 characters")
    return name


def locked_ids(conn: sqlite3.Connection) -> set[int]:
    """The remote sites beyond what the licence allows (the oldest ones come first): they are frozen, not removed."""
    from app import licence

    limit = licence.site_limit(conn)
    if limit is None:
        return set()
    return {r[0] for r in conn.execute("SELECT id FROM probes ORDER BY id").fetchall()[limit:]}


def create(conn: sqlite3.Connection, name: str) -> tuple[dict, str]:
    """Make a probe record; returns it with the token (shown once, only its hash is kept)."""
    from app import licence

    name = clean_name(name)
    limit = licence.site_limit(conn)
    if limit is not None and conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] >= limit:
        raise LicenceLimit(f"The {licence.status(conn)['name']} edition takes in {limit} remote site{'s' if limit != 1 else ''}. Add a licence key (Settings → Licence) or start the free 30-day trial for more.")
    if conn.execute("SELECT 1 FROM probes WHERE name = ? COLLATE NOCASE", (name,)).fetchone():
        raise ProbeError("there is already a remote site with that name")
    if conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0] >= 50:
        raise ProbeError("at most 50 remote sites")
    token = new_token()
    cur = conn.execute("INSERT INTO probes (name, token_hash, created) VALUES (?, ?, ?)", (name, hash_token(token), utcnow()))
    conn.commit()
    return get(conn, cur.lastrowid), token


def rotate_token(conn: sqlite3.Connection, probe_id: int) -> str:
    token = new_token()
    conn.execute("UPDATE probes SET token_hash = ? WHERE id = ?", (hash_token(token), probe_id))
    conn.commit()
    return token


def find_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    if not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        return None
    return conn.execute("SELECT * FROM probes WHERE token_hash = ?", (hash_token(token),)).fetchone()


def get(conn: sqlite3.Connection, probe_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM probes WHERE id = ?", (probe_id,)).fetchone()
    return present(conn, row) if row else None


def _parse(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, STAMP).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _vulns_view(conn: sqlite3.Connection, summary: dict) -> dict:
    """What a site reported about vulnerabilities, shown only where the licence allows vulnerabilities."""
    from app import licence

    v = summary.get("vulns") or {"configured": False}
    return v if v.get("configured") and licence.allows(conn, "vulnerabilities") else {"configured": False}


def present(conn: sqlite3.Connection, row: sqlite3.Row, now: float | None = None) -> dict:
    now = now if now is not None else time.time()
    seen = _parse(row["last_seen"])
    summary = json.loads(row["summary"] or "{}")
    counts = conn.execute(
        "SELECT COUNT(*) AS total, COALESCE(SUM(online), 0) AS online, COALESCE(SUM(CASE WHEN always_on = 1 AND online = 0 THEN 1 ELSE 0 END), 0) AS core_down "
        "FROM remote_devices WHERE probe_id = ?", (row["id"],)).fetchone()
    services = conn.execute(
        "SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN state = 'down' THEN 1 ELSE 0 END), 0) AS down FROM remote_services WHERE probe_id = ?", (row["id"],)).fetchone()
    if seen is None:
        state = "waiting"
    elif now - seen > max(SILENT_AFTER_S, row["interval_s"] * 4):
        state = "silent"
    else:
        state = "connected"
    problems = summary.get("problems") or []
    return {
        "id": row["id"], "name": row["name"], "customer": row["customer"] or "", "enabled": bool(row["enabled"]), "locked": row["id"] in locked_ids(conn), "created": row["created"], "last_seen": row["last_seen"],
        "last_ip": row["last_ip"], "version": row["version"], "interval_s": row["interval_s"], "state": state,
        "devices": {"total": counts["total"], "online": counts["online"], "core_down": counts["core_down"]},
        "services": {"total": services["total"], "down": services["down"]},
        "problems": {"count": len(problems), "critical": sum(1 for p in problems if p.get("level") == "critical")},
        "scan": summary.get("scan"), "skew_s": summary.get("skew_s"), "backups": summary.get("backups") or {"configured": False}, "vulns": _vulns_view(conn, summary),
    }


# ----------------------------------------------------------------------------- reading a payload
def _text(value: Any, limit: int = 200) -> str | None:
    if value is None:
        return None
    return str(value).replace("\x00", "")[:limit]


def _stamp(value: Any, fallback: str | None = None) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        return value
    return fallback


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if value == value and abs(value) < 1e15 else None


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _device(item: Any, fallback_ts: str) -> dict | None:
    if not isinstance(item, dict):
        return None
    key = _text(item.get("key"), 80)
    if not key:
        return None
    ports = [p for p in _list(item.get("ports")) if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536][:60]
    return {
        "key": key, "mac": _text(item.get("mac"), 20), "ip": _text(item.get("ip"), 60), "name": _text(item.get("name"), 100) or _text(item.get("ip"), 60) or key,
        "vendor": _text(item.get("vendor"), 80), "type": _text(item.get("type"), 30), "os": _text(item.get("os"), 80),
        "online": bool(item.get("online")), "always_on": bool(item.get("always_on")), "ports": ports,
        "first_seen": _stamp(item.get("first_seen"), fallback_ts), "last_seen": _stamp(item.get("last_seen"), fallback_ts),
    }


def _service(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    key = _text(item.get("key"), 80)
    if not key:
        return None
    state = item.get("state")
    return {"key": key, "name": _text(item.get("name"), 100) or key, "kind": _text(item.get("kind"), 20), "target": _text(item.get("target"), 200),
            "state": state if state in ("up", "down") else None, "ms": _number(item.get("ms")), "detail": _text(item.get("detail"), 300),
            "since": _stamp(item.get("since")), "checked": _stamp(item.get("checked"))}


# ----------------------------------------------------------------------------- the push
def ingest(conn: sqlite3.Connection, probe: sqlite3.Row, payload: dict, now: str | None = None, remote_ip: str | None = None) -> dict:
    """Store what a probe reported and raise events for what changed. Returns a short summary for the probe."""
    if not isinstance(payload, dict):
        raise ProbeError("the report must be a JSON object")
    now = now or utcnow()
    site = f"{probe['customer']} / {probe['name']}" if probe["customer"] else probe["name"]          # an alert names the customer too
    probe_id = probe["id"]
    baseline = probe["snapshot_ts"] is None            # the first report only sets the starting point; nothing is "new" yet
    events: list[tuple[str, str]] = []

    devices = [d for d in (_device(i, now) for i in _list(payload.get("devices"))[:MAX_DEVICES]) if d]
    services = [s for s in (_service(i) for i in _list(payload.get("services"))[:MAX_SERVICES]) if s]
    services_given = isinstance(payload.get("services"), list)
    old_devices = {r["key"]: r for r in conn.execute("SELECT * FROM remote_devices WHERE probe_id = ?", (probe_id,))}
    old_services = {r["key"]: r for r in conn.execute("SELECT * FROM remote_services WHERE probe_id = ?", (probe_id,))}

    seen_keys = set()
    for d in devices:
        if d["key"] in seen_keys:
            continue
        seen_keys.add(d["key"])
        before = old_devices.get(d["key"])
        shown = f"{d['name']} ({d['ip']})" if d["ip"] and d["ip"] != d["name"] else d["name"]
        if before is None:
            if not baseline:
                events.append(("remote_new", f"{site}: new device {shown}" + (f", {d['vendor']}" if d["vendor"] else "")))
            conn.execute(
                "INSERT INTO remote_devices (probe_id, key, mac, ip, name, vendor, type, os, online, always_on, ports, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (probe_id, d["key"], d["mac"], d["ip"], d["name"], d["vendor"], d["type"], d["os"], int(d["online"]), int(d["always_on"]), json.dumps(d["ports"]),
                 d["first_seen"], d["last_seen"]))
        else:
            if not baseline and bool(before["online"]) != d["online"]:
                events.append(("remote_online" if d["online"] else "remote_offline", f"{site}: {shown} " + ("is back online" if d["online"] else "went offline")))
            conn.execute(
                "UPDATE remote_devices SET mac=?, ip=?, name=?, vendor=?, type=?, os=?, online=?, always_on=?, ports=?, last_seen=? WHERE id=?",
                (d["mac"], d["ip"], d["name"], d["vendor"], d["type"], d["os"], int(d["online"]), int(d["always_on"]), json.dumps(d["ports"]), d["last_seen"], before["id"]))
    if devices:       # a device the probe no longer lists is gone (deleted or ignored there)
        gone = [k for k in old_devices if k not in seen_keys]
        for key in gone:
            conn.execute("DELETE FROM remote_devices WHERE id = ?", (old_devices[key]["id"],))
            tsdb_forget("remote", old_devices[key]["id"], conn)

    seen_services = set()
    for s in services:
        if s["key"] in seen_services:
            continue
        seen_services.add(s["key"])
        before = old_services.get(s["key"])
        if before is None:
            conn.execute("INSERT INTO remote_services (probe_id, key, name, kind, target, state, ms, detail, since, checked) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (probe_id, s["key"], s["name"], s["kind"], s["target"], s["state"], s["ms"], s["detail"], s["since"], s["checked"]))
            if not baseline and s["state"] == "down":          # a check that is broken from the start (for example one set up from here) is not a quiet one
                events.append(("remote_service_down", f"{site}: {s['name']} ({s['target']}) is down" + (f": {s['detail']}" if s["detail"] else "")))
        else:
            if not baseline and before["state"] != s["state"] and s["state"] is not None and before["state"] is not None:
                text = f"{site}: {s['name']} ({s['target']}) is {s['state']}" + (f": {s['detail']}" if s["state"] == "down" and s["detail"] else "")
                events.append(("remote_service_down" if s["state"] == "down" else "remote_service_up", text))
            conn.execute("UPDATE remote_services SET name=?, kind=?, target=?, state=?, ms=?, detail=?, since=?, checked=? WHERE id=?",
                         (s["name"], s["kind"], s["target"], s["state"], s["ms"], s["detail"], s["since"], s["checked"], before["id"]))
    if services or services_given:
        for key, row in old_services.items():
            if key not in seen_services:
                conn.execute("DELETE FROM remote_services WHERE id = ?", (row["id"],))
                tsdb_forget("remote_service", row["id"], conn)

    # health problems: what is new or got worse is announced, what went away is "normal again"
    problems_in = [p for p in _list(payload.get("problems"))[:MAX_PROBLEMS] if isinstance(p, dict)]
    problems = []
    for p in problems_in:
        level = p.get("level") if p.get("level") in ("warning", "critical") else None
        if level is None:
            continue
        problems.append({"device_key": _text(p.get("device_key"), 80), "device": _text(p.get("device"), 100), "metric": _text(p.get("metric"), 40) or "",
                         "label": _text(p.get("label"), 60) or "", "level": level, "value": _number(p.get("value")), "title": _text(p.get("title"), 60) or "",
                         "unit": _text(p.get("unit"), 8) or "", "since": _stamp(p.get("since"))})
    previous = {(p.get("device_key"), p.get("metric"), p.get("label")): p for p in (json.loads(probe["summary"] or "{}").get("problems") or [])}
    current = {(p["device_key"], p["metric"], p["label"]): p for p in problems}
    if not baseline:
        for k, p in current.items():
            was = previous.get(k)
            if was is None or (p["level"] == "critical" and was.get("level") != "critical"):
                where = f" on {p['label']}" if p["label"] else ""
                shown = f"{p['value']:.0f}{p['unit']}" if p["value"] is not None and p["unit"] else (f"{p['value']:g}" if p["value"] is not None else "")
                events.append(("remote_metric_critical" if p["level"] == "critical" else "remote_metric_warning",
                               f"{site}: {p['device']}: {p['title'].lower()}{where} is {shown}".rstrip()))
        for k, p in previous.items():
            if k not in current:
                where = f" on {p.get('label')}" if p.get("label") else ""
                events.append(("remote_metric_ok", f"{site}: {p.get('device')}: {str(p.get('title') or '').lower()}{where} is back to normal"))

    # measurements since the previous report
    samples = _list(payload.get("samples"))
    recorded = 0
    store = tsdb.for_conn(conn)
    if store is not None and samples:
        dev_ids = {r["key"]: r["id"] for r in conn.execute("SELECT key, id FROM remote_devices WHERE probe_id = ?", (probe_id,))}
        svc_ids = {r["key"]: r["id"] for r in conn.execute("SELECT key, id FROM remote_services WHERE probe_id = ?", (probe_id,))}
        now_ts = time.time()
        rows = []
        for item in samples[:MAX_SAMPLES]:
            if not isinstance(item, dict):
                continue
            value, ts = _number(item.get("value")), _number(item.get("ts"))
            metric = _text(item.get("metric"), 40)
            if value is None or ts is None or metric not in ALLOWED_METRICS or not now_ts - 3 * 86400 < ts <= now_ts + 120:
                continue
            ref = _text(item.get("ref"), 80)
            if item.get("entity") == "device" and ref in dev_ids:
                entity, ident = "remote", dev_ids[ref]
            elif item.get("entity") == "service" and ref in svc_ids:
                entity, ident = "remote_service", svc_ids[ref]
            else:
                continue
            rows.append((int(ts), entity, ident, metric, value, _text(item.get("label"), 60) or "", _text(item.get("unit"), 8) or ""))
        recorded = store.record_bulk(rows)

    interval = payload.get("interval_s")
    interval = int(interval) if isinstance(interval, int) and not isinstance(interval, bool) and 15 <= interval <= 3600 else probe["interval_s"]
    from app import guestbackups, vulns

    new_vulns = vulns.clean_report(payload.get("vulns"))
    try:
        old_vulns = json.loads(probe["summary"] or "{}").get("vulns") or {}
    except ValueError:
        old_vulns = {}
    if not baseline and new_vulns["configured"] and old_vulns.get("configured"):
        more = new_vulns["counts"]["critical"] - (old_vulns.get("counts") or {}).get("critical", 0)
        if more > 0:
            events.append(("vuln_critical", f"{site}: {more} new critical vulnerabilit{'ies' if more != 1 else 'y'}" + (", at least one known to be exploited" if new_vulns["exploited"] > (old_vulns.get("exploited") or 0) else "")))
    summary = {"vulns": new_vulns, "problems": problems, "monitors": _monitors(payload.get("monitors")), "scan": _scan(payload.get("scan")), "backups": guestbackups.clean_report(payload.get("backups")),
               "counts": {"devices": len(devices), "services": len(services), "samples": recorded},
               "accepts_config": bool(payload.get("accepts_config")), "skew_s": _skew(payload.get("sent"), now),
               "config_rev": payload.get("config_rev") if isinstance(payload.get("config_rev"), int) and not isinstance(payload.get("config_rev"), bool) else 0}
    conn.execute(
        "UPDATE probes SET last_seen = ?, last_ip = ?, version = ?, interval_s = ?, snapshot_ts = ?, summary = ?, offline_notified = 0 WHERE id = ?",
        (now, remote_ip, _text(payload.get("version"), 40), interval, now, json.dumps(summary), probe_id))
    conn.commit()
    if probe["offline_notified"] and not baseline:
        events.insert(0, ("probe_online", f"{site} is reporting again"))
    for kind, text in events:
        add_event(conn, kind, text, now=now, subject=f"site:{probe_id}")          # a snooze of the site holds back all of its alerts
    return {"ok": True, "interval_s": interval, "devices": len(devices), "services": len(services), "samples": recorded, "events": len(events), "time": utcnow()}


def _skew(sent: Any, now: str) -> int | None:
    """Seconds the site's clock is ahead (+) or behind (-) of this one, when the report says when it was sent."""
    a, b = _parse(sent if isinstance(sent, str) else None), _parse(now)
    return None if a is None or b is None else int(round(a - b))


def tsdb_forget(entity: str, entity_id: int, conn: sqlite3.Connection) -> None:
    store = tsdb.for_conn(conn)
    if store is not None:
        store.forget(entity, entity_id)


def _monitors(items: Any) -> list[dict]:
    out = []
    for m in _list(items)[:500]:
        if not isinstance(m, dict):
            continue
        latest = m.get("latest") if isinstance(m.get("latest"), dict) else {}
        out.append({"device_key": _text(m.get("device_key"), 80), "device": _text(m.get("device"), 100), "method": _text(m.get("method"), 10),
                    "ok": m.get("ok") if isinstance(m.get("ok"), bool) else None, "error": _text(m.get("error"), 200),
                    "level": m.get("level") if m.get("level") in ("ok", "warning", "critical") else "ok",
                    "latest": {k: _number(latest.get(k)) for k in ("cpu", "mem", "disk", "temp", "battery", "uptime", "rx", "tx", "supply") if k in latest},
                    "disk_label": _text(latest.get("disk_label"), 60), "supply_label": _text(latest.get("supply_label"), 60)})
    return out


def _scan(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    return {"finished": _stamp(item.get("finished")), "running": bool(item.get("running")), "hosts": item.get("hosts") if isinstance(item.get("hosts"), int) else None}


# ----------------------------------------------------------------------------- probes that went quiet
def check_silent(conn: sqlite3.Connection, now: float | None = None) -> list[str]:
    """One `probe_offline` event for every probe that has stopped reporting (and stays quiet until it reports again)."""
    now = now if now is not None else time.time()
    raised = []
    frozen = locked_ids(conn)
    for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 AND last_seen IS NOT NULL AND offline_notified = 0"):
        if row["id"] in frozen:
            continue
        seen = _parse(row["last_seen"])
        if seen is not None and now - seen > max(SILENT_AFTER_S, row["interval_s"] * 4):
            conn.execute("UPDATE probes SET offline_notified = 1 WHERE id = ?", (row["id"],))
            conn.commit()
            add_event(conn, "probe_offline", f"{row['customer'] + ' / ' if row['customer'] else ''}{row['name']} has not reported since {row['last_seen']}: its devices are not being watched", now=datetime.fromtimestamp(now, timezone.utc).strftime(STAMP),
                      subject=f"site:{row['id']}")
            raised.append(row["name"])
    return raised


# ----------------------------------------------------------------------------- commands for a site
COMMANDS = {"scan": "a quick scan", "scan_deep": "a deep scan"}


def _commands_key(probe_id: int) -> str:
    return f"probe.commands.{probe_id}"


def pending_commands(conn: sqlite3.Connection, probe_id: int) -> list[str]:
    from app.db import get_setting

    try:
        data = json.loads(get_setting(conn, _commands_key(probe_id)) or "[]")
    except ValueError:
        return []
    return [c for c in data if c in COMMANDS] if isinstance(data, list) else []


def queue_command(conn: sqlite3.Connection, probe_id: int, command: str) -> list[str]:
    """Ask the site to do something with its next report (it must accept commands). The same command is kept once."""
    from app.db import set_setting

    if command not in COMMANDS:
        raise ProbeError(f"unknown command; choose one of {', '.join(COMMANDS)}")
    row = conn.execute("SELECT summary FROM probes WHERE id = ?", (probe_id,)).fetchone()
    if not json.loads(row["summary"] or "{}").get("accepts_config"):
        raise ProbeError("this site does not accept commands yet: tick “Accept configuration and commands from the central Netlens” in its Settings → Report to a central Netlens")
    queue = pending_commands(conn, probe_id)
    if command not in queue:
        queue.append(command)
    set_setting(conn, _commands_key(probe_id), json.dumps(queue))
    return queue


def take_commands(conn: sqlite3.Connection, probe_id: int) -> list[str]:
    """The commands waiting for the site; they are handed over once."""
    from app.db import set_setting

    queue = pending_commands(conn, probe_id)
    if queue:
        set_setting(conn, _commands_key(probe_id), "[]")
    return queue


def site_events(conn: sqlite3.Connection, probe_id: int, limit: int = 30) -> list[dict]:
    """What happened at a site, newest first: the alerts this Netlens raised about it (they all start with the site's name)."""
    row = conn.execute("SELECT name, customer FROM probes WHERE id = ?", (probe_id,)).fetchone()
    if row is None:
        return []
    label = f"{row['customer']} / {row['name']}" if row["customer"] else row["name"]
    like = label.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    rows = conn.execute("SELECT id, ts, kind, detail, maintenance FROM events WHERE (detail LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\') AND (kind LIKE 'remote\\_%' ESCAPE '\\' OR kind LIKE 'probe\\_%' ESCAPE '\\' OR kind = 'vuln_critical') "
                        "ORDER BY id DESC LIMIT ?", (like + ": %", like + " has not reported%", limit)).fetchall()
    return [dict(r) for r in rows]


def delete(conn: sqlite3.Connection, probe_id: int) -> None:
    for table, entity in (("remote_devices", "remote"), ("remote_services", "remote_service")):
        for r in conn.execute(f"SELECT id FROM {table} WHERE probe_id = ?", (probe_id,)).fetchall():
            tsdb_forget(entity, r["id"], conn)
    conn.execute("DELETE FROM probes WHERE id = ?", (probe_id,))
    conn.execute("DELETE FROM settings WHERE key IN (?, ?)", (_commands_key(probe_id), f"probe.config.{probe_id}"))
    conn.commit()
