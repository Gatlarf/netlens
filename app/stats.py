"""Statistics about the network, computed from what Netlens already stores.

`compute_stats` feeds the Statistics page, `summary` is the small, stable document Home Assistant polls. Both are
read-only. `record_daily_snapshot` keeps one row per day so the history charts can go back further than the raw
uptime checks (which are pruned after 90 days).
"""

from __future__ import annotations

import json
import os
import sqlite3
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, utcnow
from app.hierarchy import children_map, load_hierarchy
from app.version import VERSION

SUMMARY_API = 1
RANGES = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}
SNAPSHOT_RETENTION_DAYS = 400
FLAP_TRANSITIONS = 6  # up/down changes within 24 h that make a device "flapping"
MIN_CHECKS = 10  # fewer checks than this say nothing about reliability
TOP = 10
NAME = "COALESCE(d.custom_name, d.hostname, d.primary_ip)"
TYPE = "COALESCE(NULLIF(d.type_override, ''), NULLIF(d.device_type, ''), 'unknown')"


# ----------------------------------------------------------------------------- time helpers
def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ago(now: str, *, days: float = 0, hours: float = 0) -> str:
    return _fmt(_parse(now) - timedelta(days=days, hours=hours))


def _pct(part: float, whole: float) -> float | None:
    return round(part / whole * 100, 2) if whole else None


def _top(counter: Counter, n: int = TOP) -> list[dict]:
    return [{"label": k, "count": v} for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]]


# ----------------------------------------------------------------------------- groups
def _overview(conn, now: str) -> dict:
    row = conn.execute("SELECT COUNT(*) AS n, COALESCE(SUM(online), 0) AS up FROM devices").fetchone()
    total, online = row["n"], row["up"]

    def count(where: str, *args) -> int:
        return conn.execute(f"SELECT COUNT(*) FROM devices WHERE {where}", args).fetchone()[0]

    return {
        "total": total,
        "online": online,
        "offline": total - online,
        "online_pct": _pct(online, total),
        "new_24h": count("first_seen >= ?", _ago(now, hours=24)),
        "new_7d": count("first_seen >= ?", _ago(now, days=7)),
        "new_30d": count("first_seen >= ?", _ago(now, days=30)),
        "stale_30d": count("last_seen < ?", _ago(now, days=30)),
        "ignored": conn.execute("SELECT COUNT(*) FROM ignored_devices").fetchone()[0],
        "unknown": count("trusted = 0"),
    }


def _topology_clients(conn) -> tuple[list[dict], dict[str, str]]:
    """Online clients and node names reported by the enabled topology plugins."""
    clients, node_names = [], {}
    for row in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'plugin.%.data'"):
        try:
            data = json.loads(row["value"])
        except ValueError:
            continue
        if not isinstance(data, dict) or "nodes" not in data:
            continue
        plugin_id = row["key"][len("plugin."):-len(".data")]
        state = get_setting(conn, f"plugin.{plugin_id}")
        try:
            if not json.loads(state or "{}").get("enabled"):
                continue
        except ValueError:
            continue
        gateway = next((n for n in data["nodes"] if n.get("role") == "gateway"), None)
        for node in data["nodes"]:
            for mac in node.get("macs") or [node["mac"]]:
                node_names[mac] = node.get("name") or node["mac"]
        for client in data.get("clients", []):
            mac = client.get("node_mac") or (gateway or {}).get("mac")
            clients.append({"node": node_names.get(mac, "unknown"), "medium": client.get("medium", "unknown"), "band": client.get("band")})
    return clients, node_names


WEAK_RSSI = -75


def _wifi(conn, now: str) -> dict:
    """Signal picture from the newest Wi-Fi sample of every client seen in the last two hours."""
    rows = conn.execute(
        f"""
        SELECT d.id, {NAME} AS n, s.band, s.rssi, s.node
        FROM wifi_samples s JOIN devices d ON d.id = s.device_id
        WHERE s.id = (SELECT MAX(id) FROM wifi_samples WHERE device_id = d.id) AND s.ts >= ?
        """,
        (_ago(now, hours=2),),
    ).fetchall()
    rssis = [r["rssi"] for r in rows if r["rssi"] is not None]
    buckets = Counter()
    for v in rssis:
        buckets["excellent (-55 and better)" if v >= -55 else "good (-56 to -65)" if v >= -65 else "fair (-66 to -75)" if v >= -75 else "weak (below -75)"] += 1
    weakest = sorted((r for r in rows if r["rssi"] is not None), key=lambda r: r["rssi"])[:5]
    return {
        "clients": len(rows),
        "avg_rssi": round(sum(rssis) / len(rssis)) if rssis else None,
        "weak": sum(1 for v in rssis if v < WEAK_RSSI),
        "quality": [{"label": k, "count": v} for k, v in sorted(buckets.items(), key=lambda kv: -kv[1])],
        "weakest": [{"id": r["id"], "name": r["n"], "rssi": r["rssi"], "node": r["node"], "band": r["band"]} for r in weakest],
        "roams_7d": conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'wifi_roamed' AND ts >= ?", (_ago(now, days=7),)).fetchone()[0],
    }


def _composition(conn, devs: dict, hierarchy: dict) -> dict:
    types = Counter(r["t"] for r in conn.execute(f"SELECT {TYPE} AS t FROM devices d"))
    vendors = Counter((r["vendor"] or "Unknown") for r in conn.execute("SELECT vendor FROM devices"))
    systems = Counter()
    for r in conn.execute("SELECT os_name FROM devices"):
        name = (r["os_name"] or "").strip()
        systems[name.split(",")[0][:40] if name else "Unknown"] += 1
    subnets = Counter()
    for r in conn.execute("SELECT primary_ip FROM devices"):
        ip = r["primary_ip"]
        subnets[".".join(ip.split(".")[:3]) + ".0/24" if ip and ip.count(".") == 3 else "no address"] += 1
    clients, _ = _topology_clients(conn)
    medium = Counter(c["medium"] for c in clients)
    bands = Counter(c["band"] for c in clients if c["medium"] == "wifi" and c["band"])
    per_node = Counter(c["node"] for c in clients)
    top_level = sum(1 for p in hierarchy.values() if p.parent_id is None)
    return {
        "by_type": _top(types, 20),
        "by_group": _groups(conn),
        "by_vendor": _top(vendors),
        "by_os": _top(systems),
        "by_subnet": _top(subnets),
        "connection": {"wired": medium.get("wired", 0), "wifi": medium.get("wifi", 0), "unknown": medium.get("unknown", 0)},
        "wifi_bands": _top(bands),
        "clients_per_node": _top(per_node),
        "top_level": top_level,
        "with_parent": len(hierarchy) - top_level,
    }


def _availability(conn, now: str) -> dict:
    def network(days: float) -> float | None:
        r = conn.execute("SELECT SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ?", (_ago(now, days=days),)).fetchone()
        return _pct(r["u"] or 0, r["n"])

    since = _ago(now, days=7)
    since_day = _ago(now, hours=24)
    per_device: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for r in conn.execute("SELECT device_id, ts, up FROM checks WHERE ts >= ? ORDER BY device_id, ts, id", (since,)):
        per_device[r["device_id"]].append((r["ts"], r["up"]))
    names = {r["id"]: r["n"] for r in conn.execute(f"SELECT d.id, {NAME} AS n FROM devices d")}
    rows = []
    for dev_id, checks in per_device.items():
        if dev_id not in names:
            continue
        ups = sum(u for _, u in checks)
        transitions = sum(1 for a, b in zip(checks, checks[1:]) if a[1] != b[1])
        outages = sum(1 for a, b in zip(checks, checks[1:]) if a[1] == 1 and b[1] == 0) + (1 if checks and checks[0][1] == 0 else 0)
        flaps = sum(1 for a, b in zip(checks, checks[1:]) if a[1] != b[1] and b[0] >= since_day)
        rows.append({"id": dev_id, "name": names[dev_id], "checks": len(checks), "uptime": _pct(ups, len(checks)), "outages": outages, "flaps_24h": flaps, "transitions": transitions})
    ranked = [r for r in rows if r["checks"] >= MIN_CHECKS]
    least = sorted(ranked, key=lambda r: (r["uptime"], -r["outages"], r["name"]))[:5]
    most = sorted(ranked, key=lambda r: (-r["uptime"], r["outages"], r["name"]))[:5]
    flapping_all = [r for r in rows if r["flaps_24h"] >= FLAP_TRANSITIONS]
    flapping = sorted(flapping_all, key=lambda r: -r["flaps_24h"])[:5]

    outages_now = []
    for r in conn.execute(f"SELECT d.id, {NAME} AS n, d.last_seen FROM devices d WHERE d.online = 0 ORDER BY d.last_seen"):
        if r["last_seen"]:
            outages_now.append({"id": r["id"], "name": r["n"], "since": r["last_seen"], "seconds": int((_parse(now) - _parse(r["last_seen"])).total_seconds())})
    outages_now.sort(key=lambda o: -o["seconds"])

    rtt = conn.execute("SELECT AVG(rtt_ms) AS a FROM checks WHERE ts >= ? AND rtt_ms IS NOT NULL", (since_day,)).fetchone()["a"]
    slow = [
        {"id": r["id"], "name": r["n"], "rtt_ms": round(r["a"], 1)}
        for r in conn.execute(
            f"SELECT d.id, {NAME} AS n, AVG(c.rtt_ms) AS a FROM checks c JOIN devices d ON d.id = c.device_id "
            "WHERE c.ts >= ? AND c.rtt_ms IS NOT NULL GROUP BY d.id ORDER BY a DESC, d.id LIMIT 5",
            (since_day,),
        )
    ]
    return {
        "uptime_24h": network(1), "uptime_7d": network(7), "uptime_30d": network(30),
        "least_reliable": least, "most_reliable": most, "flapping": flapping, "flapping_total": len(flapping_all),
        "longest_outages": outages_now[:5], "avg_rtt_ms": round(rtt, 1) if rtt is not None else None, "slowest": slow,
    }


def _identification(conn) -> dict:
    """How well Netlens knows its devices: what is still unknown, hidden behind a private address, or decided by hand."""
    from app.scanner import vendor as vendor_db

    kinds = Counter()
    for r in conn.execute(f"SELECT d.mac, d.vendor, d.custom_name, d.hostname, d.os_name, d.type_override, d.gentle, {TYPE} AS t FROM devices d"):
        kinds["unknown_type"] += 1 if r["t"] == "unknown" else 0
        mac_kind = vendor_db.mac_kind(r["mac"])
        kinds["private_mac"] += 1 if mac_kind == "randomized" else 0
        kinds["no_vendor"] += 1 if (not r["vendor"] and mac_kind == "universal") else 0
        kinds["manual_type"] += 1 if r["type_override"] else 0
        kinds["gentle"] += 1 if r["gentle"] else 0
        kinds["nameless"] += 1 if not (r["custom_name"] or r["hostname"]) else 0
        kinds["no_os"] += 1 if not r["os_name"] else 0
    keys = ("unknown_type", "private_mac", "no_vendor", "manual_type", "gentle", "nameless", "no_os")
    return {k: kinds.get(k, 0) for k in keys}


def _groups(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT COALESCE(g.name, '(no group)') AS label, COUNT(*) AS count FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id GROUP BY label ORDER BY count DESC, label"
    ).fetchall()
    return [{"label": r["label"], "count": r["count"]} for r in rows]


def _backups(conn, now: str) -> dict:
    from app import backup_schedule

    schedule = backup_schedule.get_schedule(conn)
    last = backup_schedule.get_last(conn)
    return {
        "enabled": bool(schedule.get("enabled")), "every_hours": schedule.get("every_hours"), "keep": schedule.get("keep"),
        "last_at": (last or {}).get("at"), "last_ok": None if last is None else bool(last.get("ok")), "last_error": (last or {}).get("error"),
        "last_ok_at": last["at"] if last and last.get("ok") else None,
        "age_s": int((_parse(now) - _parse(last["at"])).total_seconds()) if last and last.get("at") else None,
    }


def _netchecks(conn) -> dict:
    from app import netchecks

    servers = netchecks.list_servers(conn)
    last = netchecks.get_last(conn)
    return {
        "enabled": bool(netchecks.get_settings(conn).get("enabled")),
        "dhcp_servers": len(servers), "untrusted": sum(1 for s in servers if not s["trusted"]),
        "last_run": (last or {}).get("at"), "last_ok": None if not last else bool(last.get("ok")),
    }


def flapping_devices(conn, now: str) -> int:
    """Devices with FLAP_TRANSITIONS or more up/down changes in the last 24 hours."""
    since = _ago(now, hours=24)
    per_device: dict[int, list[int]] = defaultdict(list)
    for r in conn.execute("SELECT device_id, up FROM checks WHERE ts >= ? ORDER BY device_id, ts, id", (since,)):
        per_device[r["device_id"]].append(r["up"])
    return sum(1 for ups in per_device.values() if sum(1 for a, b in zip(ups, ups[1:]) if a != b) >= FLAP_TRANSITIONS)


def _history(conn, now: str, days: int) -> dict:
    cutoff_day = _ago(now, days=days)[:10]
    daily = [dict(r) for r in conn.execute("SELECT day, devices, online, new_devices, open_ports, events, scans FROM stats_daily WHERE day >= ? ORDER BY day", (cutoff_day,))]
    # devices online per hour (24 h / 7 d) or per day (30 d / 90 d), from the uptime checks
    cutoff = _ago(now, days=min(days, 90))
    width = 13 if days <= 7 else 10  # characters of the timestamp that make up the bucket
    per_scan = conn.execute("SELECT ts, SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ? GROUP BY ts ORDER BY ts", (cutoff,)).fetchall()
    buckets: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for r in per_scan:
        buckets[r["ts"][:width]].append((r["u"], r["n"]))
    online_series = [
        {"t": key + (":00" if width == 13 else ""), "online": round(sum(u for u, _ in vals) / len(vals), 1), "monitored": round(sum(n for _, n in vals) / len(vals), 1)}
        for key, vals in sorted(buckets.items())
    ]
    per_day = defaultdict(Counter)
    for r in conn.execute("SELECT substr(ts, 1, 10) AS d, kind, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY d, kind", (_ago(now, days=days),)):
        per_day[r["d"]][r["kind"]] = r["n"]
    events_series = [{"day": d, "total": sum(c.values()), "new": c.get("device_new", 0), "offline": c.get("device_offline", 0)} for d, c in sorted(per_day.items())]
    return {"daily": daily, "online_series": online_series, "events_series": events_series, "bucket": "hour" if width == 13 else "day"}


def _ports(conn, now: str) -> dict:
    open_rows = conn.execute("SELECT device_id, proto, port, service FROM ports WHERE state = 'open'").fetchall()
    by_port = Counter(f"{r['port']}/{r['proto']}" + (f" {r['service']}" if r["service"] else "") for r in open_rows)
    by_service = Counter(r["service"] for r in open_rows if r["service"])
    per_device = Counter(r["device_id"] for r in open_rows)
    names = {r["id"]: r["n"] for r in conn.execute(f"SELECT d.id, {NAME} AS n FROM devices d")}
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    return {
        "open_total": len(open_rows),
        "devices_with_open": len(per_device),
        "devices_without_open": max(total - len(per_device), 0),
        "top_ports": _top(by_port),
        "top_services": _top(by_service),
        "most_open": [{"id": d, "name": names.get(d, str(d)), "count": n} for d, n in sorted(per_device.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
        "opened_7d": conn.execute("SELECT COUNT(*) FROM events WHERE kind IN ('port_opened', 'port_unexpected') AND ts >= ?", (_ago(now, days=7),)).fetchone()[0],
    }


def _structure(conn, devs: dict, hierarchy: dict) -> dict:
    kids = children_map(hierarchy)
    names = {i: (d["custom_name"] or d["hostname"] or d["primary_ip"] or str(i)) for i, d in devs.items()}

    def depth(i: int) -> int:
        n, seen = 0, set()
        while hierarchy[i].parent_id is not None and i not in seen:
            seen.add(i)
            i = hierarchy[i].parent_id
            n += 1
        return n

    busiest = sorted(((len(c), p) for p, c in kids.items() if c), key=lambda t: (-t[0], names.get(t[1], "")))[:5]
    guests = defaultdict(lambda: {"guests": 0, "running": 0})
    for r in conn.execute("SELECT plugin_id, host_name, status FROM hypervisor_guests"):
        g = guests[(r["plugin_id"], r["host_name"])]
        g["guests"] += 1
        g["running"] += 1 if r["status"] == "running" else 0
    return {
        "max_depth": max((depth(i) for i in hierarchy), default=0),
        "sources": _top(Counter(p.source for p in hierarchy.values() if p.parent_id is not None)),
        "busiest_parents": [{"id": p, "name": names.get(p, str(p)), "children": n} for n, p in busiest],
        "hypervisor_hosts": [{"plugin": k[0], "host": k[1], **v} for k, v in sorted(guests.items())],
    }


def _scans(conn, now: str, days: int) -> dict:
    cutoff = _ago(now, days=days)
    rows = conn.execute("SELECT id, kind, status, started, finished, hosts_found FROM scans WHERE started >= ? ORDER BY id", (cutoff,)).fetchall()
    by_kind: dict[str, dict] = {}
    for kind in sorted({r["kind"] for r in rows}):
        mine = [r for r in rows if r["kind"] == kind]
        durations = sorted(int((_parse(r["finished"]) - _parse(r["started"])).total_seconds()) for r in mine if r["status"] == "done" and r["finished"])
        by_kind[kind] = {
            "total": len(mine),
            "done": sum(1 for r in mine if r["status"] == "done"),
            "failed": sum(1 for r in mine if r["status"] == "failed"),
            "cancelled": sum(1 for r in mine if r["status"] == "cancelled"),
            "median_s": int(statistics.median(durations)) if durations else None,
            "p95_s": durations[min(len(durations) - 1, int(len(durations) * 0.95))] if durations else None,
            "max_s": durations[-1] if durations else None,
        }
    trend = [{"id": r["id"], "kind": r["kind"], "started": r["started"], "hosts": r["hosts_found"]} for r in rows if r["status"] == "done"][-30:]
    last = conn.execute("SELECT kind, status, started, finished, hosts_found FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    timeouts = conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'host_timeout' AND ts >= ?", (cutoff,)).fetchone()[0]
    return {"by_kind": by_kind, "hosts_trend": trend, "last": dict(last) if last else None, "host_timeouts": timeouts, "total": len(rows)}


def _events(conn, now: str, days: int) -> dict:
    cutoff = _ago(now, days=days)
    kinds = Counter({r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY kind", (cutoff,))})
    active = [
        {"id": r["id"], "name": r["n"], "count": r["c"]}
        for r in conn.execute(
            f"SELECT d.id, {NAME} AS n, COUNT(*) AS c FROM events e JOIN devices d ON d.id = e.device_id WHERE e.ts >= ? GROUP BY d.id ORDER BY c DESC, d.id LIMIT 5",
            (cutoff,),
        )
    ]
    recent = [
        {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "detail": r["detail"], "device_id": r["device_id"], "device": r["n"]}
        for r in conn.execute(f"SELECT e.id, e.ts, e.kind, e.detail, e.device_id, {NAME} AS n FROM events e LEFT JOIN devices d ON d.id = e.device_id ORDER BY e.id DESC LIMIT 10")
    ]
    return {"total": sum(kinds.values()), "by_kind": _top(kinds, 20), "most_active": active, "recent": recent}


def _services(conn, now: str) -> dict:
    since = _ago(now, hours=24)
    rows = conn.execute("SELECT id, name, kind, host, port, path, enabled, last_up, last_ms, last_detail FROM service_checks ORDER BY name COLLATE NOCASE").fetchall()
    uptime = {r["check_id"]: _pct(r["u"], r["n"]) for r in conn.execute("SELECT check_id, SUM(up) AS u, COUNT(*) AS n FROM service_results WHERE ts >= ? GROUP BY check_id", (since,))}
    checks = [
        {"id": r["id"], "name": r["name"], "kind": r["kind"], "state": None if r["last_up"] is None else ("up" if r["last_up"] else "down"),
         "enabled": bool(r["enabled"]), "uptime_24h": uptime.get(r["id"]), "ms": r["last_ms"], "detail": r["last_detail"]}
        for r in rows
    ]
    active = [c for c in checks if c["enabled"]]
    return {
        "total": len(checks),
        "down": sum(1 for c in active if c["state"] == "down"),
        "up": sum(1 for c in active if c["state"] == "up"),
        "checks": checks[:30],
    }


def _plugin_status(conn) -> list[dict]:
    out = []
    for r in conn.execute("SELECT key, value FROM settings WHERE key LIKE 'plugin.%' AND key NOT LIKE 'plugin.%.%'"):
        plugin_id = r["key"][len("plugin."):]
        try:
            enabled = bool(json.loads(r["value"]).get("enabled"))
        except ValueError:
            continue
        try:
            status = json.loads(get_setting(conn, f"plugin.{plugin_id}.status") or "null")
        except ValueError:
            status = None
        out.append({
            "id": plugin_id, "enabled": enabled,
            "ok": (status or {}).get("ok") if status else None,
            "error": (status or {}).get("error") if status and not status.get("ok") else None,
            "ts": (status or {}).get("ts"),
        })
    return sorted(out, key=lambda p: p["id"])


def _system(conn, db_path: str | None, passive: dict | None = None) -> dict:
    from app.db import SCHEMA_VERSION
    from app.scanner import vendor as vendor_db

    size = None
    try:
        size = os.path.getsize(db_path) if db_path and db_path != ":memory:" else None
    except OSError:
        size = None
    rows = {}
    for table in ("devices", "ports", "events", "checks", "scans", "relations", "device_names"):
        rows[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return {
        "version": VERSION,
        "db_bytes": size,
        "rows": rows,
        "oldest_check": conn.execute("SELECT MIN(ts) FROM checks").fetchone()[0],
        "oldest_event": conn.execute("SELECT MIN(ts) FROM events").fetchone()[0],
        "plugins": _plugin_status(conn),
        "schema": SCHEMA_VERSION,
        "vendor_entries": vendor_db.info()["entries"],
        "passive": passive,
    }


# ----------------------------------------------------------------------------- public API
def compute_stats(conn: sqlite3.Connection, range_key: str = "7d", now: str | None = None, db_path: str | None = None, passive: dict | None = None) -> dict:
    """Everything the Statistics page shows. `range_key` (24h, 7d, 30d, 90d) sets the window of the history groups."""
    if range_key not in RANGES:
        raise ValueError(f"range must be one of {', '.join(RANGES)}")
    now = now or utcnow()
    days = RANGES[range_key]
    devs, hierarchy = load_hierarchy(conn)
    return {
        "generated": now,
        "range": range_key,
        "overview": _overview(conn, now),
        "composition": _composition(conn, devs, hierarchy),
        "wifi": _wifi(conn, now),
        "availability": _availability(conn, now),
        "history": _history(conn, now, days),
        "ports": _ports(conn, now),
        "structure": _structure(conn, devs, hierarchy),
        "scans": _scans(conn, now, days),
        "events": _events(conn, now, days),
        "services": _services(conn, now),
        "identification": _identification(conn),
        "backups": _backups(conn, now),
        "netchecks": _netchecks(conn),
        "system": _system(conn, db_path, passive),
    }


def summary(conn: sqlite3.Connection, now: str | None = None, scan_running: bool = False, stale_after_s: int = 3 * 3600, data_dir=None, passive: dict | None = None) -> dict:
    """The small, versioned document Home Assistant polls (see SUMMARY_API). Keys never disappear within one API version."""
    now = now or utcnow()
    overview = _overview(conn, now)
    wifi = _wifi(conn, now)
    devs, hierarchy = load_hierarchy(conn)
    names = {i: (d["custom_name"] or d["hostname"] or d["primary_ip"] or str(i)) for i, d in devs.items()}
    rows = {r["id"]: r for r in conn.execute("SELECT id, mac, vendor, last_seen, trusted, group_id, " + TYPE + " AS t FROM devices d")}
    group_names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM device_groups")}
    devices = [
        {
            "id": i, "name": names[i], "ip": devs[i]["primary_ip"], "mac": rows[i]["mac"], "online": bool(devs[i]["online"]),
            "type": rows[i]["t"], "vendor": rows[i]["vendor"], "last_seen": rows[i]["last_seen"], "trusted": bool(rows[i]["trusted"]),
            "parent_id": hierarchy[i].parent_id, "parent_name": names.get(hierarchy[i].parent_id), "group": group_names.get(rows[i]["group_id"]),
        }
        for i in sorted(devs)
    ]
    day = conn.execute("SELECT SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ?", (_ago(now, hours=24),)).fetchone()
    week = conn.execute("SELECT SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ?", (_ago(now, days=7),)).fetchone()
    last = conn.execute("SELECT kind, status, started, finished, hosts_found FROM scans WHERE status != 'running' ORDER BY id DESC LIMIT 1").fetchone()
    last_done = conn.execute("SELECT kind, started, finished, hosts_found FROM scans WHERE status = 'done' AND finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    last_info = None
    if last:
        last_info = {"kind": last["kind"], "status": last["status"], "finished": last["finished"], "hosts_found": last["hosts_found"],
                     "duration_s": int((_parse(last["finished"]) - _parse(last["started"])).total_seconds()) if last["finished"] else None}
    age = int((_parse(now) - _parse(last_done["finished"])).total_seconds()) if last_done else None
    failed_24h = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'failed' AND started >= ?", (_ago(now, hours=24),)).fetchone()[0]
    plugins = _plugin_status(conn)
    failing = [p for p in plugins if p["enabled"] and p["ok"] is False]
    # the last scan failed (a single failure in the past day that later scans recovered from is not a problem), a plugin is failing, or no scan finished for a while
    services = _services(conn, now)
    backups = _backups(conn, now)
    problems = ((1 if services["down"] else 0) + (1 if last_info and last_info["status"] == "failed" else 0) + len(failing)
                + (1 if age is not None and age > stale_after_s else 0) + (1 if backups["last_ok"] is False else 0))
    from app import updates
    from app.plugins import index as plugin_index

    upd = updates.status(conn)
    cached = plugin_index.load_cache(conn)
    plugin_updates = 0
    if cached:
        try:
            from app.plugins.index_install import installed_map
            from app.plugins.registry import discover

            entries, _ = plugin_index.parse_index(cached["index"], cached.get("url") == plugin_index.OFFICIAL_URL)
            plugin_updates = sum(1 for v in plugin_index.view(entries, installed_map(conn, discover(data_dir), data_dir or ""), VERSION) if v["update_available"])
        except Exception:  # noqa: BLE001 - a broken cache must not break the summary
            plugin_updates = 0
    return {
        "api": SUMMARY_API,
        "update": {"current": upd["current"], "latest": upd["latest"], "available": upd["available"], "plugin_updates": plugin_updates},
        "version": VERSION,
        "generated": now,
        "devices": {**{k: overview[k] for k in ("total", "online", "offline", "new_24h", "new_7d", "stale_30d", "unknown")}, "flapping": flapping_devices(conn, now)},
        "identification": _identification(conn),
        "backup": {k: backups[k] for k in ("enabled", "last_at", "last_ok", "last_error", "age_s")},
        "netchecks": _netchecks(conn),
        "passive": None if passive is None else {k: passive.get(k) for k in ("enabled", "running", "frames", "applied")},
        "wifi": {k: wifi[k] for k in ("clients", "weak", "avg_rssi")},
        "uptime": {"24h": _pct(day["u"] or 0, day["n"]), "7d": _pct(week["u"] or 0, week["n"])},
        "ports": {"open": conn.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0]},
        "events": {"24h": conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (_ago(now, hours=24),)).fetchone()[0],
                   "last_id": conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]},
        "scans": {"running": scan_running, "last": last_info, "last_ok_age_s": age, "failed_24h": failed_24h},
        "services": {"total": services["total"], "up": services["up"], "down": services["down"]},
        "plugins": plugins,
        "problems": problems,
        "problem": problems > 0,
        "device_list": devices,
    }


def record_daily_snapshot(conn: sqlite3.Connection, now: str | None = None) -> None:
    """Upsert today's row (and drop rows older than the retention). Called after every scan."""
    now = now or utcnow()
    day = now[:10]
    overview = _overview(conn, now)
    conn.execute(
        """
        INSERT INTO stats_daily (day, devices, online, new_devices, open_ports, events, scans)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(day) DO UPDATE SET devices = excluded.devices, online = excluded.online, new_devices = excluded.new_devices,
            open_ports = excluded.open_ports, events = excluded.events, scans = excluded.scans
        """,
        (
            day, overview["total"], overview["online"],
            conn.execute("SELECT COUNT(*) FROM devices WHERE substr(first_seen, 1, 10) = ?", (day,)).fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM events WHERE substr(ts, 1, 10) = ?", (day,)).fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM scans WHERE substr(started, 1, 10) = ?", (day,)).fetchone()[0],
        ),
    )
    conn.execute("DELETE FROM stats_daily WHERE day < ?", (_ago(now, days=SNAPSHOT_RETENTION_DAYS)[:10],))
    conn.commit()
