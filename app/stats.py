"""Statistics about the network, computed from what Netlens already stores.

`compute_stats` feeds the Statistics page, `summary` is the small, stable document Home Assistant polls. Both are
read-only. `record_daily_snapshot` keeps one row per day so the history charts can go back further than the raw
uptime checks (which are pruned after 90 days).
"""

from __future__ import annotations

import itertools

import json
import os
import sqlite3
import functools
import statistics
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app import checkstats, containers, guestbackups, inventory, linkgroups, remediation, sites, speedtest, storage
from app import licence as _licence, vulns as _vulns
from app.db import get_setting, utcnow
from app.hierarchy import children_map, load_hierarchy
from app.version import VERSION

SUMMARY_API = 1
RANGES = {"6h": 0.25, "24h": 1, "7d": 7, "30d": 30, "90d": 90}          # in days
SNAPSHOT_RETENTION_DAYS = 400
FLAP_TRANSITIONS = 6  # up/down changes within 24 h that make a device "flapping"
MIN_CHECKS = 10  # fewer checks than this say nothing about reliability
TOP = 10
NAME = "COALESCE(d.custom_name, d.hostname, d.primary_ip)"
TYPE = "COALESCE(NULLIF(d.type_override, ''), NULLIF(d.device_type, ''), 'unknown')"


# ----------------------------------------------------------------------------- time helpers
def _parse(ts: str) -> datetime:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        # stamps written by older versions (the backup schedule) carry microseconds and "+00:00"
        return datetime.fromisoformat(ts).astimezone(timezone.utc)


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


_local = threading.local()


class memo_scope:
    """While it is open, the same expensive question asked twice (who flapped in the last 24 hours) is answered once. A page and the numbers
    for Prometheus ask it several times: for everybody, for the always-on devices, for the lists."""

    def __enter__(self):
        self.outer = getattr(_local, "memo", None)
        if self.outer is None:
            _local.memo = {}
        return self

    def __exit__(self, *exc):
        if self.outer is None:
            _local.memo = None


def _quick_sequences(conn, since: str, ids: list[int] | None = None) -> dict[int, tuple[int, int]]:
    """(outages, transitions) since `since` of the devices that have quick checks (beats) in that time, worked out from every check of theirs with the
    debounce of the quick checks: one lost answer is no outage. The transitions are the same kind of number as the plain count of up/down changes
    (an outage that ended is two, one that goes on is one), so the flapping limit means the same. Devices without quick checks are not in the result."""
    from app import beats, flapping

    misses = beats.settings(conn)[1]
    quick = [r[0] for r in conn.execute("SELECT DISTINCT device_id FROM checks WHERE beat = 1 AND ts >= ?", (since,))]
    if ids is not None:
        wanted = set(ids)
        quick = [d for d in quick if d in wanted]
    out: dict[int, tuple[int, int]] = {}
    for i in range(0, len(quick), 400):
        part = quick[i:i + 400]
        marks = ",".join("?" * len(part))
        rows = conn.execute(f"SELECT device_id, ts, up, beat FROM checks WHERE ts >= ? AND device_id IN ({marks}) ORDER BY device_id, ts, id", [since, *part]).fetchall()
        for device, group in itertools.groupby(rows, key=lambda r: r["device_id"]):
            runs = flapping.outages(list(group), misses)
            out[device] = (len(runs), sum(2 if o["end"] else 1 for o in runs))
    return out


def _flaps(conn, since: str, core: bool | None = None) -> dict[int, int]:
    """Per device the changes between up and down among its checks since `since` (only devices that changed at all)."""
    memo = getattr(_local, "memo", None)
    key = (id(conn), since)
    if memo is None or key not in memo:
        found = {r[0]: r[1] for r in conn.execute(
            "WITH s AS (SELECT device_id AS d, up, LAG(up) OVER (PARTITION BY device_id ORDER BY ts, id) AS prev FROM checks WHERE ts >= ? AND beat = 0) "
            "SELECT d, SUM(prev IS NOT NULL AND prev != up) AS n FROM s GROUP BY d HAVING n > 0", (since,))}
        for device, (_outages, transitions) in _quick_sequences(conn, since).items():       # devices with quick checks: counted without the single lost answers
            if transitions:
                found[device] = transitions
            else:
                found.pop(device, None)
        if memo is not None:
            memo[key] = found
    else:
        found = memo[key]
    if core is None or not found:
        return found
    wanted = {r[0] for r in conn.execute("SELECT id FROM devices WHERE always_on = ?", (1 if core else 0,))}
    return {d: n for d, n in found.items() if d in wanted}


def _sequences(conn, ids: list[int], since: str) -> dict[int, tuple[int, int]]:
    """(outages, transitions) of the given devices since `since`: an outage is a check that is down after one that was up (or a first check that is down)."""
    out: dict[int, tuple[int, int]] = {}
    for i in range(0, len(ids), 400):
        part = ids[i:i + 400]
        marks = ",".join("?" * len(part))
        rows = conn.execute(
            "WITH s AS (SELECT device_id AS d, up, LAG(up) OVER (PARTITION BY device_id ORDER BY ts, id) AS prev, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY ts, id) AS rn "
            f"FROM checks WHERE ts >= ? AND beat = 0 AND device_id IN ({marks})) "
            "SELECT d, SUM(prev IS NOT NULL AND prev != up), SUM(prev = 1 AND up = 0) + SUM(rn = 1 AND up = 0) FROM s GROUP BY d", [since, *part])
        for d, transitions, outages in rows:
            out[d] = (outages or 0, transitions or 0)
    out.update(_quick_sequences(conn, since, ids))
    return out


def _availability(conn, now: str) -> dict:
    def network(days: float) -> float | None:
        u, n = checkstats.network(conn, _ago(now, days=days))
        return _pct(u, n)

    since = _ago(now, days=7)
    since_day = _ago(now, hours=24)
    names = {r["id"]: r["n"] for r in conn.execute(f"SELECT d.id, {NAME} AS n FROM devices d")}
    sums = {d: v for d, v in checkstats.totals(conn, since).items() if d in names}
    flaps = _flaps(conn, since_day)

    def row_of(dev_id: int, outages: int = 0, transitions: int = 0) -> dict:
        ups, n = sums[dev_id][0], sums[dev_id][1]
        return {"id": dev_id, "name": names[dev_id], "checks": n, "uptime": _pct(ups, n), "outages": outages, "flaps_24h": flaps.get(dev_id, 0), "transitions": transitions}

    # Only the devices that can end up in a list need their outage and transition counts, which need the checks in order. A device that was never down has
    # none, so on a healthy network that is almost every device. Devices past the fifth place on uptime cannot appear (ties are broken by the outage count).
    quick = {d: row_of(d) for d in sums}
    wanted: set[int] = set(sorted(flaps, key=lambda d: -flaps[d])[:5])
    ranked_ids = [d for d in quick if quick[d]["checks"] >= MIN_CHECKS]
    if ranked_ids:
        ups = sorted(quick[d]["uptime"] for d in ranked_ids)
        low_edge, high_edge = ups[min(4, len(ups) - 1)], ups[max(0, len(ups) - 5)]
        wanted |= {d for d in ranked_ids if quick[d]["uptime"] <= low_edge or quick[d]["uptime"] >= high_edge}
    seq = _sequences(conn, [d for d in wanted if sums[d][0] < sums[d][1]], since)
    rows = [row_of(d, *seq[d]) if d in seq else quick[d] for d in quick]
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
        "core": core_numbers(conn, now),
        "least_reliable": least, "most_reliable": most, "flapping": flapping, "flapping_total": len(flapping_all),
        "longest_outages": outages_now[:5], "avg_rtt_ms": round(rtt, 1) if rtt is not None else None, "slowest": slow,
    }


def _identification(conn) -> dict:
    """How well Netlens knows its devices: what is still unknown, hidden behind a private address, or decided by hand."""
    from app.scanner import vendor as vendor_db

    from app.scanner.options import saved_gentle_types

    kinds = Counter()
    gentle_types = set(saved_gentle_types(conn))
    for r in conn.execute(f"SELECT d.mac, d.vendor, d.custom_name, d.hostname, d.os_name, d.type_override, d.gentle, d.gentle_off, {TYPE} AS t FROM devices d"):
        kinds["unknown_type"] += 1 if r["t"] == "unknown" else 0
        mac_kind = vendor_db.mac_kind(r["mac"])
        kinds["private_mac"] += 1 if mac_kind == "randomized" else 0
        kinds["no_vendor"] += 1 if (not r["vendor"] and mac_kind == "universal") else 0
        kinds["manual_type"] += 1 if r["type_override"] else 0
        kinds["gentle"] += 1 if (r["gentle"] or (not r["gentle_off"] and r["t"] in gentle_types)) else 0
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
        "enabled": bool(netchecks.get_settings(conn)["dhcp_enabled"]),
        "dhcp_servers": len(servers), "untrusted": sum(1 for s in servers if not s["trusted"]),
        "last_run": (last or {}).get("at"), "last_ok": None if not last else bool(last.get("ok")),
    }


def _dns(conn) -> dict:
    """DNS registration in numbers (from the last plan Netlens made after a scan)."""
    counts = {r["state"]: r["n"] for r in conn.execute("SELECT state, COUNT(*) AS n FROM dns_state WHERE state IS NOT NULL GROUP BY state")}
    return {
        "registered": counts.get("ok", 0), "pending": counts.get("add", 0) + counts.get("update", 0) + counts.get("delete", 0),
        "conflicts": counts.get("conflict", 0), "registers_itself": counts.get("self", 0), "waiting": counts.get("wait", 0),
    }


def flapping_devices(conn, now: str, core: bool | None = None) -> int:
    """Devices with FLAP_TRANSITIONS or more up/down changes in the last 24 hours. core=True: only the always-on devices, False: only the others."""
    return sum(1 for n in _flaps(conn, _ago(now, hours=24), core).values() if n >= FLAP_TRANSITIONS)


def core_numbers(conn, now: str) -> dict:
    """The always-on ("core") devices: how many there are, how many are online, their availability and how many of them flap.
    The availability is None while no device is marked."""
    row = conn.execute("SELECT COUNT(*) AS n, COALESCE(SUM(online), 0) AS o FROM devices WHERE always_on = 1").fetchone()

    def pct(days: float) -> float | None:
        u, n = checkstats.network(conn, _ago(now, days=days), core=True)
        return _pct(u, n)

    return {"devices": row["n"], "online": row["o"], "uptime": {"24h": pct(1), "7d": pct(7), "30d": pct(30)}, "flapping": flapping_devices(conn, now, True) if row["n"] else 0}


def _history(conn, now: str, days: float) -> dict:
    cutoff_day = _ago(now, days=days)[:10]
    daily = [dict(r) for r in conn.execute("SELECT day, devices, online, new_devices, open_ports, events, scans FROM stats_daily WHERE day >= ? ORDER BY day", (cutoff_day,))]
    # devices online per hour (24 h / 7 d) or per day (30 d / 90 d), from the uptime checks
    cutoff = _ago(now, days=min(days, 90))
    width = 16 if days < 1 else 13 if days <= 7 else 10  # characters of the timestamp that make up the bucket: per scan (minute), hour or day
    per_scan = conn.execute("SELECT ts, SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ? AND beat = 0 GROUP BY ts ORDER BY ts", (cutoff,)).fetchall()
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
    return {"daily": daily, "online_series": online_series, "events_series": events_series, "bucket": "minute" if width == 16 else "hour" if width == 13 else "day"}


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


def _applications(conn, days: int) -> dict:
    """Traffic per application and per device over the last `days` days, as the router's traffic analyser counted it (empty when no plugin reports it)."""
    from app import usagecfg

    if not usagecfg.enabled(conn):
        return {"available": False, "enabled": False}
    last = conn.execute("SELECT MAX(day) FROM app_usage").fetchone()[0]
    if last is None:
        return {"available": False, "enabled": True}
    first = (datetime.strptime(last, "%Y-%m-%d") - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    apps = conn.execute(
        "SELECT name, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM app_usage WHERE day >= ? GROUP BY name ORDER BY SUM(rx_bytes) + SUM(tx_bytes) DESC", (first,)
    ).fetchall()
    per_day = conn.execute("SELECT day, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM app_usage WHERE day >= ? GROUP BY day ORDER BY day", (first,)).fetchall()
    clients = conn.execute(
        f"SELECT d.id, {NAME} AS n, SUM(u.rx_bytes) AS rx, SUM(u.tx_bytes) AS tx FROM client_usage u JOIN devices d ON d.id = u.device_id "
        "WHERE u.day >= ? GROUP BY d.id ORDER BY SUM(u.rx_bytes) + SUM(u.tx_bytes) DESC LIMIT 10", (first,)
    ).fetchall()
    total = sum(r["rx"] + r["tx"] for r in apps)
    return {
        "available": True, "enabled": True, "from": first, "to": last, "days": len(per_day),
        "rx": sum(r["rx"] for r in apps), "tx": sum(r["tx"] for r in apps), "applications_total": len(apps),
        "applications": [{"name": r["name"], "rx": r["rx"], "tx": r["tx"], "share": _pct(r["rx"] + r["tx"], total)} for r in apps[:15]],
        "per_day": [{"day": r["day"], "rx": r["rx"], "tx": r["tx"]} for r in per_day],
        "clients": [{"id": r["id"], "name": r["n"], "rx": r["rx"], "tx": r["tx"]} for r in clients],
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


def _scans(conn, now: str, days: float) -> dict:
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


def _events(conn, now: str, days: float) -> dict:
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
    rows = conn.execute("SELECT id, name, kind, host, port, path, enabled, last_up, last_ms, last_detail FROM service_checks ORDER BY LOWER(name)").fetchall()
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
    from app.plugins.service import failure_grace

    grace = failure_grace(conn)
    out = []
    for r in conn.execute("SELECT key FROM settings WHERE key LIKE 'plugin.%' AND key NOT LIKE 'plugin.%.%'").fetchall():
        plugin_id = r["key"][len("plugin."):]
        try:
            enabled = bool(json.loads(get_setting(conn, r["key"]) or "null").get("enabled"))       # the saved configuration is encrypted
        except (ValueError, AttributeError):
            continue
        try:
            status = json.loads(get_setting(conn, f"plugin.{plugin_id}.status") or "null")
        except ValueError:
            status = None
        ok = (status or {}).get("ok") if status else None
        fails = ((status or {}).get("fails") or grace) if ok is False else 0      # a failure stored before the count existed is judged as before
        # a refused login is a problem at once (syncing is paused); a timeout or a busy server only after a few failures in a row
        failing = ok is False and (bool((status or {}).get("auth_failed")) or fails >= grace)
        out.append({
            "id": plugin_id, "enabled": enabled,
            "ok": ok, "failing": failing, "fails": fails, "grace": grace,
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
def _shared(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with memo_scope():
            return fn(*args, **kwargs)

    return wrapper


@_shared
def compute_stats(conn: sqlite3.Connection, range_key: str = "7d", now: str | None = None, db_path: str | None = None, passive: dict | None = None) -> dict:
    """Everything the Statistics page shows. `range_key` (6h, 24h, 7d, 30d, 90d) sets the window of the history groups."""
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
        "applications": _applications(conn, max(1, int(days))),
        "structure": _structure(conn, devs, hierarchy),
        "scans": _scans(conn, now, days),
        "events": _events(conn, now, days),
        "services": _services(conn, now),
        "identification": _identification(conn),
        "backups": _backups(conn, now),
        "netchecks": _netchecks(conn),
        "containers": containers.summary(conn),
        "guests": containers.guest_summary(conn),
        "sites": {**sites.summary(conn), "certificate_list": sites.certificates(conn)[:30]},
        "speed": speedtest.stats(conn, now, days),
        "system": _system(conn, db_path, passive),
    }


def _health(conn: sqlite3.Connection) -> tuple[dict, dict[int, dict]]:
    """The health monitors in numbers, and the newest readings of each monitored device (for the per-device entities)."""
    from app import forecast, tsdb
    from app.hostmetrics import service as hm

    rows = conn.execute("SELECT device_id, last_ok FROM host_monitors WHERE enabled = 1").fetchall()
    levels: dict[int, str] = {}
    problems = hm.problems(conn, include_snoozed=False)       # what someone has acknowledged is not counted
    for p in problems:
        cur = levels.get(p["device_id"], "ok")
        levels[p["device_id"]] = "critical" if "critical" in (cur, p["level"]) else "warning"
    store = tsdb.for_conn(conn)
    per_device = {}
    known = store.metrics_of_many("device", [r["device_id"] for r in rows]) if store is not None else {}
    for r in rows:
        latest = hm.latest_readings(store, r["device_id"], known.get(r["device_id"], []))
        per_device[r["device_id"]] = {"level": levels.get(r["device_id"], "ok"), "readable": None if r["last_ok"] is None else bool(r["last_ok"]),
                                      **{k: latest[k] for k in ("cpu", "mem", "disk", "temp", "battery", "rx", "tx")}}
    days = [f["days_to_full"] for f in forecast.cached(conn) if f["days_to_full"] is not None]
    block = {"monitored": len(rows), "warning": sum(1 for d in per_device.values() if d["level"] == "warning"),
             "critical": sum(1 for d in per_device.values() if d["level"] == "critical"),
             "unreadable": sum(1 for d in per_device.values() if d["readable"] is False), "problems": len(problems),
             "days_to_full": round(min(days), 1) if days else None}
    return block, per_device


def _remote_sites(conn: sqlite3.Connection) -> dict:
    from app import probes

    sites = [site for site in (probes.present(conn, r) for r in conn.execute("SELECT * FROM probes WHERE enabled = 1")) if not site["locked"]]
    return {"total": len(sites), "silent": sum(1 for s in sites if s["state"] == "silent"), "problems": sum(s["problems"]["count"] for s in sites),
            "devices_down": sum(s["devices"]["total"] - s["devices"]["online"] for s in sites), "services_down": sum(s["services"]["down"] for s in sites)}


@_shared
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
    health, health_by_device = _health(conn)
    for d in devices:
        if d["id"] in health_by_device:
            d["health"] = health_by_device[d["id"]]
    day, week, month = (dict(zip(("u", "n"), checkstats.network(conn, since))) for since in (_ago(now, hours=24), _ago(now, days=7), _ago(now, days=30)))
    last = conn.execute("SELECT kind, status, started, finished, hosts_found FROM scans WHERE status != 'running' ORDER BY id DESC LIMIT 1").fetchone()
    last_done = conn.execute("SELECT kind, started, finished, hosts_found FROM scans WHERE status = 'done' AND finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    last_info = None
    if last:
        last_info = {"kind": last["kind"], "status": last["status"], "finished": last["finished"], "hosts_found": last["hosts_found"],
                     "duration_s": int((_parse(last["finished"]) - _parse(last["started"])).total_seconds()) if last["finished"] else None}
    age = int((_parse(now) - _parse(last_done["finished"])).total_seconds()) if last_done else None
    failed_24h = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'failed' AND started >= ?", (_ago(now, hours=24),)).fetchone()[0]
    plugins = _plugin_status(conn)
    failing = [p for p in plugins if p["enabled"] and p["failing"]]
    # the last scan failed (a single failure in the past day that later scans recovered from is not a problem), a plugin is failing, or no scan finished for a while
    services = _services(conn, now)
    backups = _backups(conn, now)
    container_numbers = containers.summary(conn)
    guest_numbers = containers.guest_summary(conn)
    problems = ((1 if services["down"] else 0) + (1 if container_numbers["problems"] else 0) + (1 if last_info and last_info["status"] == "failed" else 0) + len(failing)
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
    plugin_problems = 0
    if data_dir:
        try:
            from app.plugins import autoupdate

            found = autoupdate.check(conn, data_dir)
            plugin_problems = 0 if found["dismissed"] else len(found["problems"])
        except Exception:  # noqa: BLE001
            plugin_problems = 0
    return {
        "api": SUMMARY_API,
        "update": {"current": upd["current"], "latest": upd["latest"], "available": upd["available"], "plugin_updates": plugin_updates, "plugin_problems": plugin_problems},
        "version": VERSION,
        "generated": now,
        "devices": {**{k: overview[k] for k in ("total", "online", "offline", "new_24h", "new_7d", "stale_30d", "unknown")}, "flapping": flapping_devices(conn, now), "always_on": conn.execute("SELECT COUNT(*) FROM devices WHERE always_on = 1").fetchone()[0]},
        "identification": _identification(conn),
        "backup": {k: backups[k] for k in ("enabled", "last_at", "last_ok", "last_error", "age_s")},
        "netchecks": _netchecks(conn),
        "dns": _dns(conn),
        "containers": {k: container_numbers[k] for k in ("total", "running", "stopped", "restarting", "unhealthy", "exposed", "hosts")},
        "guests": {k: guest_numbers[k] for k in ("total", "running", "stopped", "hosts", "by_kind", "update_available", "image_updates", "old_images")},
        "sites": sites.summary(conn),
        "guest_backups": guestbackups.summary(conn),
        "storage": storage.summary(conn),
        "link_groups": linkgroups.summary(conn),
        "vulns": vulns_summary(conn),
        "smarthome": inventory.summary(conn),
        "remediation": remediation.summary(conn),
        "health": health,
        "remote_sites": _remote_sites(conn),
        "speed": speedtest.summary(conn, now),
        "passive": None if passive is None else {k: passive.get(k) for k in ("enabled", "running", "frames", "applied")},
        "wifi": {k: wifi[k] for k in ("clients", "weak", "avg_rssi")},
        "uptime": {"24h": _pct(day["u"] or 0, day["n"]), "7d": _pct(week["u"] or 0, week["n"]), "30d": _pct(month["u"] or 0, month["n"])},
        "core": core_numbers(conn, now),
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


def vulns_summary(conn: sqlite3.Connection) -> dict:
    """The vulnerability figures for the dashboard; without a licence for them nothing is shown (the page explains why)."""
    if not _licence.allows(conn, "vulnerabilities"):
        return {"allowed": False, "configured": False, "counts": {}, "total": 0, "devices": 0, "exploited": 0, "servers": 0, "last_scan": None}
    return {"allowed": True, **_vulns.summary(conn)}
