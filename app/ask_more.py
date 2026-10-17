"""The rest of the questions of "Ask your network": what is on the network, ports, virtual machines, backups, certificates, speed tests, remote sites,
smart home, security, who changed what, what is connected to what, Wi-Fi, maintenance, versions and updates.

Every question is a read-only tool: a function that returns a small piece of data, the sentence that writes it out without a language model,
and the words (a route) that make Netlens pick it on its own. A language model sees the same tools through their descriptions.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app import ask
from app.ask import LIMIT, _days, _name, _since

STAMP = "%Y-%m-%dT%H:%M:%SZ"
SERVICE_PORTS = {"ssh": 22, "telnet": 23, "ftp": 21, "smtp": 25, "dns": 53, "http": 80, "https": 443, "smb": 445, "samba": 445, "rdp": 3389, "vnc": 5900, "mqtt": 1883, "snmp": 161,
                 "mysql": 3306, "postgres": 5432, "printing": 631, "ntp": 123}
ETYPE = "COALESCE(d.type_override, d.device_type, 'unknown')"


def _like(text: Any) -> str:
    return "%" + str(text).strip().lower().replace("%", "").replace("_", "\\_")[:60] + "%"


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return True if text in ("true", "1", "yes", "online", "up") else False if text in ("false", "0", "no", "offline", "down") else None


def _short(row) -> dict:
    return {"name": _name(row), "ip": row["primary_ip"], "type": row["type_override"] or row["device_type"], "vendor": row["vendor"], "os": row["os_name"], "online": bool(row["online"])}


# ----------------------------------------------------------------------------- tools
def t_search_devices(conn, args, now=None) -> dict:
    where, params, shown = ["1 = 1"], [], {}
    kind = ask._type_word(str(args.get("type") or "").strip().lower()) if args.get("type") else None
    if args.get("type") and not kind:                  # not one of the kinds ("iphone", "raspberry"): look for the word in the names instead
        args = {**args, "text": args.get("text") or args["type"], "type": None}
    if kind:
        where.append(f"{ETYPE} = ?")
        params.append(kind)
        shown["type"] = kind
    if args.get("vendor"):
        where.append("LOWER(COALESCE(d.vendor, '')) LIKE ? ESCAPE '\\'")
        params.append(_like(args["vendor"]))
        shown["vendor"] = args["vendor"]
    if args.get("os"):
        where.append("LOWER(COALESCE(d.os_name, '')) LIKE ? ESCAPE '\\'")
        params.append(_like(args["os"]))
        shown["os"] = args["os"]
    online = _bool(args["online"]) if args.get("online") not in (None, "") else None
    if online is not None:
        where.append("d.online = ?")
        params.append(1 if online else 0)
        shown["online"] = online
    if args.get("port"):
        try:
            where.append("EXISTS (SELECT 1 FROM ports p WHERE p.device_id = d.id AND p.port = ? AND p.state LIKE 'open%')")
            params.append(int(args["port"]))
            shown["port"] = int(args["port"])
        except (TypeError, ValueError):
            pass
    if args.get("service"):
        where.append("EXISTS (SELECT 1 FROM ports p WHERE p.device_id = d.id AND LOWER(COALESCE(p.service, '')) LIKE ? ESCAPE '\\' AND p.state LIKE 'open%')")
        params.append(_like(args["service"]))
        shown["service"] = args["service"]
    if args.get("group"):
        where.append("d.group_id IN (SELECT id FROM device_groups WHERE LOWER(name) LIKE ? ESCAPE '\\')")
        params.append(_like(args["group"]))
        shown["group"] = args["group"]
    if args.get("tag"):
        where.append("LOWER(COALESCE(d.tags, '')) LIKE ? ESCAPE '\\'")
        params.append(_like(args["tag"]))
        shown["tag"] = args["tag"]
    if args.get("text"):
        where.append("(LOWER(COALESCE(d.custom_name, '')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(d.hostname, '')) LIKE ? ESCAPE '\\' OR COALESCE(d.primary_ip, '') LIKE ? ESCAPE '\\')")
        params += [_like(args["text"])] * 3
        shown["text"] = args["text"]
    if args.get("new_days"):
        where.append("d.first_seen >= ?")
        params.append(_since(_days(args["new_days"]), now))
        shown["new_in_days"] = _days(args["new_days"])
    if _bool(args.get("untrusted")):
        where.append("d.trusted = 0")
        shown["untrusted"] = True
    rows = conn.execute(f"SELECT d.* FROM devices d WHERE {' AND '.join(where)} ORDER BY d.online DESC, d.last_seen DESC", params).fetchall()
    return {"filters": shown, "count": len(rows), "devices": [_short(r) for r in rows[:20]]}


def t_counts(conn, args, now=None) -> dict:
    by = str(args.get("by") or "type").lower()
    column = {"type": ETYPE, "vendor": "COALESCE(d.vendor, 'unknown')", "os": "COALESCE(d.os_name, 'unknown')", "group": "COALESCE((SELECT name FROM device_groups g WHERE g.id = d.group_id), 'no group')"}.get(by)
    if column is None:
        by, column = "type", ETYPE
    rows = conn.execute(f"SELECT {column} AS k, COUNT(*) AS n, SUM(d.online) AS up FROM devices d GROUP BY k ORDER BY n DESC LIMIT 15").fetchall()
    total = conn.execute("SELECT COUNT(*) AS n, SUM(online) AS up FROM devices").fetchone()
    return {"by": by, "total": total["n"], "online": total["up"] or 0, "groups": [{"name": r["k"], "devices": r["n"], "online": r["up"] or 0} for r in rows]}


def t_ports(conn, args, now=None) -> dict:
    if args.get("device"):
        needle = str(args["device"]).strip().lower()
        row = next((r for r in conn.execute("SELECT * FROM devices") if needle in _name(r).lower() or needle == (r["primary_ip"] or "")), None)
        if row is None:
            return {"error": f"no device matches {needle!r}"}
        ports = conn.execute("SELECT proto, port, service, product FROM ports WHERE device_id = ? AND state LIKE 'open%' ORDER BY port LIMIT 40", (row["id"],)).fetchall()
        return {"device": _name(row), "open_ports": [{"port": p["port"], "proto": p["proto"], "service": p["service"] or "", "product": p["product"] or ""} for p in ports]}
    port = args.get("port")
    if not port and args.get("service"):
        port = SERVICE_PORTS.get(str(args["service"]).lower())
    found = t_search_devices(conn, {"port": port} if port else {"service": args.get("service")}, now)
    return {"port": port, "service": args.get("service"), "count": found["count"], "devices": found["devices"]}


def t_guests(conn, args, now=None) -> dict:
    where, params = ["1 = 1"], []
    status = str(args.get("status") or "").lower()
    if status and status != "unhealthy":
        if status == "stopped":
            where.append("LOWER(status) IN ('stopped', 'exited', 'dead', 'shut off', 'off')")
        else:
            where.append("LOWER(status) LIKE ?")
            params.append(status + "%")
    if args.get("kind"):
        where.append("LOWER(kind) = ?")
        params.append(str(args["kind"]).lower())
    if args.get("text"):
        where.append("(LOWER(name) LIKE ? ESCAPE '\\' OR LOWER(host_name) LIKE ? ESCAPE '\\')")
        params += [_like(args["text"])] * 2
    rows = conn.execute(f"SELECT * FROM hypervisor_guests WHERE {' AND '.join(where)} ORDER BY status, name COLLATE NOCASE LIMIT 200", params).fetchall()
    if status == "unhealthy":
        rows = [r for r in rows if '"unhealthy"' in (r["details"] or "")]
    states = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) AS n FROM hypervisor_guests GROUP BY status")}
    out = []
    for r in rows[:25]:
        try:
            d = json.loads(r["details"] or "{}")
        except ValueError:
            d = {}
        out.append({"name": r["name"], "kind": r["kind"], "host": r["host_name"], "status": r["status"], "plugin": r["plugin_id"], **{k: d[k] for k in ("health", "restarts", "image") if d.get(k) not in (None, "")}})
    return {"filters": {"status": status or None, "kind": args.get("kind"), "text": args.get("text")}, "all_by_status": states, "guests": out}


def t_backups(conn, args, now=None) -> dict:
    from app import guestbackups

    o = guestbackups.overview(conn, now)
    s = o["summary"]
    if not s["configured"]:
        return {"configured": False}
    bad = [{"name": t["name"], "state": t["last_state"], "last_backup": t["last_backup"], "late": t["late"]} for t in o["targets"] if t["last_state"] == "failed" or t["late"]][:LIMIT]
    return {"configured": True, "summary": {k: s[k] for k in ("guests", "protected", "unprotected", "targets", "failed", "late", "stores_at_risk", "problems")}, "failing_or_late": bad,
            "unprotected_guests": [g["name"] for g in o["unprotected"]][:LIMIT], "stores": [{"name": x["name"], "used_pct": x["percent"], "full_in_days": x["days_to_full"], "level": x["level"]} for x in o["stores"]][:6],
            "newest_backup": max((t["last_backup"] for t in o["targets"] if t["last_backup"]), default=None)}


def t_certificates(conn, args, now=None) -> dict:
    from app import tsdb

    store = tsdb.for_conn(conn)
    out = []
    for c in conn.execute("SELECT id, name, host FROM service_checks WHERE enabled = 1"):
        for s in (store.metrics_of("service", c["id"]) if store else []):
            if s["metric"] == "cert_days" and s["last"] is not None:
                out.append({"name": c["name"], "host": c["host"], "days_left": round(s["last"])})
    out.sort(key=lambda x: x["days_left"])
    events = [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'cert_expiring' AND ts >= ? ORDER BY id DESC LIMIT 5", (_since(30, now),))]
    return {"certificates": out[:LIMIT], "checked": len(out), "expiring_alerts": events}


def t_speedtest(conn, args, now=None) -> dict:
    days = _days(args.get("days"), 30)
    rows = conn.execute("SELECT ts, kind, target, down_mbps, up_mbps, latency_ms FROM speedtests WHERE ok = 1 AND ts >= ? ORDER BY ts DESC", (_since(days, now),)).fetchall()
    if not rows:
        return {"days": days, "tests": 0}
    internet = [r for r in rows if r["kind"] not in ("iperf-in", "iperf-out")] or rows
    avg = lambda key: round(sum(r[key] for r in internet if r[key] is not None) / max(1, sum(1 for r in internet if r[key] is not None)), 1)   # noqa: E731
    best = max(internet, key=lambda r: r["down_mbps"] or 0)
    worst = min(internet, key=lambda r: r["down_mbps"] if r["down_mbps"] is not None else 1e9)
    last = rows[0]
    return {"days": days, "tests": len(rows), "latest": {"at": last["ts"], "down_mbps": last["down_mbps"], "up_mbps": last["up_mbps"], "latency_ms": last["latency_ms"]},
            "average": {"down_mbps": avg("down_mbps"), "up_mbps": avg("up_mbps"), "latency_ms": avg("latency_ms")}, "slowest_download": {"at": worst["ts"], "mbps": worst["down_mbps"]},
            "fastest_download": {"at": best["ts"], "mbps": best["down_mbps"]}}


def t_network_services(conn, args, now=None) -> dict:
    dhcp = [{"server": r["ip"], "trusted": bool(r["trusted"]), "router": r["router"], "dns": json.loads(r["dns"] or "[]"), "last_seen": r["last_seen"]} for r in conn.execute("SELECT * FROM dhcp_servers ORDER BY last_seen DESC LIMIT 8")]
    states = {r["state"] or "none": r["n"] for r in conn.execute("SELECT state, COUNT(*) AS n FROM dns_state GROUP BY state")}
    records = conn.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0]
    gateway = conn.execute("SELECT value FROM settings WHERE key = 'gateway.ip'").fetchone()
    return {"dhcp_servers": dhcp, "dns_registration": states, "dns_records_written_by_netlens": records, "gateway": gateway["value"] if gateway else None}


def t_remote_sites(conn, args, now=None) -> dict:
    from app import probes

    sites = []
    for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY name COLLATE NOCASE"):
        p = probes.present(conn, row)
        sites.append({"name": p["name"], "state": p["state"], "last_seen": row["last_seen"], "problems": (p.get("problems") or {}).get("count", 0), "devices": (p.get("devices") or {}) if isinstance(p.get("devices"), dict) else p.get("devices")})
    return {"sites": sites}


def t_smart_home(conn, args, now=None) -> dict:
    focus = args.get("focus")
    rows = conn.execute("SELECT name, area, available, battery, battery_low, update_available, unavailable_since FROM inventory_devices ORDER BY name COLLATE NOCASE").fetchall()
    if not rows:
        return {"configured": False}
    return {"configured": True, "focus": focus, "devices": len(rows), "unavailable": [{"name": r["name"], "area": r["area"], "since": r["unavailable_since"]} for r in rows if not r["available"]][:LIMIT],
            "low_battery": [{"name": r["name"], "area": r["area"], "battery_pct": r["battery"]} for r in rows if r["battery_low"]][:LIMIT],
            "lowest_batteries": sorted([{"name": r["name"], "battery_pct": r["battery"]} for r in rows if r["battery"] is not None], key=lambda x: x["battery_pct"])[:6],
            "updates_available": [r["name"] for r in rows if r["update_available"]][:LIMIT]}


def t_security(conn, args, now=None) -> dict:
    from app import baselines

    days = _days(args.get("days"), 7)
    since = _since(days, now)
    kinds = ("dhcp_rogue", "gateway_changed", "login_failed", "port_unexpected", "port_opened", "device_new", "ip_reused")
    counts = {r["kind"]: r["n"] for r in conn.execute(f"SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? AND kind IN ({','.join('?' * len(kinds))}) GROUP BY kind", (since, *kinds))}
    drift = {i: d for i, d in baselines.drift_counts(conn).items() if d["unexpected"] or d["missing"]}
    names = {r["id"]: _name(r) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    return {"days": days, "events": counts, "untrusted_devices": conn.execute("SELECT COUNT(*) FROM devices WHERE trusted = 0").fetchone()[0],
            "unknown_dhcp_servers": [r["ip"] for r in conn.execute("SELECT ip FROM dhcp_servers WHERE trusted = 0")],
            "port_changes_from_baseline": [{"device": names.get(i), **d} for i, d in list(drift.items())[:LIMIT]],
            "recent_failed_logins": [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'login_failed' AND ts >= ? ORDER BY id DESC LIMIT 5", (since,))]}


def t_audit(conn, args, now=None) -> dict:
    days = _days(args.get("days"), 7)
    rows = conn.execute("SELECT ts, user, action FROM audit_log WHERE ts >= ? AND status < 400 AND method != 'GET' AND path NOT LIKE '/api/login%' AND path NOT LIKE '/api/logout%' AND path NOT LIKE '/api/insights/ask%' AND path NOT LIKE '/api/insights/model-check%' ORDER BY id DESC LIMIT 25", (_since(days, now),)).fetchall()
    return {"days": days, "changes": [{"at": r["ts"], "who": r["user"] or "unknown", "what": (r["action"] or "")[:120]} for r in rows]}


def t_connections(conn, args, now=None) -> dict:
    from app.hierarchy import ancestors, device_name, load_hierarchy

    needle = str(args.get("device") or args.get("name") or "").strip().lower()
    devices, tree = load_hierarchy(conn)
    row = next((d for d in devices.values() if needle and (needle in device_name(d).lower() or needle == (d.get("primary_ip") or ""))), None)
    if row is None:
        return {"error": f"no device matches {needle!r}"}
    children = [i for i, p in tree.items() if p.parent_id == row["id"]]
    below = set(children)
    frontier = list(children)
    while frontier:
        nxt = [i for i, p in tree.items() if p.parent_id in frontier and i not in below]
        below.update(nxt)
        frontier = nxt
    path = [device_name(devices[i]) for i in ancestors(tree, row["id"]) if i in devices]
    return {"device": device_name(row), "plugged_into": path[0] if path else None, "path_to_the_top": path, "directly_connected": [device_name(devices[i]) for i in children if i in devices][:30],
            "directly_connected_count": len(children), "everything_below_count": len(below), "offline_below": [device_name(devices[i]) for i in below if i in devices and not devices[i]["online"]][:12]}


def t_wifi(conn, args, now=None) -> dict:
    rows = conn.execute("SELECT s.device_id, s.rssi, s.band, s.node, s.ts FROM wifi_samples s JOIN (SELECT device_id, MAX(id) AS m FROM wifi_samples WHERE ts >= ? GROUP BY device_id) x ON x.m = s.id WHERE s.rssi IS NOT NULL ORDER BY s.rssi LIMIT 40",
                        (_since(1, now),)).fetchall()
    names = {r["id"]: _name(r) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    return {"clients_seen_in_24h": len(rows), "weakest": [{"device": names.get(r["device_id"]), "signal_dbm": r["rssi"], "band": r["band"], "access_point": r["node"]} for r in rows[:10]],
            "strongest": [{"device": names.get(r["device_id"]), "signal_dbm": r["rssi"]} for r in rows[-3:]][::-1]}


def t_maintenance(conn, args, now=None) -> dict:
    from app import maintenance, snooze

    t = now or datetime.now(timezone.utc)
    out = []
    for w in maintenance.load_windows(conn):
        start = maintenance.next_start(w, t)
        out.append({"name": w.get("name"), "enabled": w.get("enabled", True), "active_now": maintenance.is_active(w, t), "schedule": maintenance.describe_schedule(w), "next_start": start.strftime(STAMP) if start else None})
    return {"windows": out[:12], "snoozed_alerts": len(snooze.active(conn, t))}


def _update_info(conn, now=None) -> dict:
    """What Netlens knows about newer versions, and how far that can be trusted: the check can be switched off, and an old answer says nothing about today."""
    from app import updates

    up = updates.status(conn)
    t = now or datetime.now(timezone.utc)
    checked = None
    try:
        checked = datetime.strptime(up["checked"], STAMP).replace(tzinfo=timezone.utc) if up.get("checked") else None
    except ValueError:
        pass
    fresh = bool(up["enabled"] and checked and (t - checked) < timedelta(days=3))
    return {"update_checking_is_on": up["enabled"], "last_checked": up.get("checked"), "latest_known": up.get("latest"), "current": up["current"],
            "update_available": (bool(up["available"]) if fresh else None), "answer_is_current": fresh}


def t_system(conn, args, now=None) -> dict:
    from app import licence, updates
    from app.plugins.registry import discover
    from app.plugins.service import get_state
    from app.version import VERSION

    scans = conn.execute("SELECT kind, status, started, finished, hosts_found FROM scans ORDER BY id DESC LIMIT 3").fetchall()
    data_dir = conn.execute("PRAGMA database_list").fetchone()[2]
    plugins = []
    try:
        from pathlib import Path

        for p in discover(Path(data_dir).parent).values():
            if p.manifest:
                st = get_state(conn, p)
                plugins.append({"name": p.name, "enabled": st["enabled"], "version": p.manifest["version"]})
    except Exception:  # noqa: BLE001 - plugins are optional
        pass
    return {"netlens_version": VERSION, "update": _update_info(conn, now), "edition": licence.status(conn)["name"], "last_scans": [dict(s) for s in scans],
            "plugins": plugins[:30], "monitored_hosts": conn.execute("SELECT COUNT(*) FROM host_monitors WHERE enabled = 1").fetchone()[0], "service_checks": conn.execute("SELECT COUNT(*) FROM service_checks WHERE enabled = 1").fetchone()[0]}


def t_updates(conn, args, now=None) -> dict:
    from app import updates

    rows = conn.execute("SELECT DISTINCT detail FROM events WHERE kind = 'guest_update_available' AND ts >= ? ORDER BY id DESC LIMIT 15", (_since(30, now),)).fetchall()
    smart = [r["name"] for r in conn.execute("SELECT name FROM inventory_devices WHERE update_available = 1 LIMIT 15")]
    return {"guest_updates": [r["detail"] for r in rows], "smart_home_updates": smart, "netlens_update": _update_info(conn, now)}


def t_changes(conn, args, now=None) -> dict:
    from app import changes

    period = {1: "24h", 7: "7d", 30: "30d"}.get(_days(args.get("days"), 1) if _days(args.get("days"), 1) in (1, 7, 30) else 7, "24h")
    t = changes.timeline(conn, period, include_audit=True, limit=40, now=now)
    return {"period": period, "counts": t["counts"], "latest": [{"at": i["ts"], "what": i["text"][:130], "who": i["who"], "category": i["category"]} for i in t["items"][:15]]}


def t_ipv6(conn, args, now=None) -> dict:
    rows = conn.execute("SELECT COUNT(DISTINCT device_id) AS n FROM device_ipv6").fetchone()
    sample = conn.execute("SELECT COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, COUNT(*) AS n FROM device_ipv6 v JOIN devices d ON d.id = v.device_id GROUP BY v.device_id ORDER BY n DESC LIMIT 10").fetchall()
    return {"devices_with_ipv6": rows["n"], "examples": [{"name": r["name"], "addresses": r["n"]} for r in sample]}


# ----------------------------------------------------------------------------- the sentences
def _lines(items, fmt) -> str:
    return "\n".join(fmt(i) for i in items)


def r_search_devices(r: dict) -> str:
    if not r["count"]:
        return "No device matches" + (f" ({', '.join(f'{k}: {v}' for k, v in r['filters'].items())})." if r["filters"] else ".")
    head = f"{r['count']} device{'s' if r['count'] != 1 else ''}" + (f" ({', '.join(f'{k}: {v}' for k, v in r['filters'].items())})" if r["filters"] else "") + ":"
    return head + "\n" + _lines(r["devices"], lambda d: f"{d['name']} — {d['type'] or 'unknown type'}{', ' + d['vendor'] if d['vendor'] else ''}, {'online' if d['online'] else 'offline'}") + (f"\n…and {r['count'] - 20} more." if r["count"] > 20 else "")


def r_counts(r: dict) -> str:
    return f"{r['total']} devices, {r['online']} online. By {r['by']}:\n" + _lines(r["groups"], lambda g: f"{g['name']}: {g['devices']} ({g['online']} online)")


def r_ports(r: dict) -> str:
    if r.get("error"):
        return r["error"]
    if "open_ports" in r:
        return (f"{r['device']} has these open ports: " + ", ".join(f"{p['port']}/{p['proto']}" + (f" ({p['service']})" if p["service"] else "") for p in r["open_ports"]) + ".") if r["open_ports"] else f"{r['device']} has no open ports on record."
    what = f"port {r['port']}" if r.get("port") else f"the service {r.get('service')}"
    return (f"{r['count']} device(s) have {what} open:\n" + _lines(r["devices"], lambda d: f"{d['name']} ({d['type'] or 'unknown'}, {'online' if d['online'] else 'offline'})")) if r["count"] else f"No device has {what} open."


def r_guests(r: dict) -> str:
    total = sum(r["all_by_status"].values())
    if not total:
        return "No virtual machines or containers are known (install a hypervisor plugin such as Proxmox, Docker or Hyper-V)."
    head = f"{total} guests: " + ", ".join(f"{n} {s}" for s, n in sorted(r["all_by_status"].items(), key=lambda x: -x[1])) + "."
    if not r["guests"]:
        return head + " None match your question."
    return head + "\n" + _lines(r["guests"], lambda g: f"{g['name']} ({g['kind']} on {g['host'] or g['plugin']}): {g['status']}" + (f", {g['restarts']} restarts" if g.get("restarts") else "") + (f", health {g['health']}" if g.get("health") else ""))


def r_backups(r: dict) -> str:
    if not r["configured"]:
        return "No backup plugin is connected yet (Settings → Integrations, for example Proxmox Backup Server)."
    s = r["summary"]
    lines = [f"{s['protected']} of {s['guests']} virtual machines and containers have a backup; {s['unprotected']} have none. {s['failed']} backup(s) failed, {s['late']} are late, {s['stores_at_risk']} backup store(s) are at risk."]
    if r["failing_or_late"]:
        lines.append("Needs a look: " + "; ".join(f"{b['name']} ({'failed' if b['state'] == 'failed' else 'late'})" for b in r["failing_or_late"]) + ".")
    if r["unprotected_guests"]:
        lines.append("Without a backup: " + ", ".join(r["unprotected_guests"]) + ".")
    if s["problems"]:
        lines.append(f"The backup server has recorded {s['problems']} problem(s) (failed or warning tasks); see the Backups page.")
    if r["newest_backup"]:
        lines.append(f"Newest backup: {r['newest_backup'][:16].replace('T', ' ')} UTC.")
    return "\n".join(lines)


def r_certificates(r: dict) -> str:
    if not r["certificates"]:
        return "No certificate expiry is monitored (add an HTTPS service check)."
    return f"{r['checked']} certificate(s) watched, soonest to expire first:\n" + _lines(r["certificates"][:8], lambda c: f"{c['name']}: {c['days_left']} days left")


def r_speedtest(r: dict) -> str:
    if not r["tests"]:
        return f"No speed tests in the last {r['days']} days."
    a, last = r["average"], r["latest"]
    return (f"{r['tests']} tests in the last {r['days']} days. Average: {a['down_mbps']} Mbit/s down, {a['up_mbps']} up, {a['latency_ms']} ms latency. Latest ({last['at'][:16].replace('T', ' ')} UTC): {last['down_mbps']} down, {last['up_mbps']} up. "
            f"Slowest download {r['slowest_download']['mbps']} Mbit/s, fastest {r['fastest_download']['mbps']}.")


def r_network_services(r: dict) -> str:
    lines = []
    for d in r["dhcp_servers"]:
        lines.append(f"DHCP server {d['server']}: {'trusted' if d['trusted'] else 'NOT marked trusted'}, router {d['router'] or '?'}, DNS {', '.join(d['dns']) or '?'}")
    lines.append("DNS registration: " + (", ".join(f"{n} {s}" for s, n in r["dns_registration"].items()) if r["dns_registration"] else "not used") + f"; {r['dns_records_written_by_netlens']} record(s) written by Netlens.")
    return "\n".join(lines)


def r_remote_sites(r: dict) -> str:
    return _lines(r["sites"], lambda s: f"{s['name']}: {s['state']}, {s['problems']} problem(s), last report {(s['last_seen'] or 'never')[:16].replace('T', ' ')}") if r["sites"] else "No remote sites are connected."


def r_smart_home(r: dict) -> str:
    if not r["configured"]:
        return "No smart-home hub is connected (install the Home Assistant plugin)."
    avail = f"{len(r['unavailable'])} of {r['devices']} smart-home devices are unavailable: " + ", ".join(d["name"] for d in r["unavailable"]) + "." if r["unavailable"] else f"All {r['devices']} smart-home devices are available."
    battery = "Low batteries: " + ", ".join(f"{d['name']} ({d['battery_pct']}%)" for d in r["low_battery"]) + "." if r["low_battery"] else "No battery is low." + (" Lowest: " + ", ".join(f"{d['name']} {d['battery_pct']}%" for d in r["lowest_batteries"][:3]) + "." if r["lowest_batteries"] else "")
    lines = [battery, avail] if r.get("focus") == "battery" else [avail, battery]
    if r["updates_available"]:
        lines.append("Updates available for: " + ", ".join(r["updates_available"]) + ".")
    return "\n".join(lines)


def r_security(r: dict) -> str:
    ev = r["events"]
    lines = [f"Last {r['days']} days: " + (", ".join(f"{n}× {k.replace('_', ' ')}" for k, n in ev.items()) if ev else "no security-related events") + "."]
    lines.append(f"{r['untrusted_devices']} device(s) are not marked as trusted yet." + (f" Unknown DHCP server(s): {', '.join(r['unknown_dhcp_servers'])}." if r["unknown_dhcp_servers"] else ""))
    if r["port_changes_from_baseline"]:
        lines.append("Ports differ from the accepted baseline on: " + "; ".join(f"{p['device']} ({p['unexpected']} new, {p['missing']} missing)" for p in r["port_changes_from_baseline"]) + ".")
    if r["recent_failed_logins"]:
        lines.append("Failed logins: " + " | ".join(r["recent_failed_logins"][:3]))
    return "\n".join(lines)


def r_audit(r: dict) -> str:
    return _lines(r["changes"][:12], lambda c: f"{c['at'][:16].replace('T', ' ')} {c['who']}: {c['what']}") if r["changes"] else f"No changes were made in the last {r['days']} days."


def r_connections(r: dict) -> str:
    if r.get("error"):
        return r["error"]
    parts = [f"{r['device']} is plugged into {r['plugged_into']}." if r["plugged_into"] else f"{r['device']} is at the top of the network (nothing above it is known)."]
    if r["directly_connected_count"]:
        parts.append(f"{r['directly_connected_count']} device(s) are connected directly ({', '.join(r['directly_connected'][:8])}{'…' if r['directly_connected_count'] > 8 else ''}); {r['everything_below_count']} depend on it in total.")
        if r["offline_below"]:
            parts.append("Offline below it: " + ", ".join(r["offline_below"]) + ".")
    return " ".join(parts)


def r_wifi(r: dict) -> str:
    if not r["weakest"]:
        return "No Wi-Fi signal readings in the last 24 hours (needs a Wi-Fi source such as the Omada plugin)."
    return f"{r['clients_seen_in_24h']} Wi-Fi clients seen. Weakest signal:\n" + _lines(r["weakest"][:6], lambda w: f"{w['device']}: {w['signal_dbm']} dBm ({w['band'] or '?'} via {w['access_point'] or '?'})")


def r_maintenance(r: dict) -> str:
    lines = [f"{w['name']}: {'ACTIVE NOW' if w['active_now'] else 'not active'}, {w['schedule']}" + (f", next start {w['next_start'][:16].replace('T', ' ')} UTC" if w["next_start"] else "") for w in r["windows"]]
    return "\n".join(lines or ["No maintenance windows are set."]) + f"\n{r['snoozed_alerts']} alert(s) are snoozed."


def _update_sentence(up: dict) -> str:
    if not up["update_checking_is_on"]:
        return ("Checking for updates is switched off (Settings → About), so Netlens cannot say whether a newer version exists"
                + (f"; the last check, on {up['last_checked'][:10]}, found {up['latest_known']}." if up.get("last_checked") else "."))
    if not up["answer_is_current"]:
        return "Netlens has not been able to check for a newer version recently" + (f" (last answer {up['last_checked'][:10]}: {up['latest_known']})." if up.get("last_checked") else ".")
    return f"A newer version, {up['latest_known']}, is available." if up["update_available"] else f"This is the newest published version (checked {up['last_checked'][:10]})."


def r_system(r: dict) -> str:
    up = r["update"]
    lines = [f"Netlens {r['netlens_version']} ({r['edition']}). " + _update_sentence(up)]
    if r["last_scans"]:
        s = r["last_scans"][0]
        lines.append(f"Last scan: {s['kind']} {s['status']} at {s['started'][:16].replace('T', ' ')} UTC, {s['hosts_found']} hosts.")
    on = [p for p in r["plugins"] if p["enabled"]]
    lines.append(f"{len(on)} plugin(s) on of {len(r['plugins'])} installed: " + ", ".join(f"{p['name']} {p['version']}" for p in on[:10]) + f". {r['monitored_hosts']} host monitor(s), {r['service_checks']} service check(s).")
    return "\n".join(lines)


def r_updates(r: dict) -> str:
    lines = []
    if r["guest_updates"]:
        lines.append("Updates available for guests:\n" + "\n".join(r["guest_updates"][:8]))
    if r["smart_home_updates"]:
        lines.append("Smart-home updates: " + ", ".join(r["smart_home_updates"]) + ".")
    lines.append("Netlens itself: " + _update_sentence(r["netlens_update"]))
    return "\n".join(lines)


def r_changes(r: dict) -> str:
    head = f"Over the last {r['period']}: " + (", ".join(f"{n} {c}" for c, n in r["counts"].items()) if r["counts"] else "nothing changed") + "."
    return head + ("\n" + _lines(r["latest"][:10], lambda c: f"{c['at'][:16].replace('T', ' ')} [{c['category']}] {c['what']}" + (f" ({c['who']})" if c["who"] else "")) if r["latest"] else "")


def r_ipv6(r: dict) -> str:
    return f"{r['devices_with_ipv6']} device(s) have an IPv6 address on record." + (" Most: " + ", ".join(f"{e['name']} ({e['addresses']})" for e in r["examples"][:5]) + "." if r["examples"] else " (IPv6 discovery is optional: Settings → IPv6.)")


STOP = set("which what whats who whom how does did the this that these those have has had are was were not with from for and any all can could would will about into over under open ports port "
           "connected plugged behind depends depend upstream downstream uplink attached device devices machine machines show list tell give many much more most least there their they them "
           "online offline down running used uses use using wifi network netlens".split())


def find_named(q: str, names: list[str]) -> str | None:
    """The device a question is about: its full name in the question, or a word of the question that is (part of) the first part of a name ("nas" for truenas.home.example)."""
    low = q.lower()
    for name in sorted(names, key=len, reverse=True):
        if len(name) > 2 and re.search(r"(?<![\w.-])" + re.escape(name.lower()) + r"(?![\w-])", low):
            return name
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", low) if w not in STOP]
    labels = {n: re.split(r"[.]", n.lower())[0] for n in names if len(n) > 2}
    for w in words:                                   # an exact label first, then a label that contains the word
        for name, label in labels.items():
            if w == label or w == label.rstrip("0123456789"):
                return name
    for w in words:
        w = w.rstrip("s") if len(w) > 4 else w
        hits = [n for n, label in labels.items() if w in label]
        if len(hits) == 1:
            return hits[0]
    return None


# ----------------------------------------------------------------------------- the words that pick a tool
def _vendors(conn) -> list[str]:
    return [v for v in {(r[0] or "").split(" ")[0].lower().strip(",") for r in conn.execute("SELECT DISTINCT vendor FROM devices WHERE vendor IS NOT NULL")} if len(v) > 2]


def _days_in(q: str, default: int) -> int:
    m = re.search(r"(\d+)\s*(day|week|month)", q)
    if m:
        return max(1, min(30, int(m.group(1)) * {"day": 1, "week": 7, "month": 30}[m.group(2)]))
    return 1 if re.search(r"today|24 ?h|yesterday|last night|tonight", q) else 30 if "month" in q else 7 if "week" in q else default


def route(conn, q: str, names: list[str]) -> tuple[str, dict] | None:
    """(tool, args) for the new kinds of question, or None when the question is not one of them."""
    online = False if re.search(r"offline|\bdown\b|unreachable|not responding", q) else True if re.search(r"\bonline\b|\bup\b|reachable|responding", q) else None
    # one device and what it is connected to
    if re.search(r"connected to|plugged|behind|depends? on|upstream|downstream|uplink|attached|what is on", q):
        name = find_named(q, names)
        if name:
            return "connections", {"device": name}
    # ports and services on devices
    m = re.search(r"\bport (\d{1,5})\b", q)
    if m:
        return "ports", {"port": int(m.group(1))}
    if re.search(r"open|listening|exposed|expose|running|use|uses|has", q):
        for word, port in SERVICE_PORTS.items():
            if re.search(rf"\b{word}\b", q) and re.search(r"which|what|who|list|how many|any|devices|machines", q):
                return "ports", {"port": port, "service": word}
    if re.search(r"which ports|what ports|open ports|listening", q):
        name = find_named(q, names)
        if name:
            return "ports", {"device": name}
    if re.search(r"untrusted|not trusted|unknown devices?|strangers?|not (yet )?marked", q) and re.search(r"which|list|show|what|who", q):
        return "search_devices", {"untrusted": True}
    q_types = re.sub(r"\b(dhcp|dns|ntp|proxy|web|mail|name|backup|syslog|rogue)\s+servers?\b", " ", q)       # "a DHCP server" is not a device of the kind "server"
    typed = next((t for t in ask.TYPE_WORDS if re.search(rf"\b{t}(e?s)?\b", q_types)), None)
    own = find_named(q, names)
    if typed and own and own.lower().split(".")[0] == typed:        # a device that is called "printer": the question is about it
        typed = None
    if typed and re.search(r"online|offline|\bdown\b|\bup\b|which|list|show|how many|any |are there|do i have", q) and not re.search(r"slowest|fastest|highest|lowest|most |least |worst|best|reliab|unreliab|response|latency|availab", q):
        return "search_devices", {"type": typed, "online": online}
    rules = [
        ("backups", r"backup|back-up"), ("certificates", r"certificat|\bcerts?\b|\bssl\b|\btls\b|expir"), ("speedtest", r"speed ?test|internet speed|bandwidth|mbit|mbps|download speed|upload speed|how fast is (my|the) internet"),
        ("remote_sites", r"remote sites?|branch|other (site|location)|probe"), ("wifi", r"wi-?fi|wireless|\bsignal\b|rssi"), ("maintenance", r"maintenance|snooze|planned (downtime|work)|scheduled downtime"),
        ("audit", r"who (changed|did|edited|deleted|added)|audit|changed (the )?settings|logged in|who logged"), ("ipv6", r"ipv6"),
        ("security", r"secur|rogue|intrud|suspicious|untrusted|not trusted|failed logins?|unexpected port|break-?in|attack|exposed to"), ("network_services", r"dhcp|dns record|dns registration|gateway|name servers?"), ("updates", r"updates? (are |is )?(available|waiting|pending)|outdated|out of date|newer (image|version) of|need updating"),
        ("smart_home", r"smart ?home|home assistant|zigbee|thermostat|\bsensors?\b|shelly|battery|batteries"),
        ("system", r"which version|netlens version|what version|plugins?|licen[cs]e|edition|last scan|when did .* scan|scanning"), ("changes", r"what changed|configuration|settings changed|config"),
    ]
    if re.search(r"\bups\b", q) and re.search(r"battery|batteries", q):
        rules = [r for r in rules if r[0] != "smart_home"]
    if re.search(r"guests?\b|virtual machines?|\bvms?\b|containers?|\blxc\b|docker|hypervisor|proxmox|restarting", q) and not re.search(r"backup", q):
        status = next((s for s, p in (("stopped", r"stopped|not running|down|off"), ("running", r"running|started|up\b"), ("restarting", r"restart"), ("paused", r"paused")) if re.search(p, q)), "")
        if re.search(r"unhealthy", q):
            return "guests", {"status": "unhealthy"}
        families = [k for k, p in (("lxc", r"\blxc\b"), ("container", r"container|docker"), ("qemu", r"\bvms?\b|virtual machine")) if re.search(p, q)]
        return "guests", {"status": status, "kind": families[0] if len(families) == 1 else ""}
    for tool, pattern in rules:
        if re.search(pattern, q):
            if tool in ("speedtest", "security", "audit", "changes"):
                return tool, {"days": _days_in(q, 7 if tool != "speedtest" else 30)}
            return tool, ({"focus": "battery"} if tool == "smart_home" and re.search(r"batter", q) else {})
    # counting and listing devices by a property
    trigger = re.search(r"(?:how many|which|list|show|any|are there)\s+(.*)", q)
    if trigger and re.search(r"how many|which|list|show|are there", q):
        noun = next((w for w in re.findall(r"[a-z][a-z0-9_-]{2,}", trigger.group(1)) if w not in STOP and w not in ("devices", "machines", "hosts", "computers", "things")), None)
        word = noun.rstrip("s") if noun and len(noun) > 4 else noun
        if word and any(word in n.lower() for n in names) and not re.search(r"per (type|vendor)|by (type|vendor|os|group)", q):
            return "search_devices", {"text": word, "online": online}
    if re.search(r"how many|number of|count|breakdown|distribution|per (type|vendor|manufacturer)|by (type|vendor|manufacturer|os|group)|what kinds? of", q):
        by = "vendor" if re.search(r"vendor|manufacturer|brand", q) else "os" if re.search(r"\bos\b|operating system|windows|linux|android|ios", q) else "group" if "group" in q else "type"
        if not re.search(r"windows|linux|android|ios\b|macos|openwrt", q) or by != "os" or re.search(r"operating system|\bos\b|by os", q):
            return "counts", {"by": by}
    if re.search(r"windows|linux|android|\bios\b|macos|mac os|openwrt|freebsd|ubuntu|debian", q) and re.search(r"which|what|list|how many|devices|machines|running|any", q):
        os_word = re.search(r"windows|linux|android|\bios\b|macos|mac os|openwrt|freebsd|ubuntu|debian", q).group(0)
        return "search_devices", {"os": os_word, "online": online}
    vendors = _vendors(conn)
    hit = next((v for v in vendors if re.search(rf"\b{re.escape(v)}\b", q)), None)
    if hit:
        return "search_devices", {"vendor": hit, "online": online}
    if re.search(r"untrusted|not trusted|unknown devices?|strangers?", q):
        return "search_devices", {"untrusted": True}
    if re.search(r"tagged|tag ", q):
        tag = re.search(r"tag(?:ged)? ?(?:with |as )?[\"']?(\w+)", q)
        if tag:
            return "search_devices", {"tag": tag.group(1)}
    return None


RENDERERS = {"search_devices": r_search_devices, "counts": r_counts, "ports": r_ports, "guests": r_guests, "backups": r_backups, "certificates": r_certificates, "speedtest": r_speedtest,
             "network_services": r_network_services, "remote_sites": r_remote_sites, "smart_home": r_smart_home, "security": r_security, "audit": r_audit, "connections": r_connections,
             "wifi": r_wifi, "maintenance": r_maintenance, "system": r_system, "updates": r_updates, "changes": r_changes, "ipv6": r_ipv6}

TOOLS = {
    "search_devices": (t_search_devices, "find devices by a property and count them. args (all optional): type (printer, camera, nas, switch ...), vendor (manufacturer word), os (windows, linux, android ...), online (true/false), port (number), service (name), group, tag, text (part of the name or address, for anything that is not a kind: iphone, raspberry ...), new_days, untrusted (true)"),
    "counts": (t_counts, "how many devices there are, split by type, vendor, os or group. args: by (type, vendor, os or group)"),
    "ports": (t_ports, "open network ports: which devices have a port or service open (args: port or service such as ssh, rdp, smb, http), or which ports one device has open (args: device)"),
    "guests": (t_guests, "virtual machines and containers of the hypervisor plugins (Proxmox, Docker, Hyper-V ...) with their state, restarts and health. args (optional): status (running, stopped, restarting, unhealthy), kind (qemu, lxc, container), text"),
    "backups": (t_backups, "backup status: guests with or without a backup, failed or late backups, backup stores filling up. args: none"),
    "certificates": (t_certificates, "TLS certificates that are watched and how many days they have left, soonest first. args: none"),
    "speedtest": (t_speedtest, "internet speed tests: latest, average, slowest and fastest. args: days (1-30)"),
    "network_services": (t_network_services, "DHCP servers on the network (and whether they are trusted), gateway and DNS record registration. args: none"),
    "remote_sites": (t_remote_sites, "the remote sites (other locations) that report to this Netlens and their state. args: none"),
    "smart_home": (t_smart_home, "smart-home devices of Home Assistant: unavailable ones, low batteries, updates. args: none"),
    "security": (t_security, "security-related findings: rogue DHCP, gateway changes, failed logins, unexpected open ports, devices not marked trusted. args: days (1-30)"),
    "audit": (t_audit, "who changed which settings in Netlens recently. args: days (1-30)"),
    "connections": (t_connections, "what one device is plugged into and which devices depend on it (the network hierarchy). args: device (name)"),
    "wifi": (t_wifi, "Wi-Fi signal strength of clients, weakest first. args: none"),
    "maintenance": (t_maintenance, "planned maintenance windows and snoozed alerts. args: none"),
    "system": (t_system, "Netlens itself: version, whether a newer version exists (only trust it when update.answer_is_current is true), last scans, installed plugins, number of monitors. args: none"),
    "updates": (t_updates, "software updates that are waiting: containers and guests, smart-home devices, Netlens. args: none"),
    "changes": (t_changes, "what changed on the network and in the settings in a period, by category. args: days (1, 7 or 30)"),
    "ipv6": (t_ipv6, "devices that have IPv6 addresses. args: none"),
}

PRESETS = [
    {"id": "types", "text": "How many devices do I have, by type?", "tool": "counts", "args": {"by": "type"}},
    {"id": "windows", "text": "Which devices run Windows?", "tool": "search_devices", "args": {"os": "windows"}},
    {"id": "ssh", "text": "Which devices have SSH open?", "tool": "ports", "args": {"port": 22, "service": "ssh"}},
    {"id": "rdp", "text": "Which devices have remote desktop (RDP) open?", "tool": "ports", "args": {"port": 3389, "service": "rdp"}},
    {"id": "stopped", "text": "Which virtual machines or containers are stopped?", "tool": "guests", "args": {"status": "stopped"}},
    {"id": "backups", "text": "Are my backups healthy?", "tool": "backups", "args": {}},
    {"id": "certs", "text": "Which certificates expire soonest?", "tool": "certificates", "args": {}},
    {"id": "speed", "text": "How fast is my internet?", "tool": "speedtest", "args": {"days": 30}},
    {"id": "security", "text": "Is there anything suspicious on the network?", "tool": "security", "args": {"days": 7}},
    {"id": "batteries", "text": "Which smart-home batteries are low?", "tool": "smart_home", "args": {}},
    {"id": "ram", "text": "Which machines are low on RAM?", "tool": "health", "args": {"metric": "memory"}},
    {"id": "wifi", "text": "Which devices have a weak Wi-Fi signal?", "tool": "wifi", "args": {}},
    {"id": "who", "text": "Who changed settings this week?", "tool": "audit", "args": {"days": 7}},
    {"id": "version", "text": "Which version of Netlens is this and is there an update?", "tool": "system", "args": {}},
]


def register() -> None:
    ask.TOOLS.update(TOOLS)
    ask.RENDERERS.update(RENDERERS)
    ask.PRESETS.extend(p for p in PRESETS if p["id"] not in {x["id"] for x in ask.PRESETS})
