"""What a storage plugin (NetApp, Dell, Pure, Ceph ...) reports, tied to the devices Netlens knows.

A storage *system* is matched to a device by its IP, a *controller* by its IP or MAC, and the hosts that use a *volume* (NFS clients, iSCSI
initiators ...) by their IP. Events are only written when something *changes* (a system, pool or disk becomes unhealthy, a pool fills up, a new
critical alert, a problem is over), never on every sync; the first sync after switching a plugin on is not news.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.db import add_event

STAMP = "%Y-%m-%dT%H:%M:%SZ"
FULL_WARN, FULL_CRITICAL = 85.0, 95.0          # percent of a pool that is used
RANK = {"ok": 0, "unknown": 0, "warning": 1, "critical": 2}
TABLES = ("storage_systems", "storage_controllers", "storage_pools", "storage_volumes", "storage_disks", "storage_alerts")


def _percent(used: int | None, total: int | None) -> float | None:
    return round(used / total * 100, 1) if total and used is not None else None


def pool_level(used: int | None, total: int | None) -> str:
    p = _percent(used, total)
    return "ok" if p is None else "critical" if p >= FULL_CRITICAL else "warning" if p >= FULL_WARN else "ok"


def _disk_health(state: str) -> str:
    return "critical" if state == "failed" else "warning" if state == "degraded" else "ok"


def apply_storage(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict | None = None, now: datetime | None = None) -> dict:
    """Store a storage plugin's output, match it to devices and write the events for what changed. Returns the summary."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime(STAMP)
    first = conn.execute("SELECT 1 FROM storage_systems WHERE plugin_id = ? LIMIT 1", (plugin_id,)).fetchone() is None
    before = {
        "system": {r["system_id"]: r["health"] for r in conn.execute("SELECT system_id, health FROM storage_systems WHERE plugin_id = ?", (plugin_id,))},
        "pool": {r["pool_id"]: (r["health"], r["level"]) for r in conn.execute("SELECT pool_id, health, level FROM storage_pools WHERE plugin_id = ?", (plugin_id,))},
        "disk": {r["disk_id"]: r["state"] for r in conn.execute("SELECT disk_id, state FROM storage_disks WHERE plugin_id = ?", (plugin_id,))},
        "alert": {r["alert_id"] for r in conn.execute("SELECT alert_id FROM storage_alerts WHERE plugin_id = ?", (plugin_id,))},
    }
    for table in TABLES:
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    by_ip = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices WHERE primary_ip IS NOT NULL")}
    by_mac = {r["mac"].lower(): r["id"] for r in conn.execute("SELECT id, mac FROM devices WHERE mac IS NOT NULL")}
    names = {s["id"]: s["name"] for s in data["systems"]}
    events = 0

    def event(kind: str, text: str, subject: str, device_id: int | None = None) -> None:
        nonlocal events
        if not first:
            add_event(conn, kind, text, device_id=device_id, now=stamp, subject=subject)
            events += 1

    system_device = {}
    for s in data["systems"]:
        device_id = by_ip.get(s["ip"])
        system_device[s["id"]] = device_id
        conn.execute("INSERT INTO storage_systems (plugin_id, system_id, name, ip, vendor, model, version, serial, online, health, device_id, warnings, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, s["id"], s["name"], s["ip"], s["vendor"], s["model"], s["version"], s["serial"], int(s["online"]), s["health"], device_id, json.dumps(s["warnings"]), stamp))
        old = before["system"].get(s["id"])
        if old is not None:
            health = "critical" if not s["online"] else s["health"]
            if RANK[health] > RANK.get(old, 0):
                event("storage_degraded", f"{s['name']}: {'not reachable' if not s['online'] else 'health is ' + health}", f"storage:{plugin_id}:{s['id']}", device_id)
            elif RANK[health] == 0 and RANK.get(old, 0) > 0:
                event("storage_recovered", f"{s['name']}: healthy again", f"storage:{plugin_id}:{s['id']}", device_id)
    for c in data["controllers"]:
        device_id = by_ip.get(c["ip"]) or by_mac.get(c["mac"])
        conn.execute("INSERT INTO storage_controllers (plugin_id, controller_id, system_id, name, ip, mac, online, health, device_id, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, c["id"], c["system_id"], c["name"], c["ip"], c["mac"], int(c["online"]), c["health"], device_id, stamp))
    for p in data["pools"]:
        level = pool_level(p["used"], p["total"])
        conn.execute("INSERT INTO storage_pools (plugin_id, pool_id, system_id, name, total, used, avail, health, raid, level, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, p["id"], p["system_id"], p["name"], p["total"], p["used"], p["avail"], p["health"], p["raid"], level, stamp))
        old = before["pool"].get(p["id"])
        if old is None:
            continue
        who, device_id, subject = f"Pool {p['name']} on {names.get(p['system_id'], p['system_id'])}", system_device.get(p["system_id"]), f"storagepool:{plugin_id}:{p['id']}"
        if RANK[p["health"]] > RANK.get(old[0], 0):
            event("storage_degraded", f"{who}: health is {p['health']}", subject, device_id)
        elif RANK[p["health"]] == 0 and RANK.get(old[0], 0) > 0:
            event("storage_recovered", f"{who}: healthy again", subject, device_id)
        if level != "ok" and level != old[1] and (old[1] == "ok" or level == "critical"):
            event("capacity_critical" if level == "critical" else "capacity_warning", f"{who} is {_percent(p['used'], p['total'])}% full", subject, device_id)
    for v in data["volumes"]:
        clients = [{"ip": ip, "device_id": by_ip.get(ip)} for ip in v["clients"]]
        conn.execute("INSERT INTO storage_volumes (plugin_id, volume_id, system_id, pool_id, name, kind, protocol, size, used, health, clients, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, v["id"], v["system_id"], v["pool_id"], v["name"], v["kind"], v["protocol"], v["size"], v["used"], v["health"], json.dumps(clients), stamp))
    failed = 0
    for d in data["disks"]:
        conn.execute("INSERT INTO storage_disks (plugin_id, disk_id, system_id, name, slot, model, size, state, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, d["id"], d["system_id"], d["name"], d["slot"], d["model"], d["size"], d["state"], stamp))
        failed += 1 if d["state"] == "failed" else 0
        old = before["disk"].get(d["id"])
        if old is None:
            continue
        who, device_id, subject = f"Disk {d['slot'] or d['name']} of {names.get(d['system_id'], d['system_id'])}", system_device.get(d["system_id"]), f"storagedisk:{plugin_id}:{d['id']}"
        if RANK[_disk_health(d["state"])] > RANK[_disk_health(old)]:
            event("storage_degraded", f"{who}: {d['state']}", subject, device_id)
        elif RANK[_disk_health(d["state"])] == 0 and RANK[_disk_health(old)] > 0:
            event("storage_recovered", f"{who}: healthy again", subject, device_id)
    for a in data["alerts"]:
        conn.execute("INSERT INTO storage_alerts (plugin_id, alert_id, system_id, severity, text, at) VALUES (?, ?, ?, ?, ?, ?)", (plugin_id, a["id"], a["system_id"], a["severity"], a["text"], a["at"]))
        if a["severity"] == "critical" and a["id"] not in before["alert"] and a["text"]:
            event("storage_degraded", f"{names.get(a['system_id'], a['system_id'])}: {a['text']}", f"storagealert:{plugin_id}:{a['id']}", system_device.get(a["system_id"]))
    conn.commit()
    return {"systems": len(data["systems"]), "controllers": len(data["controllers"]), "pools": len(data["pools"]), "volumes": len(data["volumes"]), "disks": len(data["disks"]),
            "failed_disks": failed, "alerts": len(data["alerts"]), "events": events}


def remove_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    for table in TABLES:
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    conn.commit()


# ----------------------------------------------------------------------------- for the API
def _device_names(conn: sqlite3.Connection) -> dict[int, str]:
    return {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    """Everything the Storage page shows."""
    devices = _device_names(conn)
    systems = [{"plugin_id": r["plugin_id"], "id": r["system_id"], "name": r["name"], "ip": r["ip"], "vendor": r["vendor"], "model": r["model"], "version": r["version"], "serial": r["serial"],
                "online": bool(r["online"]), "health": "critical" if not r["online"] else r["health"], "device_id": r["device_id"], "device": devices.get(r["device_id"]),
                "warnings": json.loads(r["warnings"] or "[]")} for r in conn.execute("SELECT * FROM storage_systems ORDER BY LOWER(name)")]
    controllers = [{"plugin_id": r["plugin_id"], "id": r["controller_id"], "system_id": r["system_id"], "name": r["name"], "ip": r["ip"], "mac": r["mac"], "online": bool(r["online"]),
                    "health": r["health"], "device_id": r["device_id"], "device": devices.get(r["device_id"])} for r in conn.execute("SELECT * FROM storage_controllers ORDER BY LOWER(name)")]
    pools = [{"plugin_id": r["plugin_id"], "id": r["pool_id"], "system_id": r["system_id"], "name": r["name"], "total": r["total"], "used": r["used"], "avail": r["avail"],
              "percent": _percent(r["used"], r["total"]), "health": r["health"], "raid": r["raid"], "level": r["level"]} for r in conn.execute("SELECT * FROM storage_pools ORDER BY LOWER(name)")]
    volumes = []
    for r in conn.execute("SELECT * FROM storage_volumes ORDER BY LOWER(name)"):
        clients = json.loads(r["clients"] or "[]")
        for c in clients:
            c["device"] = devices.get(c.get("device_id"))
        volumes.append({"plugin_id": r["plugin_id"], "id": r["volume_id"], "system_id": r["system_id"], "pool_id": r["pool_id"], "name": r["name"], "kind": r["kind"], "protocol": r["protocol"],
                        "size": r["size"], "used": r["used"], "percent": _percent(r["used"], r["size"]), "health": r["health"], "clients": clients})
    disks = [{"plugin_id": r["plugin_id"], "id": r["disk_id"], "system_id": r["system_id"], "name": r["name"], "slot": r["slot"], "model": r["model"], "size": r["size"], "state": r["state"]}
             for r in conn.execute("SELECT * FROM storage_disks ORDER BY system_id, slot, name")]
    alerts = [{"plugin_id": r["plugin_id"], "id": r["alert_id"], "system_id": r["system_id"], "severity": r["severity"], "text": r["text"], "at": r["at"]}
              for r in conn.execute("SELECT * FROM storage_alerts ORDER BY at DESC")]
    return {"systems": systems, "controllers": controllers, "pools": pools, "volumes": volumes, "disks": disks, "alerts": alerts, "summary": summary(conn)}


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """The few numbers of the dashboard and /metrics (cheap: counts only)."""
    one = lambda sql: conn.execute(sql).fetchone()[0]    # noqa: E731 - fixed statements, no user input
    systems = one("SELECT COUNT(*) FROM storage_systems")
    if not systems:
        return {"configured": False, "systems": 0, "unhealthy": 0, "pools": 0, "pools_filling": 0, "disks": 0, "failed_disks": 0, "alerts": 0, "volumes": 0}
    return {"configured": True, "systems": systems, "unhealthy": one("SELECT COUNT(*) FROM storage_systems WHERE online = 0 OR health IN ('warning', 'critical')"),
            "pools": one("SELECT COUNT(*) FROM storage_pools"), "pools_filling": one("SELECT COUNT(*) FROM storage_pools WHERE level != 'ok' OR health IN ('warning', 'critical')"),
            "disks": one("SELECT COUNT(*) FROM storage_disks"), "failed_disks": one("SELECT COUNT(*) FROM storage_disks WHERE state = 'failed'"),
            "alerts": one("SELECT COUNT(*) FROM storage_alerts"), "volumes": one("SELECT COUNT(*) FROM storage_volumes")}


def for_device(conn: sqlite3.Connection, device_id: int) -> dict | None:
    """What the storage plugins know about a device: the array or controller it is, and the volumes it uses (as an NFS/iSCSI client)."""
    system_ids = {(r["plugin_id"], r["system_id"]) for r in conn.execute("SELECT plugin_id, system_id FROM storage_systems WHERE device_id = ?", (device_id,))}
    system_ids |= {(r["plugin_id"], r["system_id"]) for r in conn.execute("SELECT plugin_id, system_id FROM storage_controllers WHERE device_id = ?", (device_id,))}
    mine = []
    for sys in conn.execute("SELECT * FROM storage_systems ORDER BY LOWER(name)"):
        if (sys["plugin_id"], sys["system_id"]) in system_ids:
            mine.append({"name": sys["name"], "vendor": sys["vendor"], "model": sys["model"], "version": sys["version"], "health": "critical" if not sys["online"] else sys["health"],
                         "pools": conn.execute("SELECT COUNT(*) FROM storage_pools WHERE plugin_id = ? AND system_id = ?", (sys["plugin_id"], sys["system_id"])).fetchone()[0],
                         "failed_disks": conn.execute("SELECT COUNT(*) FROM storage_disks WHERE plugin_id = ? AND system_id = ? AND state = 'failed'", (sys["plugin_id"], sys["system_id"])).fetchone()[0]})
    uses = []
    for v in conn.execute("SELECT v.*, s.name AS system_name FROM storage_volumes v LEFT JOIN storage_systems s ON s.plugin_id = v.plugin_id AND s.system_id = v.system_id WHERE v.clients != '[]'"):
        if any(c.get("device_id") == device_id for c in json.loads(v["clients"] or "[]")):
            uses.append({"volume": v["name"], "system": v["system_name"] or v["system_id"], "protocol": v["protocol"], "kind": v["kind"], "health": v["health"]})
    return {"systems": mine, "uses": uses} if mine or uses else None
