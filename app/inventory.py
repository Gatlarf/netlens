"""What a smart-home hub (kind "inventory": Home Assistant ...) knows about its devices.

The hub's devices are stored as reported. A device with a MAC address (or an address Netlens found on the network) is tied to the matching
device Netlens found by scanning, so its page can show manufacturer, model, area, firmware and battery. Devices that are not on the network
(Zigbee sensors, switches, Bluetooth devices) are listed on the Smart home page, with the device they are paired through. Events: a device that
becomes unavailable or comes back, and a battery that runs low.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.db import add_event

STAMP = "%Y-%m-%dT%H:%M:%SZ"


def apply_inventory(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict | None = None, now: datetime | None = None) -> dict:
    """Store the output, match devices to the network and write the events for what changed. Returns the summary."""
    stamp = (now or datetime.now(timezone.utc)).strftime(STAMP)
    before = {r["dev_id"]: dict(r) for r in conn.execute("SELECT * FROM inventory_devices WHERE plugin_id = ?", (plugin_id,))}
    conn.execute("DELETE FROM inventory_servers WHERE plugin_id = ?", (plugin_id,))
    conn.execute("DELETE FROM inventory_devices WHERE plugin_id = ?", (plugin_id,))
    by_mac = {r["mac"].lower(): r["id"] for r in conn.execute("SELECT id, mac FROM devices WHERE mac IS NOT NULL")}
    by_ip = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices WHERE primary_ip IS NOT NULL")}
    for s in data["servers"]:
        conn.execute("INSERT INTO inventory_servers (plugin_id, server_id, name, ip, version, online, warnings) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, s["id"], s["name"], s["ip"], s["version"], int(s["online"]), json.dumps(s["warnings"])))
    threshold = {}
    events = matched = gone = low = 0
    for d in data["devices"]:
        device_id = by_mac.get(d["mac"]) if d["mac"] else None
        if device_id is None and d["ip"]:
            device_id = by_ip.get(d["ip"])
        matched += 1 if device_id else 0
        old = before.get(d["id"])
        since = None if d["available"] else ((old or {}).get("unavailable_since") or stamp)
        conn.execute(
            """INSERT INTO inventory_devices (plugin_id, dev_id, server_id, name, manufacturer, model, area, sw, protocol, mac, ip, via_id, available, battery, battery_low,
                                              update_available, url, entities, device_id, unavailable_since)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_id, d["id"], d["server_id"], d["name"], d["manufacturer"], d["model"], d["area"], d["sw"], d["protocol"], d["mac"], d["ip"], d["via_id"], int(d["available"]),
             d["battery"], int(d["battery_low"]), int(d["update"]), d["url"], d["entities"], device_id, since))
        gone += 0 if d["available"] else 1
        low += 1 if d["battery_low"] else 0
        if old is None:
            continue                                              # the first sync after switching the plugin on is not news
        where = f" ({d['area']})" if d["area"] else ""
        subject = f"inventory:{plugin_id}:{d['id']}"
        if old["available"] and not d["available"]:
            add_event(conn, "inventory_unavailable", f"{d['name']}{where} is unavailable in Home Assistant" if plugin_id == "homeassistant" else f"{d['name']}{where} is unavailable",
                      device_id=device_id, now=stamp, subject=subject)
            events += 1
        elif not old["available"] and d["available"]:
            add_event(conn, "inventory_available", f"{d['name']}{where} is available again", device_id=device_id, now=stamp, subject=subject)
            events += 1
        if d["battery_low"] and not old["battery_low"]:
            level = f" ({d['battery']}%)" if d["battery"] is not None else ""
            add_event(conn, "inventory_battery_low", f"{d['name']}{where}: the battery is low{level}", device_id=device_id, now=stamp, subject=subject + ":battery")
            events += 1
    conn.commit()
    return {"servers": len(data["servers"]), "devices": len(data["devices"]), "matched": matched, "unavailable": gone, "battery_low": low, "events": events}


def remove_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    conn.execute("DELETE FROM inventory_servers WHERE plugin_id = ?", (plugin_id,))
    conn.execute("DELETE FROM inventory_devices WHERE plugin_id = ?", (plugin_id,))


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    """Everything the Smart home page shows."""
    names = {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    servers = [{"plugin_id": r["plugin_id"], "id": r["server_id"], "name": r["name"], "ip": r["ip"], "version": r["version"], "online": bool(r["online"]), "warnings": json.loads(r["warnings"] or "[]")}
               for r in conn.execute("SELECT * FROM inventory_servers ORDER BY LOWER(name)")]
    rows = conn.execute("SELECT * FROM inventory_devices ORDER BY LOWER(name)").fetchall()
    by_id = {(r["plugin_id"], r["dev_id"]): r["name"] for r in rows}
    devices = [{"plugin_id": r["plugin_id"], "id": r["dev_id"], "server_id": r["server_id"], "name": r["name"], "manufacturer": r["manufacturer"], "model": r["model"], "area": r["area"], "sw": r["sw"],
                "protocol": r["protocol"], "mac": r["mac"], "ip": r["ip"], "via_id": r["via_id"], "via": by_id.get((r["plugin_id"], r["via_id"])) if r["via_id"] else None, "available": bool(r["available"]),
                "battery": r["battery"], "battery_low": bool(r["battery_low"]), "update": bool(r["update_available"]), "url": r["url"], "device_id": r["device_id"], "device": names.get(r["device_id"]),
                "unavailable_since": r["unavailable_since"]} for r in rows]
    return {"servers": servers, "devices": devices, "summary": summary(conn)}


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Counts for the dashboard, the attention list and /metrics."""
    one = lambda sql: conn.execute(sql).fetchone()[0]    # noqa: E731 - fixed statements, no user input
    total = one("SELECT COUNT(*) FROM inventory_devices")
    return {"configured": bool(one("SELECT COUNT(*) FROM inventory_servers")), "devices": total, "unavailable": one("SELECT COUNT(*) FROM inventory_devices WHERE available = 0"),
            "battery_low": one("SELECT COUNT(*) FROM inventory_devices WHERE battery_low = 1"), "updates": one("SELECT COUNT(*) FROM inventory_devices WHERE update_available = 1"),
            "matched": one("SELECT COUNT(*) FROM inventory_devices WHERE device_id IS NOT NULL")}


def for_device(conn: sqlite3.Connection, device_id: int) -> dict | None:
    r = conn.execute("SELECT * FROM inventory_devices WHERE device_id = ? ORDER BY available DESC LIMIT 1", (device_id,)).fetchone()
    if r is None:
        return None
    via = conn.execute("SELECT name FROM inventory_devices WHERE plugin_id = ? AND dev_id = ?", (r["plugin_id"], r["via_id"])).fetchone() if r["via_id"] else None
    return {"plugin_id": r["plugin_id"], "name": r["name"], "manufacturer": r["manufacturer"], "model": r["model"], "area": r["area"], "sw": r["sw"], "protocol": r["protocol"],
            "available": bool(r["available"]), "battery": r["battery"], "battery_low": bool(r["battery_low"]), "update": bool(r["update_available"]), "url": r["url"], "via": via["name"] if via else None}
