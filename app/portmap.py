"""Which device sits behind which port of a switch.

The facts come from two places: the links a switch plugin reports (`client_links`: SNMP reads the MAC table) and the links the owner set by
hand (the same table, source 'manual': the only way for a switch that does not tell, like a TP-Link Easy Smart). The hierarchy says what is
below a device in the network; a device below a switch whose port is unknown is listed apart. A device behind another switch that hangs on
this one is listed under the port that leads there.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from app.hierarchy import children_map, descendants, device_name, load_hierarchy
from app.plugins.matching import norm_mac

MAX_BEHIND = 200      # devices listed behind one port; the rest is only counted


def natural(text: str) -> list:
    """Sort key: 'Gi1/0/10' after 'Gi1/0/9'."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", str(text))]


def _entry(devs: dict, device_id: int) -> dict[str, Any]:
    d = devs[device_id]
    return {"id": device_id, "name": device_name(d), "type": d.get("type_override") or d.get("device_type") or "unknown", "online": bool(d.get("online"))}


def _label(port: Any) -> str:
    return str(port).strip()


def for_switch(conn: sqlite3.Connection, switch_id: int) -> dict[str, Any]:
    """The port map of one switch: its ports with the devices on them, devices with no known port, and where this switch itself is connected."""
    devs, hierarchy = load_hierarchy(conn)
    if switch_id not in devs:
        return {"ports": [], "no_port": [], "uplink": None}
    kids = children_map(hierarchy)
    me = devs[switch_id]
    my_mac = norm_mac(me["mac"]) if me.get("mac") else None

    known: dict[str, dict] = {}                     # label -> port facts from the switch itself
    for r in conn.execute("SELECT * FROM switch_ports WHERE device_id = ? ORDER BY port", (switch_id,)):
        known[str(r["port"])] = dict(r)
    name_to_label = {(p["name"] or "").strip().lower(): label for label, p in known.items() if (p["name"] or "").strip()}

    links: dict[int, dict] = {}                     # linked device -> its link row, for this switch
    rows = conn.execute(
        "SELECT device_id, node_mac, node_name, port, source, node_device_id, seen_node, seen_port FROM client_links"
    ).fetchall()
    for r in rows:
        mine = r["node_device_id"] == switch_id or (r["node_device_id"] is None and my_mac and r["node_mac"] and norm_mac(r["node_mac"]) == my_mac)
        if mine and r["device_id"] in devs and r["device_id"] != switch_id:
            links[r["device_id"]] = dict(r)

    direct = set(links) | set(kids.get(switch_id, []))
    by_port: dict[str, list[dict]] = {}
    no_port: list[dict] = []
    for device_id in sorted(direct, key=lambda i: device_name(devs[i]).lower()):
        entry = _entry(devs, device_id)
        behind_ids = sorted(descendants(hierarchy, device_id, kids) - direct - {switch_id}, key=lambda i: device_name(devs[i]).lower())
        entry["behind"] = [_entry(devs, i) for i in behind_ids[:MAX_BEHIND]]
        entry["behind_total"] = len(behind_ids)
        link = links.get(device_id)
        entry["manual"] = bool(link and link["source"] == "manual")
        entry["differs"] = None
        if link and link["source"] == "manual" and (link["seen_port"] or link["seen_node"]):
            other_port = bool(link["seen_port"]) and link["seen_port"] != (link["port"] or "")
            other_node = bool(link["seen_node"]) and link["seen_node"].lower() != device_name(me).lower()
            if other_port or other_node:
                entry["differs"] = {"node": link["seen_node"], "port": link["seen_port"]}
        port = _label(link["port"]) if link and link["port"] else ""
        label = port if port in known else name_to_label.get(port.lower(), port)      # a port may be given by its number or by the name the switch gives it
        (by_port.setdefault(label, []) if label else no_port).append(entry)

    labels = sorted(set(known) | set(by_port), key=natural)
    ports = []
    for label in labels:
        k = known.get(label)
        ports.append({
            "port": label,
            "name": (k or {}).get("name") or "",
            "known": k is not None,
            "up": bool(k["up"]) if k else None,
            "enabled": bool(k["enabled"]) if k else None,
            "speed_mbps": k["speed_mbps"] if k else None,
            "duplex": k["duplex"] if k else None,
            "devices": by_port.get(label, []),
        })

    own = conn.execute("SELECT node_mac, node_name, port, source, node_device_id FROM client_links WHERE device_id = ?", (switch_id,)).fetchone()
    parent = hierarchy[switch_id].parent_id
    uplink = None
    if parent is not None:
        uplink = {"id": parent, "name": device_name(devs[parent]), "port": own["port"] if own and own["node_device_id"] in (None, parent) else None,
                  "manual": bool(own and own["source"] == "manual")}
    return {"ports": ports, "no_port": no_port, "uplink": uplink}


def set_manual(conn: sqlite3.Connection, device_id: int, switch_id: int, port: str | None, now: str) -> None:
    """The owner says: this device is connected to this switch (on this port). It becomes the device's parent as well."""
    sw = conn.execute("SELECT mac, custom_name, hostname, primary_ip FROM devices WHERE id = ?", (switch_id,)).fetchone()
    name = sw["custom_name"] or sw["hostname"] or sw["primary_ip"] or f"device {switch_id}"
    conn.execute(
        """
        INSERT INTO client_links (device_id, plugin_id, node_mac, node_name, port, medium, updated, source, node_device_id, seen_node, seen_port)
        VALUES (?, 'manual', ?, ?, ?, 'wired', ?, 'manual', ?, NULL, NULL)
        ON CONFLICT(device_id) DO UPDATE SET plugin_id = 'manual', node_mac = excluded.node_mac, node_name = excluded.node_name, port = excluded.port,
            medium = 'wired', updated = excluded.updated, source = 'manual', node_device_id = excluded.node_device_id
        """,
        (device_id, sw["mac"], name, (port or "").strip()[:60] or None, now, switch_id),
    )
    conn.execute("UPDATE devices SET parent_mode = 'device', parent_device_id = ? WHERE id = ?", (switch_id, device_id))
    conn.commit()


def clear_manual(conn: sqlite3.Connection, device_id: int) -> bool:
    """Forget a link set by hand; the parent goes back to automatic when it was this switch."""
    row = conn.execute("SELECT node_device_id FROM client_links WHERE device_id = ? AND source = 'manual'", (device_id,)).fetchone()
    if row is None:
        return False
    conn.execute("DELETE FROM client_links WHERE device_id = ? AND source = 'manual'", (device_id,))
    if row["node_device_id"] is not None:
        conn.execute(
            "UPDATE devices SET parent_mode = 'auto', parent_device_id = NULL WHERE id = ? AND parent_mode = 'device' AND parent_device_id = ?",
            (device_id, row["node_device_id"]),
        )
    conn.commit()
    return True
