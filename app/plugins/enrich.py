"""What Netlens learns from a topology plugin besides the links: names from the router, Wi-Fi signal samples, roaming."""

from __future__ import annotations

import sqlite3

from app.db import add_event, utcnow
from app.plugins.matching import norm_mac

WIFI_RETENTION_DAYS = 14
ROAM_WINDOW_HOURS = 24  # a node change counts as roaming only when the previous sample is this recent
ALIAS_PRIORITY = ("ptr", "upnp", "mdns", "router")  # which name wins as a device's hostname when it has none
MAX_NAME = 80


def device_lookup(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, int]]:
    """(device id by MAC, device id by IP); the newest device wins a clash."""
    by_mac: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for row in conn.execute("SELECT id, mac, primary_ip FROM devices ORDER BY id DESC"):
        if row["mac"]:
            by_mac[norm_mac(row["mac"])] = row["id"]
        if row["primary_ip"]:
            by_ip[row["primary_ip"]] = row["id"]
    for row in conn.execute("SELECT device_id, ip FROM device_ips ORDER BY device_id DESC"):
        by_ip[row["ip"]] = row["device_id"]
    return by_mac, by_ip


def refresh_hostname(conn: sqlite3.Connection, device_id: int) -> None:
    """A device without a hostname takes its best alias (PTR, UPnP, mDNS, router name, in that order)."""
    row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None or (row["hostname"] or "").strip():
        return
    names = conn.execute("SELECT name, source FROM device_names WHERE device_id = ?", (device_id,)).fetchall()
    for source in ALIAS_PRIORITY:
        for n in names:
            if n["source"] == source and n["name"].strip():
                conn.execute("UPDATE devices SET hostname = ? WHERE id = ?", (n["name"].strip(), device_id))
                return


def record_router_names(conn: sqlite3.Connection, data: dict, now: str | None = None) -> int:
    """Store the names a router knows its clients by (source 'router'). Returns how many were recorded."""
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    count = 0
    for client in data.get("clients", []):
        name = (client.get("name") or "").strip()[:MAX_NAME]
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if not name or device_id is None or name == client.get("ip"):
            continue
        conn.execute(
            """
            INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, 'router', ?, ?)
            ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (device_id, name, now, now),
        )
        refresh_hostname(conn, device_id)
        count += 1
    conn.commit()
    return count


def record_wifi(conn: sqlite3.Connection, data: dict, now: str | None = None) -> dict:
    """Store one signal sample per Wi-Fi client and log a `wifi_roamed` event when a client changed node.

    Call once per fresh fetch (not when links are re-applied), so every sample is a real measurement.
    """
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    node_name = {m: n.get("name") or n["mac"] for n in data.get("nodes", []) for m in n["macs"]}
    gateway = next((n for n in data.get("nodes", []) if n["role"] == "gateway"), None)
    samples = roams = 0
    from datetime import datetime, timedelta, timezone

    cutoff_roam = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(hours=ROAM_WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for client in data.get("clients", []):
        if client.get("medium") != "wifi":
            continue
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if device_id is None:
            continue
        node = node_name.get(client.get("node_mac") or (gateway or {}).get("mac"), None)
        previous = conn.execute("SELECT ts, node FROM wifi_samples WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        if previous and previous["node"] and node and previous["node"] != node and previous["ts"] >= cutoff_roam:
            add_event(conn, "wifi_roamed", f"{previous['node']} -> {node}" + (f" ({client['band']})" if client.get("band") else ""), device_id=device_id, now=now)
            roams += 1
        conn.execute(
            "INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps, rx_mbps) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_id, now, node, client.get("band"), client.get("rssi"), client.get("tx_mbps"), client.get("rx_mbps")),
        )
        samples += 1
    old = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(days=WIFI_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM wifi_samples WHERE ts < ?", (old,))
    conn.commit()
    return {"samples": samples, "roams": roams}
