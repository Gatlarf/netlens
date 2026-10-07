"""Store a Proxmox inventory, match it to scanned devices and expose it on the map."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sqlite3

from app.db import connect, set_setting, utcnow
from app.integrations.proxmox_client import ProxmoxClient, ProxmoxError
from app.integrations.proxmox_config import is_configured, load_config
from app.integrations.proxmox_match import match_inventory

log = logging.getLogger(__name__)
STATUS_KEY = "proxmox_status"


def _devices_for_matching(conn: sqlite3.Connection) -> list[dict]:
    devices: dict[int, dict] = {}
    for row in conn.execute("SELECT id, mac, primary_ip FROM devices"):
        devices[row["id"]] = {"id": row["id"], "mac": row["mac"], "ips": [row["primary_ip"]] if row["primary_ip"] else []}
    for row in conn.execute("SELECT device_id, ip FROM device_ips"):
        d = devices.get(row["device_id"])
        if d is not None and row["ip"] not in d["ips"]:
            d["ips"].append(row["ip"])
    return list(devices.values())


def store_inventory(conn: sqlite3.Connection, inventory: dict, now: str | None = None) -> dict:
    """Replace the stored guests with the matched inventory; returns a summary."""
    now = now or utcnow()
    matched = match_inventory(inventory, _devices_for_matching(conn))
    conn.execute("DELETE FROM proxmox_guests")
    for g in matched["guests"]:
        conn.execute(
            """
            INSERT INTO proxmox_guests (vmid, name, kind, node, status, macs, ips, device_id, host_device_id, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (g["vmid"], g["name"], g["kind"], g["node"], g["status"], json.dumps(g["macs"]), json.dumps(g["ips"]),
             g["device_id"], g["host_device_id"], now),
        )
    conn.commit()
    return {
        "nodes": len(inventory["nodes"]),
        "hosts_matched": sum(1 for v in matched["hosts"].values() if v is not None),
        "guests": len(matched["guests"]),
        "guests_matched": sum(1 for g in matched["guests"] if g["device_id"] is not None),
    }


def apply_proxmox_relations(conn: sqlite3.Connection) -> int:
    """Create 'host-of' edges guest -> Proxmox host (confidence 1.0). Heuristic edges for these guests are dropped.

    Edges the user deleted (manual = -1) stay hidden. Call after every relation re-inference.
    """
    pairs = [
        (r["device_id"], r["host_device_id"])
        for r in conn.execute(
            "SELECT device_id, host_device_id FROM proxmox_guests "
            "WHERE device_id IS NOT NULL AND host_device_id IS NOT NULL AND device_id != host_device_id"
        )
    ]
    conn.execute("DELETE FROM relations WHERE source = 'proxmox' AND manual = 0")
    for guest, host in pairs:
        conn.execute(
            "DELETE FROM relations WHERE kind = 'host-of' AND manual = 0 AND src_id = ? AND dst_id != ?",
            (guest, host),
        )
        conn.execute(
            """
            INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual)
            VALUES (?, ?, 'host-of', 'proxmox', 1.0, 0)
            ON CONFLICT(src_id, dst_id, kind) DO UPDATE SET source = 'proxmox', confidence = 1.0 WHERE manual = 0
            """,
            (guest, host),
        )
    conn.commit()
    return len(pairs)


def record_status(conn: sqlite3.Connection, **fields) -> None:
    set_setting(conn, STATUS_KEY, json.dumps({"ts": utcnow(), **fields}))


async def sync_now(db_path: str, *, client_factory=ProxmoxClient) -> dict:
    """Fetch the inventory from Proxmox and store it. Returns the summary or {'error': ...}."""
    conn = connect(db_path)
    try:
        cfg = load_config(conn)
        if not is_configured(cfg):
            return {"error": "Proxmox is not configured"}
        try:
            inventory = await asyncio.to_thread(lambda: client_factory(cfg).inventory())
        except ProxmoxError as exc:
            log.warning("proxmox sync failed: %s", exc)
            record_status(conn, ok=False, error=str(exc))
            return {"error": str(exc)}
        summary = store_inventory(conn, inventory)
        links = apply_proxmox_relations(conn)
        record_status(conn, ok=True, links=links, **summary)
        return {**summary, "links": links}
    finally:
        conn.close()


async def proxmox_after_scan(db_path: str) -> None:
    """Scan hook: refresh the inventory and re-apply the edges the scan's inference just replaced."""
    conn = connect(db_path)
    try:
        enabled = load_config(conn).enabled
    finally:
        conn.close()
    if not enabled:
        return
    result = await sync_now(db_path)
    if "error" in result:  # keep the last known guests on the map
        conn = connect(db_path)
        try:
            apply_proxmox_relations(conn)
        finally:
            conn.close()
