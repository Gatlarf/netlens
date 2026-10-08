"""Turn the router's view (which client sits on which AiMesh node) into 'uplink' relations."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3

from app.db import connect, get_setting, set_setting, utcnow
from app.integrations.asus_client import AsusAuthError, AsusClient, AsusError, norm_mac
from app.integrations.asus_config import is_configured, load_config

log = logging.getLogger(__name__)
STATUS_KEY = "asus_status"
SNAPSHOT_KEY = "asus_snapshot"
SOURCE = "asus-mesh"


def _lookup(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, int]]:
    by_mac: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for row in conn.execute("SELECT id, mac, primary_ip FROM devices ORDER BY id DESC"):
        if row["mac"]:
            by_mac[norm_mac(row["mac"]) or row["mac"].lower()] = row["id"]
        if row["primary_ip"]:
            by_ip[row["primary_ip"]] = row["id"]
    for row in conn.execute("SELECT device_id, ip FROM device_ips ORDER BY device_id DESC"):
        by_ip[row["ip"]] = row["device_id"]
    return by_mac, by_ip


def compute_links(snapshot: dict, by_mac: dict[str, int], by_ip: dict[str, int]) -> list[tuple[int, int, str]]:
    """[(child device id, parent device id, 'how')]; mesh nodes hang below the node they are wired to, else the main router."""
    nodes = snapshot.get("nodes") or []

    def node_device(node: dict) -> int | None:
        for mac in node.get("macs") or [node.get("mac")]:
            if mac in by_mac:
                return by_mac[mac]
        return by_ip.get(node.get("ip") or "")

    main = next((n for n in nodes if n.get("main")), None)
    dev_of = {n["mac"]: node_device(n) for n in nodes}
    mac_to_node = {m: n for n in nodes for m in (n.get("macs") or [n["mac"]])}
    node_ids = {d for d in dev_of.values() if d is not None}
    links: dict[int, tuple[int, str]] = {}

    for node in nodes:
        child = dev_of[node["mac"]]
        if child is None or node is main:
            continue
        parent_node = next((p for p in nodes if p is not node and node["mac"] in (p.get("wired_macs") or [])), None) or main
        parent = dev_of.get(parent_node["mac"]) if parent_node else None
        if parent is not None and parent != child:
            links[child] = (parent, "mesh node")

    for client in snapshot.get("clients") or []:
        child = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if child is None or child in node_ids:
            continue
        node = mac_to_node.get(client.get("node_mac") or "") or main
        parent = dev_of.get(node["mac"]) if node else None
        if parent is None or parent == child:
            continue
        links[child] = (parent, "wired" if client.get("wired") else f"Wi-Fi {client.get('band') or ''}".strip())
    return [(c, p, how) for c, (p, how) in links.items()]


def apply_asus_relations(conn: sqlite3.Connection) -> int:
    """Create 'uplink' edges client -> mesh node from the stored snapshot. Call after every relation re-inference.

    Edges the user deleted (manual = -1) stay hidden; other kinds of edge are left alone.
    """
    raw = get_setting(conn, SNAPSHOT_KEY)
    conn.execute("DELETE FROM relations WHERE source = ? AND manual = 0", (SOURCE,))
    if not raw:
        conn.commit()
        return 0
    try:
        snapshot = json.loads(raw)
    except ValueError:
        conn.commit()
        return 0
    by_mac, by_ip = _lookup(conn)
    links = compute_links(snapshot, by_mac, by_ip)
    for child, parent, _how in links:
        conn.execute(
            """
            INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual)
            VALUES (?, ?, 'uplink', ?, 1.0, 0)
            ON CONFLICT(src_id, dst_id, kind) DO UPDATE SET source = excluded.source, confidence = 1.0 WHERE manual = 0
            """,
            (child, parent, SOURCE),
        )
    conn.commit()
    return len(links)


def record_status(conn: sqlite3.Connection, **fields) -> None:
    set_setting(conn, STATUS_KEY, json.dumps({"ts": utcnow(), **fields}))


def load_status(conn: sqlite3.Connection) -> dict | None:
    raw = get_setting(conn, STATUS_KEY)
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


async def sync_now(db_path: str, *, client_factory=AsusClient) -> dict:
    """Read the router and store the result. Returns a summary or {'error': ...}."""
    conn = connect(db_path)
    try:
        cfg = load_config(conn)
        if not is_configured(cfg):
            return {"error": "the router is not configured"}
        try:
            snapshot = await asyncio.to_thread(lambda: client_factory(cfg).snapshot())
        except AsusError as exc:
            log.warning("asus sync failed: %s", exc)
            record_status(conn, ok=False, error=str(exc), auth_failed=isinstance(exc, AsusAuthError))
            return {"error": str(exc)}
        set_setting(conn, SNAPSHOT_KEY, json.dumps(snapshot))
        links = apply_asus_relations(conn)
        record_status(conn, ok=True, nodes=len(snapshot["nodes"]), clients=len(snapshot["clients"]), links=links)
        return {"nodes": len(snapshot["nodes"]), "clients": len(snapshot["clients"]), "links": links}
    finally:
        conn.close()


async def asus_after_scan(db_path: str) -> None:
    """Scan hook: refresh from the router and re-apply the edges the scan's inference just replaced.

    After a refused login the hook stops asking until the user saves or syncs again (no hammering the login).
    """
    conn = connect(db_path)
    try:
        cfg = load_config(conn)
        status = load_status(conn)
    finally:
        conn.close()
    if not cfg.enabled:
        return
    if not (status and status.get("auth_failed")):
        result = await sync_now(db_path)
        if "error" not in result:
            return
    conn = connect(db_path)
    try:
        apply_asus_relations(conn)  # keep the last known links on the map
    finally:
        conn.close()
