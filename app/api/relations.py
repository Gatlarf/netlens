import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
import sqlite3
from typing import Any

from app.api.devices import get_conn
from app import groups as groups_mod
from app.scanner import vendor as vendor_db
from app.hierarchy import load_hierarchy
from app.scanner.relstore import list_relations, add_manual, delete_relation


router = APIRouter(prefix="/api", tags=["relations"])


class RelationCreate(BaseModel):
    src_id: int
    dst_id: int
    kind: str = "manual"


@router.get("/relations")
def get_relations(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    return list_relations(conn)


@router.post("/relations", status_code=201)
def create_relation(
    body: RelationCreate,
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, int]:
    try:
        relation_id = add_manual(conn, body.src_id, body.dst_id, body.kind)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"id": relation_id}


@router.delete("/relations/{relation_id}", status_code=204)
def remove_relation(
    relation_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> None:
    if not delete_relation(conn, relation_id):
        raise HTTPException(status_code=404, detail="relation not found")


SHOWN_STATES = ("running", "restarting", "paused")


def _guest_nodes(conn: sqlite3.Connection, known: set[int]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Containers and apps that are not a device themselves, as nodes under their host. A virtual machine is left out:
    it is a device, or it has not been seen on the network."""
    nodes, edges = [], []
    rows = conn.execute(
        """SELECT plugin_id, guest_id, name, kind, status, host_device_id, details FROM hypervisor_guests
           WHERE device_id IS NULL AND host_device_id IS NOT NULL AND kind NOT IN ('qemu', 'vm') ORDER BY plugin_id, name"""
    ).fetchall()
    for r in rows:
        if r["host_device_id"] not in known or r["status"] not in SHOWN_STATES:
            continue
        try:
            details = json.loads(r["details"]) if r["details"] else {}
        except ValueError:
            details = {}
        node_id = f"g:{r['plugin_id']}:{r['guest_id']}"
        nodes.append({
            "id": node_id, "label": r["name"], "ip": None, "mac": None, "vendor": None, "type": "container", "online": r["status"] == "running",
            "pos_x": None, "pos_y": None, "open_ports": 0, "tags": [], "mac_kind": None, "group_id": None, "group": None, "group_color": None,
            "virtual": True, "guest_kind": r["kind"], "status": r["status"], "health": details.get("health"), "image": details.get("image"),
            "plugin": r["plugin_id"], "parent_id": r["host_device_id"], "parent_source": "hypervisor",
        })
        edges.append({"id": f"v{node_id}", "from": r["host_device_id"], "to": node_id, "kind": "parent", "source": "hypervisor", "confidence": 1.0,
                      "manual": False, "reason": "runs on this host", "virtual": True})
    return nodes, edges


@router.get("/map")
def get_map(guests: bool = False, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT id, mac, primary_ip, hostname, vendor, device_type, type_override,
               online, pos_x, pos_y, tags, custom_name, group_id,
               (SELECT COUNT(*) FROM ports WHERE device_id = devices.id AND state LIKE 'open%') AS open_ports
        FROM devices
        ORDER BY id
        """
    ).fetchall()

    known_groups = groups_mod.lookup(conn)
    for row in rows:
        group = known_groups.get(row["group_id"])
        tags_raw = row["tags"]
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
        label = row["custom_name"] or row["hostname"] or row["primary_ip"]
        device_type = row["type_override"] or row["device_type"] or "unknown"
        nodes.append({
            "id": row["id"],
            "label": label,
            "ip": row["primary_ip"],
            "mac": row["mac"],
            "vendor": row["vendor"],
            "type": device_type,
            "online": bool(row["online"]),
            "pos_x": row["pos_x"],
            "pos_y": row["pos_y"],
            "open_ports": row["open_ports"],
            "tags": tags,
            "mac_kind": vendor_db.mac_kind(row["mac"]),
            "group_id": row["group_id"],
            "group": group["name"] if group else None,
            "group_color": group["color"] if group else None,
        })

    # The chosen parent of every device as an edge parent -> child (the "hierarchy" view of the map)
    _, hierarchy = load_hierarchy(conn)
    by_id = {n["id"]: n for n in nodes}
    for dev_id, info in hierarchy.items():
        by_id[dev_id]["parent_id"] = info.parent_id
        by_id[dev_id]["parent_source"] = info.source

    edges: list[dict[str, Any]] = []
    for dev_id, info in sorted(hierarchy.items()):
        if info.parent_id is not None:
            edges.append({
                "id": f"p{dev_id}",
                "from": info.parent_id,
                "to": dev_id,
                "kind": "parent",
                "source": info.source,
                "confidence": 1.0,
                "manual": info.locked,
                "reason": info.reason,
            })
    for rel in list_relations(conn):
        edges.append({
            "id": rel["id"],
            "from": rel["src_id"],
            "to": rel["dst_id"],
            "kind": rel["kind"],
            "source": rel["source"],
            "confidence": rel["confidence"],
            "manual": bool(rel["manual"]),
        })

    if guests:
        extra_nodes, extra_edges = _guest_nodes(conn, {n["id"] for n in nodes})
        nodes += extra_nodes
        edges += extra_edges
    return {"nodes": nodes, "edges": edges}