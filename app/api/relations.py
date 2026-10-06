from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
import sqlite3
from typing import Any

from app.api.devices import get_conn
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


@router.get("/map")
def get_map(conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    rows = conn.execute(
        """
        SELECT id, mac, primary_ip, hostname, vendor, device_type, type_override,
               online, pos_x, pos_y, tags, custom_name,
               (SELECT COUNT(*) FROM ports WHERE device_id = devices.id AND state LIKE 'open%') AS open_ports
        FROM devices
        ORDER BY id
        """
    ).fetchall()

    for row in rows:
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
        })

    edges: list[dict[str, Any]] = []
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

    return {"nodes": nodes, "edges": edges}