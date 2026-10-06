Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The events table is events(id, ts, device_id, kind, detail). Every events query and the dict built from it must use these real column names: SELECT id, ts, kind, detail FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 20, and return keys id, ts, kind, detail. There are columns named event_type, timestamp and details in the current code that do not exist; remove them. Also avoid duplicating the detail-building logic: PATCH should reuse the same helper as GET.

CURRENT FILE:
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.db import connect

DEVICE_TYPES = {
    "router",
    "switch",
    "ap",
    "server",
    "pc",
    "phone",
    "printer",
    "iot",
    "camera",
    "nas",
    "vm",
    "unknown",
}


def get_conn(request: Request):
    conn = connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


router = APIRouter(prefix="/api", tags=["devices"])


class DevicePatch(BaseModel):
    custom_name: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    type_override: str | None = None


def _parse_tags(value: str | None) -> list[str]:
    if not value:
        return []
    return [t.strip() for t in value.split(",") if t.strip()]


def _device_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "primary_ip": row["primary_ip"],
        "mac": row["mac"],
        "hostname": row["hostname"],
        "custom_name": row["custom_name"],
        "vendor": row["vendor"],
        "device_type": row["device_type"],
        "type_override": row["type_override"],
        "notes": row["notes"],
        "tags": _parse_tags(row["tags"]),
        "online": row["online"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "name": row["custom_name"] or row["hostname"] or row["primary_ip"],
        "type": row["type_override"] or row["device_type"] or "unknown",
        "open_ports": row["open_ports"],
    }


@router.get("/devices")
def list_devices(
    request: Request,
    online: bool | None = None,
    q: str | None = None,
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    sql = """
        SELECT
            id,
            primary_ip,
            mac,
            hostname,
            custom_name,
            vendor,
            device_type,
            type_override,
            notes,
            tags,
            online,
            first_seen,
            last_seen,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
    """
    params: list[Any] = []
    conditions: list[str] = []

    if online is not None:
        conditions.append("online = ?")
        params.append(int(online))

    if q:
        conditions.append(
            "(hostname LIKE ? OR custom_name LIKE ? OR primary_ip LIKE ? OR mac LIKE ? OR vendor LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like, like])

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += " ORDER BY primary_ip, id"

    rows = conn.execute(sql, params).fetchall()
    return [_device_dict(row) for row in rows]


@router.get("/devices/{device_id}")
def get_device(
    device_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            id,
            primary_ip,
            mac,
            hostname,
            custom_name,
            vendor,
            device_type,
            type_override,
            notes,
            tags,
            online,
            first_seen,
            last_seen,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="device not found")

    result = _device_dict(row)

    ips = conn.execute(
        "SELECT ip, last_seen FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC",
        (device_id,),
    ).fetchall()
    result["ips"] = [{"ip": r["ip"], "last_seen": r["last_seen"]} for r in ips]

    names = conn.execute(
        "SELECT name, source FROM device_names WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    result["names"] = [{"name": r["name"], "source": r["source"]} for r in names]

    ports = conn.execute(
        "SELECT port, proto, service FROM ports WHERE device_id = ? ORDER BY proto, port",
        (device_id,),
    ).fetchall()
    result["ports"] = [{"port": r["port"], "proto": r["proto"], "service": r["service"]} for r in ports]

    events = conn.execute(
        "SELECT id, event_type, timestamp, details FROM events WHERE device_id = ? ORDER BY timestamp DESC LIMIT 20",
        (device_id,),
    ).fetchall()
    result["events"] = [
        {"id": r["id"], "event_type": r["event_type"], "timestamp": r["timestamp"], "details": r["details"]}
        for r in events
    ]

    return result


@router.patch("/devices/{device_id}")
def patch_device(
    device_id: int,
    body: DevicePatch,
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT
            id,
            primary_ip,
            mac,
            hostname,
            custom_name,
            vendor,
            device_type,
            type_override,
            notes,
            tags,
            online,
            first_seen,
            last_seen,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="device not found")

    fields_set = body.model_fields_set

    if not fields_set:
        return _device_dict(row)

    updates: dict[str, Any] = {}

    if "custom_name" in fields_set:
        val = body.custom_name
        updates["custom_name"] = val if val else None

    if "notes" in fields_set:
        val = body.notes
        updates["notes"] = val if val else None

    if "type_override" in fields_set:
        val = body.type_override
        if val is not None:
            if val not in DEVICE_TYPES:
                raise HTTPException(status_code=422, detail="invalid type_override")
            updates["type_override"] = val
        else:
            updates["type_override"] = None

    if "tags" in fields_set:
        raw_tags = body.tags
        if raw_tags is None:
            updates["tags"] = None
        else:
            cleaned = [t.strip() for t in raw_tags if t.strip()]
            if len(cleaned) > 20:
                raise HTTPException(status_code=422, detail="max 20 tags")
            if any(len(t) > 40 for t in cleaned):
                raise HTTPException(status_code=422, detail="max 40 chars per tag")
            updates["tags"] = ",".join(cleaned) if cleaned else None

    if updates:
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        params = list(updates.values()) + [device_id]
        conn.execute(f"UPDATE devices SET {set_clause} WHERE id = ?", params)
        conn.commit()

    row = conn.execute(
        """
        SELECT
            id,
            primary_ip,
            mac,
            hostname,
            custom_name,
            vendor,
            device_type,
            type_override,
            notes,
            tags,
            online,
            first_seen,
            last_seen,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    result = _device_dict(row)

    ips = conn.execute(
        "SELECT ip, last_seen FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC",
        (device_id,),
    ).fetchall()
    result["ips"] = [{"ip": r["ip"], "last_seen": r["last_seen"]} for r in ips]

    names = conn.execute(
        "SELECT name, source FROM device_names WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    result["names"] = [{"name": r["name"], "source": r["source"]} for r in names]

    ports = conn.execute(
        "SELECT port, proto, service FROM ports WHERE device_id = ? ORDER BY proto, port",
        (device_id,),
    ).fetchall()
    result["ports"] = [{"port": r["port"], "proto": r["proto"], "service": r["service"]} for r in ports]

    events = conn.execute(
        "SELECT id, event_type, timestamp, details FROM events WHERE device_id = ? ORDER BY timestamp DESC LIMIT 20",
        (device_id,),
    ).fetchall()
    result["events"] = [
        {"id": r["id"], "event_type": r["event_type"], "timestamp": r["timestamp"], "details": r["details"]}
        for r in events
    ]

    return result