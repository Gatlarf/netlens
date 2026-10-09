from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import actions, baselines, groups as groups_mod
from app.db import add_event, connect, utcnow
from app.scanner.orchestrator import ScanBusy
from app.hierarchy import children_map, descendants, device_name, load_hierarchy, would_loop

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
    custom_name: str | None = Field(default=None, max_length=100)
    notes: str | None = Field(default=None, max_length=4000)
    tags: list[str] | None = None
    type_override: str | None = None
    notify_offline: bool | None = None
    trusted: bool | None = None             # True = a device the user knows
    group_id: int | None = None             # a group from /api/groups, or null for none
    parent_mode: str | None = None          # 'auto' | 'none' | 'device'
    parent_device_id: int | None = None
    pos_x: float | None = None
    pos_y: float | None = None


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
        "os_name": row["os_name"],
        "os_confidence": row["os_confidence"],
        "pos_x": row["pos_x"],
        "pos_y": row["pos_y"],
        "name": row["custom_name"] or row["hostname"] or row["primary_ip"],
        "type": row["type_override"] or row["device_type"] or "unknown",
        "open_ports": row["open_ports"],
        "notify_offline": bool(row["notify_offline"]),
        "trusted": bool(row["trusted"]),
        "group_id": row["group_id"],
    }


def _add_group(conn: sqlite3.Connection, devices: list[dict[str, Any]]) -> None:
    """Add the group's name and colour next to `group_id`."""
    known = groups_mod.lookup(conn)
    for d in devices:
        g = known.get(d.get("group_id"))
        d["group"] = g["name"] if g else None
        d["group_color"] = g["color"] if g else None


def _virtualization_info(conn: sqlite3.Connection, device_id: int) -> dict[str, Any] | None:
    """Hypervisor role of a device: it is a guest (VM/container) of a host and/or a host with guests."""
    guest = None
    row = conn.execute(
        """
        SELECT g.plugin_id, g.guest_id, g.name, g.kind, g.host_name AS node, g.status, g.host_device_id,
               COALESCE(h.custom_name, h.hostname, h.primary_ip) AS host_name
        FROM hypervisor_guests g LEFT JOIN devices h ON h.id = g.host_device_id
        WHERE g.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is not None:
        guest = {k: row[k] for k in row.keys()}

    rows = conn.execute(
        """
        SELECT g.plugin_id, g.guest_id, g.name, g.kind, g.status, g.ips, g.device_id,
               COALESCE(d.custom_name, d.hostname, d.primary_ip) AS device_name
        FROM hypervisor_guests g LEFT JOIN devices d ON d.id = g.device_id
        WHERE g.host_device_id = ? ORDER BY g.plugin_id, g.name
        """,
        (device_id,),
    ).fetchall()
    guests = []
    for r in rows:
        item = {k: r[k] for k in r.keys()}
        try:
            item["ips"] = json.loads(item["ips"])
        except (TypeError, ValueError):
            item["ips"] = []
        guests.append(item)

    if guest is None and not guests:
        return None
    return {"guest": guest, "guests": guests}


def _parent_info(conn: sqlite3.Connection, device_id: int) -> dict[str, Any]:
    """Where the device sits in the network hierarchy and what is below it."""
    devs, hierarchy = load_hierarchy(conn)
    d = devs[device_id]
    info = hierarchy[device_id]
    parent = None
    if info.parent_id is not None:
        parent = {"id": info.parent_id, "name": device_name(devs[info.parent_id])}
    kids = children_map(hierarchy).get(device_id, [])
    return {
        "mode": d["parent_mode"],
        "device_id": d["parent_device_id"] if d["parent_mode"] == "device" else None,
        "effective": parent,
        "source": info.source,
        "reason": info.reason,
        "children": [
            {
                "id": k,
                "name": device_name(devs[k]),
                "type": devs[k]["type_override"] or devs[k]["device_type"] or "unknown",
                "online": bool(devs[k]["online"]),
            }
            for k in sorted(kids, key=lambda i: device_name(devs[i]).lower())
        ],
        "descendants": sorted(descendants(hierarchy, device_id)),
    }


def _build_device_detail(conn: sqlite3.Connection, device_id: int, row: sqlite3.Row) -> dict[str, Any]:
    result = _device_dict(row)
    _add_group(conn, [result])

    ips = conn.execute(
        "SELECT ip, first_seen, last_seen FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC",
        (device_id,),
    ).fetchall()
    result["ips"] = [
        {"ip": r["ip"], "first_seen": r["first_seen"], "last_seen": r["last_seen"]}
        for r in ips
    ]

    names = conn.execute(
        "SELECT name, source, first_seen, last_seen FROM device_names WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    result["names"] = [
        {"name": r["name"], "source": r["source"], "first_seen": r["first_seen"], "last_seen": r["last_seen"]}
        for r in names
    ]

    ports = conn.execute(
        "SELECT proto, port, state, service, product, version, updated FROM ports WHERE device_id = ? ORDER BY proto, port",
        (device_id,),
    ).fetchall()
    result["ports"] = [
        {
            "proto": r["proto"],
            "port": r["port"],
            "state": r["state"],
            "service": r["service"],
            "product": r["product"],
            "version": r["version"],
            "updated": r["updated"],
        }
        for r in ports
    ]

    events = conn.execute(
        "SELECT id, ts, kind, detail FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 20",
        (device_id,),
    ).fetchall()
    result["events"] = [
        {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "detail": r["detail"]}
        for r in events
    ]

    result["baseline"] = baselines.drift(conn, device_id)
    result["virtualization"] = _virtualization_info(conn, device_id)
    result["parent"] = _parent_info(conn, device_id)

    return result


@router.get("/devices")
def list_devices(
    request: Request,
    online: bool | None = None,
    trusted: bool | None = None,
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
            os_name,
            os_confidence,
            pos_x,
            pos_y,
            notify_offline,
            trusted,
            group_id,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
    """
    params: list[Any] = []
    conditions: list[str] = []

    if online is not None:
        conditions.append("online = ?")
        params.append(int(online))

    if trusted is not None:
        conditions.append("trusted = ?")
        params.append(int(trusted))

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
    drift = baselines.drift_counts(conn)
    result = []
    for row in rows:
        d = _device_dict(row)
        counts = drift.get(row["id"])
        # None = no baseline; otherwise how many ports differ from it
        d["ports_drift"] = None if counts is None else counts["unexpected"] + counts["missing"]
        result.append(d)
    _add_group(conn, result)
    return result


class TrustBody(BaseModel):
    ids: list[int] | None = None  # these devices; omit to apply to every device
    trusted: bool = True


@router.post("/devices/trust")
def trust_devices(body: TrustBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, int]:
    """Mark devices as known (or unknown again). Without `ids` it applies to all devices ("trust everything on my network now")."""
    value = 1 if body.trusted else 0
    if body.ids is None:
        changed = conn.execute("UPDATE devices SET trusted = ? WHERE trusted != ?", (value, value)).rowcount
    else:
        marks = ",".join("?" for _ in body.ids) or "NULL"
        changed = conn.execute(f"UPDATE devices SET trusted = ? WHERE trusted != ? AND id IN ({marks})", (value, value, *body.ids)).rowcount
    conn.commit()
    return {"changed": changed}


class BaselineBody(BaseModel):
    ids: list[int] | None = None  # these devices; omit to apply to every device
    accept: bool = True  # False removes the baseline


class GroupAssignBody(BaseModel):
    ids: list[int] | None = None  # these devices; omit to apply to every device
    group_id: int | None = None  # null takes them out of their group


@router.post("/devices/group")
def assign_group(body: GroupAssignBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, int]:
    """Put devices in a group (or none)."""
    try:
        return {"changed": groups_mod.assign(conn, body.ids, body.group_id)}
    except KeyError:
        raise HTTPException(status_code=422, detail="no such group")


@router.post("/devices/baseline")
def set_baselines(body: BaselineBody, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, int]:
    """Take the current open ports of devices as their normal ones (or forget the baseline)."""
    changed = baselines.accept(conn, body.ids) if body.accept else baselines.clear(conn, body.ids)
    return {"changed": changed}


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
            os_name,
            os_confidence,
            pos_x,
            pos_y,
            notify_offline,
            trusted,
            group_id,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="device not found")

    return _build_device_detail(conn, device_id, row)


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
            os_name,
            os_confidence,
            pos_x,
            pos_y,
            notify_offline,
            trusted,
            group_id,
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
        return _build_device_detail(conn, device_id, row)

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

    if "group_id" in fields_set:
        if body.group_id is not None and not groups_mod.exists(conn, body.group_id):
            raise HTTPException(status_code=422, detail="no such group")
        updates["group_id"] = body.group_id

    if "notify_offline" in fields_set:
        updates["notify_offline"] = 0 if body.notify_offline is False else 1

    if "trusted" in fields_set and body.trusted is not None:
        updates["trusted"] = 1 if body.trusted else 0

    if "parent_mode" in fields_set or "parent_device_id" in fields_set:
        mode = body.parent_mode
        parent_id = body.parent_device_id
        if mode is None:  # a bare parent_device_id means "use this device"; neither means automatic
            mode = "device" if parent_id is not None else "auto"
        if mode not in ("auto", "none", "device"):
            raise HTTPException(status_code=422, detail="parent_mode must be auto, none or device")
        if mode == "device":
            if parent_id is None:
                raise HTTPException(status_code=422, detail="parent_device_id is required when parent_mode is device")
            devs, hierarchy = load_hierarchy(conn)
            if parent_id == device_id:
                raise HTTPException(status_code=422, detail="a device cannot be its own parent")
            if parent_id not in devs:
                raise HTTPException(status_code=422, detail="parent device not found")
            if would_loop(hierarchy, device_id, parent_id):
                raise HTTPException(
                    status_code=422,
                    detail=f"{device_name(devs[parent_id])} sits below this device; choosing it as parent would create a loop",
                )
            updates["parent_mode"] = "device"
            updates["parent_device_id"] = parent_id
        else:
            updates["parent_mode"] = mode
            updates["parent_device_id"] = None

    if "pos_x" in fields_set:
        updates["pos_x"] = body.pos_x

    if "pos_y" in fields_set:
        updates["pos_y"] = body.pos_y

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
            os_name,
            os_confidence,
            pos_x,
            pos_y,
            notify_offline,
            trusted,
            group_id,
            (SELECT COUNT(*) FROM ports WHERE device_id = devices.id) AS open_ports
        FROM devices
        WHERE id = ?
        """,
        (device_id,),
    ).fetchone()

    return _build_device_detail(conn, device_id, row)


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: int, ignore: bool = False, conn: sqlite3.Connection = Depends(get_conn)) -> None:
    """Delete a device with its ports, names, history and links.

    With ignore=true the device is also put on the ignore list, so scans do not add it back
    (a device that is still on the network would otherwise reappear at the next scan).
    """
    row = conn.execute(
        "SELECT mac, primary_ip, hostname, custom_name FROM devices WHERE id = ?", (device_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="device not found")
    label = row["custom_name"] or row["hostname"] or row["primary_ip"] or (row["mac"] or f"device {device_id}")
    if ignore:
        if row["mac"]:
            conn.execute(
                "INSERT INTO ignored_devices (mac, ip, label, added) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(mac) WHERE mac IS NOT NULL DO UPDATE SET ip = excluded.ip, label = excluded.label",
                (row["mac"].lower(), row["primary_ip"], label, utcnow()),
            )
        elif row["primary_ip"]:
            conn.execute(
                "INSERT INTO ignored_devices (mac, ip, label, added) VALUES (NULL, ?, ?, ?) "
                "ON CONFLICT(ip) WHERE mac IS NULL DO UPDATE SET label = excluded.label",
                (row["primary_ip"], label, utcnow()),
            )
        else:
            raise HTTPException(status_code=422, detail="this device has no MAC or IP address to ignore")
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    ip = f" ({row['primary_ip']})" if row["primary_ip"] and row["primary_ip"] != label else ""
    add_event(conn, "device_deleted", f"{label}{ip} deleted" + (" and ignored" if ignore else ""))


@router.post("/devices/{device_id}/scan", status_code=202)
async def scan_device(device_id: int, request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    """Run a full scan of this one host: all TCP ports, service versions, OS detection and traceroute."""
    row = conn.execute("SELECT primary_ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="device not found")
    if not row["primary_ip"]:
        raise HTTPException(status_code=422, detail="this device has no IP address to scan")
    try:
        scan_id = await request.app.state.scan_manager.start("full", target=row["primary_ip"])
    except ScanBusy:
        raise HTTPException(status_code=409, detail="scan already running")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"id": scan_id}


def _action_target(conn: sqlite3.Connection, device_id: int):
    row = conn.execute("SELECT mac, primary_ip, custom_name, hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="device not found")
    return row


@router.post("/devices/{device_id}/wake")
def wake_device(device_id: int, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    """Send a Wake-on-LAN magic packet to the device's MAC address."""
    row = _action_target(conn, device_id)
    try:
        sent = actions.wake(row["mac"], row["primary_ip"])
    except actions.ActionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    label = row["custom_name"] or row["hostname"] or row["primary_ip"] or row["mac"]
    add_event(conn, "wake_sent", f"Wake-on-LAN sent to {label}", device_id=device_id)
    return {"ok": True, "sent_to": sent}


@router.post("/devices/{device_id}/ping")
async def ping_device(device_id: int, request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    row = _action_target(conn, device_id)
    try:
        return await actions.ping(row["primary_ip"], getattr(request.app.state, "action_runner", None))
    except actions.ActionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/devices/{device_id}/trace")
async def trace_device(device_id: int, request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    row = _action_target(conn, device_id)
    try:
        return await actions.trace(row["primary_ip"], getattr(request.app.state, "action_runner", None))
    except actions.ActionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
