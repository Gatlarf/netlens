from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.api.devices import get_conn
from app.auth import scope_of
import sqlite3


router = APIRouter(prefix="/api", tags=["events"])


class EventDict(BaseModel):
    id: int
    ts: str
    device_id: int | None
    kind: str
    detail: str | None
    maintenance: str | None = None      # the maintenance window that held this event back
    device: str | None = None           # the name of the device (its custom name, host name or address)


@router.get("/events", response_model=list[EventDict])
def list_events(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    kind: str | None = None,
    device_id: int | None = None,
    since_id: int | None = Query(None, ge=0, description="only events newer than this id (for integrations that poll)"),
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []

    if kind is not None:
        conditions.append("e.kind = ?")
        params.append(kind)

    if device_id is not None:
        conditions.append("e.device_id = ?")
        params.append(device_id)

    if since_id is not None:
        conditions.append("e.id > ?")
        params.append(since_id)

    scope = scope_of(request)
    if scope is not None:                  # a customer view: only events of the devices in its groups
        conditions.append(f"e.device_id IN (SELECT id FROM devices WHERE group_id IN ({','.join('?' * len(scope))}))")
        params.extend(scope)

    query = ("SELECT e.id, e.ts, e.device_id, e.kind, e.detail, e.maintenance, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS device "
             "FROM events e LEFT JOIN devices d ON d.id = e.device_id")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY e.id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]