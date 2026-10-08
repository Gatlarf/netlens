from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.devices import get_conn
import sqlite3


router = APIRouter(prefix="/api", tags=["events"])


class EventDict(BaseModel):
    id: int
    ts: str
    device_id: int | None
    kind: str
    detail: str | None


@router.get("/events", response_model=list[EventDict])
def list_events(
    limit: int = Query(100, ge=1, le=500),
    kind: str | None = None,
    device_id: int | None = None,
    since_id: int | None = Query(None, ge=0, description="only events newer than this id (for integrations that poll)"),
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []

    if kind is not None:
        conditions.append("kind = ?")
        params.append(kind)

    if device_id is not None:
        conditions.append("device_id = ?")
        params.append(device_id)

    if since_id is not None:
        conditions.append("id > ?")
        params.append(since_id)

    query = "SELECT id, ts, device_id, kind, detail FROM events"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]