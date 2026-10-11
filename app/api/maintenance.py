"""Maintenance windows: list, create, change, delete, and 'start one now' for the device page."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import maintenance as m
from app.db import connect

router = APIRouter(prefix="/api", tags=["maintenance"])


def _public(conn, window: dict, now: datetime) -> dict:
    end = m.current_end(window, now)
    nxt = m.next_start(window, now)
    return {**window, "summary": m.describe_schedule(window), "active": end is not None,
            "ends": end.strftime(m.STAMP) if end else None, "next": nxt.strftime(m.STAMP) if nxt else None,
            "devices_covered": len(m.device_ids(conn, window))}


def _overview(conn) -> dict:
    now = datetime.now(timezone.utc)
    return {"windows": [_public(conn, w, now) for w in m.load_windows(conn)], "now": now.strftime(m.STAMP)}


class WindowBody(BaseModel):
    name: str = ""
    enabled: bool = True
    scope: dict = Field(default_factory=dict)
    schedule: dict = Field(default_factory=dict)
    tz: str = "UTC"
    offset_min: int = 0


@router.get("/maintenance")
def get_windows(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _overview(conn)
    finally:
        conn.close()


@router.post("/maintenance", status_code=201)
def create_window(body: WindowBody, request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            window = m.clean_window(body.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        m.save_windows(conn, m.load_windows(conn) + [window])
        return _overview(conn)
    finally:
        conn.close()


@router.put("/maintenance/{window_id}")
def update_window(window_id: str, body: WindowBody, request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        windows = m.load_windows(conn)
        index = next((i for i, w in enumerate(windows) if w["id"] == window_id), None)
        if index is None:
            raise HTTPException(status_code=404, detail="no such maintenance window")
        try:
            windows[index] = m.clean_window(body.model_dump(), windows[index])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        m.save_windows(conn, windows)
        return _overview(conn)
    finally:
        conn.close()


@router.delete("/maintenance/{window_id}")
def delete_window(window_id: str, request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        windows = m.load_windows(conn)
        if not any(w["id"] == window_id for w in windows):
            raise HTTPException(status_code=404, detail="no such maintenance window")
        m.save_windows(conn, [w for w in windows if w["id"] != window_id])
        return _overview(conn)
    finally:
        conn.close()


class NowBody(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=50)
    minutes: int = Field(ge=5, le=60 * 24 * 7)
    behind: bool = False


@router.post("/maintenance/now", status_code=201)
def start_now(body: NowBody, request: Request) -> dict:
    """A one-time window that starts now, for the device page's quick button."""
    conn = connect(request.app.state.db_path)
    try:
        names = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
        missing = [d for d in body.device_ids if d not in names]
        if missing:
            raise HTTPException(status_code=404, detail="unknown device")
        start = datetime.now(timezone.utc).replace(microsecond=0)
        label = names[body.device_ids[0]] + (f" and {len(body.device_ids) - 1} more" if len(body.device_ids) > 1 else "")
        window = m.clean_window({"name": f"Manual: {label}", "scope": {"devices": body.device_ids, "behind": body.behind},
                                 "schedule": {"type": "once", "start": start.strftime(m.STAMP), "end": (start + timedelta(minutes=body.minutes)).strftime(m.STAMP)},
                                 "manual": True})
        m.save_windows(conn, m.load_windows(conn) + [window])
        return _overview(conn)
    finally:
        conn.close()
