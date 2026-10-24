from typing import Literal

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.devices import get_conn
from app.api.stats import _cached
from app.auth import devices_in_scope, scope_of
from app.db import connect
from app.uptime import RANGES, core_choices, device_uptime, set_core, uptime_overview

router = APIRouter(prefix="/api", tags=["uptime"])


@router.get("/uptime/latest")
def get_uptime_latest(request: Request, conn=Depends(get_conn)) -> list[dict]:
    """The response time right now of every device that answered a check in the last half hour (the average of its last three checks), for views that move
    with it, such as the radar of the HUD. {id, rtt_ms, up, ts}; a device whose latest check failed has up false and no rtt_ms."""
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    latest: dict[int, list] = {}
    for r in conn.execute("SELECT device_id, ts, up, rtt_ms FROM checks WHERE ts >= ? ORDER BY ts", (since,)):
        latest.setdefault(r["device_id"], []).append(r)
    scope = scope_of(request)
    allowed = devices_in_scope(conn, scope) if scope is not None else None
    out = []
    for device_id, rows in latest.items():
        if allowed is not None and device_id not in allowed:
            continue
        last = rows[-1]
        times = [r["rtt_ms"] for r in rows[-3:] if r["up"] and r["rtt_ms"] is not None]
        out.append({"id": device_id, "up": bool(last["up"]), "rtt_ms": round(sum(times) / len(times), 2) if last["up"] and times else None, "ts": last["ts"]})
    return out


@router.get("/uptime")
def get_uptime_overview(request: Request, bars: int = Query(60, ge=1, le=240), range: Literal["24h", "7d", "30d"] | None = None) -> list[dict]:
    """Per-device heartbeat bars and 24h/7d/30d uptime, like Uptime Kuma's dashboard. With `range` each bar is a slice of that period with its
    time and response time (what the page uses); without it the bars are the last checks as 1/0."""
    def build():
        conn = connect(request.app.state.db_path)
        try:
            return uptime_overview(conn, bars=bars, days=RANGES[range] if range else None)
        finally:
            conn.close()

    result = _cached(request, ("uptime", request.app.state.db_path, range, bars), build)
    scope = scope_of(request)
    if scope is not None:                      # a customer view: only the devices of its groups
        conn = connect(request.app.state.db_path)
        try:
            allowed = devices_in_scope(conn, scope)
        finally:
            conn.close()
        result = [r for r in result if r.get("id") in allowed]
    return result


@router.get("/devices/{device_id}/uptime")
def get_device_uptime(
    device_id: int,
    limit: int = Query(60, ge=1, le=500),
    range: Literal["24h", "7d", "30d"] | None = None,
    conn=Depends(get_conn),
) -> dict:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device_uptime(conn, device_id, limit=limit, days=RANGES[range] if range else None)


@router.get("/uptime/core")
def get_core(conn=Depends(get_conn)) -> dict:
    """Every device with whether it is marked always-on, plus Netlens's suggestions."""
    return {"devices": core_choices(conn)}


class CoreBody(BaseModel):
    device_ids: list[int] = Field(max_length=5000)


@router.put("/uptime/core")
def put_core(body: CoreBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Mark exactly these devices as always-on (an administrator; viewers are refused by the role filter)."""
    count = set_core(conn, body.device_ids)
    request.app.state.__dict__.get("stats_cache", {}).clear()      # the pages show the new choice at once
    return {"count": count}
