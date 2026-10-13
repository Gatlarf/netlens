from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.devices import get_conn
from app.api.stats import _cached
from app.db import connect
from app.uptime import RANGES, device_uptime, uptime_overview

router = APIRouter(prefix="/api", tags=["uptime"])


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

    return _cached(request, ("uptime", request.app.state.db_path, range, bars), build)


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
