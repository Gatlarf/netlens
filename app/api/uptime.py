from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.devices import get_conn
from app.uptime import device_uptime, uptime_overview

router = APIRouter(prefix="/api", tags=["uptime"])


@router.get("/uptime")
def get_uptime_overview(bars: int = Query(60, ge=1, le=240), conn=Depends(get_conn)) -> list[dict]:
    """Per-device heartbeat bars and 24h/7d uptime, like Uptime Kuma's dashboard."""
    return uptime_overview(conn, bars=bars)


@router.get("/devices/{device_id}/uptime")
def get_device_uptime(
    device_id: int,
    limit: int = Query(60, ge=1, le=500),
    conn=Depends(get_conn),
) -> dict:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device_uptime(conn, device_id, limit=limit)
