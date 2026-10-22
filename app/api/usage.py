"""The switch for application statistics, and the applications one device used (see app/usagecfg.py). Administrators only."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import usagecfg
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["statistics"])


class UsageBody(BaseModel):
    enabled: bool


@router.get("/usage")
def state(conn=Depends(get_conn)) -> dict:
    return {"enabled": usagecfg.enabled(conn), "stored_rows": usagecfg.stored_rows(conn)}


@router.put("/usage")
def change(body: UsageBody, request: Request, conn=Depends(get_conn)) -> dict:
    removed = usagecfg.set_enabled(conn, body.enabled)
    request.app.state.__dict__.setdefault("stats_cache", {}).clear()
    return {"enabled": body.enabled, "removed_rows": removed}


@router.get("/devices/{device_id}/applications")
def device_applications(device_id: int, days: int = Query(7, ge=1, le=90), conn=Depends(get_conn)) -> dict:
    """What one device used over the last `days` days: traffic per application (when the router can say so), and per day."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    if not usagecfg.enabled(conn):
        return {"enabled": False, "available": False}
    last = conn.execute("SELECT MAX(day) FROM client_usage WHERE device_id = ?", (device_id,)).fetchone()[0]
    if last is None:
        return {"enabled": True, "available": False}
    first = (datetime.strptime(last, "%Y-%m-%d") - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    per_day = conn.execute(
        "SELECT day, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM client_usage WHERE device_id = ? AND day >= ? GROUP BY day ORDER BY day", (device_id, first)).fetchall()
    apps = conn.execute(
        "SELECT name, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM client_app_usage WHERE device_id = ? AND day >= ? GROUP BY name "
        "ORDER BY SUM(rx_bytes) + SUM(tx_bytes) DESC LIMIT 25", (device_id, first)).fetchall()
    listed = conn.execute("SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) FROM client_app_usage WHERE device_id = ? AND day >= ?", (device_id, first)).fetchone()[0]
    return {
        "enabled": True, "available": True, "from": first, "to": last, "days": len(per_day),
        "rx": sum(r["rx"] for r in per_day), "tx": sum(r["tx"] for r in per_day),
        "per_day": [{"day": r["day"], "rx": r["rx"], "tx": r["tx"]} for r in per_day],
        "applications": [{"name": r["name"], "rx": r["rx"], "tx": r["tx"], "share": round(100 * (r["rx"] + r["tx"]) / listed, 1) if listed else 0} for r in apps],
    }
