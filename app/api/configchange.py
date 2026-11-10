"""What changed in the settings of a router, firewall or controller (see app/configchange.py). Administrators only: rules and port forwards are sensitive."""

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit, configchange
from app.api.devices import get_conn
from app.auth import client_ip, require_admin

router = APIRouter(prefix="/api", tags=["configchange"])


@router.get("/devices/{device_id}/config")
def device_config(device_id: int, request: Request, limit: int = 50, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="no such device")
    audit.record_read(conn, getattr(request.state, "user", None), client_ip(request), request.url.path, f"Viewed the configuration changes of device {device_id}")
    return configchange.for_device(conn, device_id, limit) or {"plugin": None, "updated": None, "items": 0, "changes": []}


@router.get("/config-changes")
def recent_changes(request: Request, days: int = 7, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    return {"changes": configchange.recent(conn, days)}
