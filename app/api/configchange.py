"""What changed in the settings of a router, firewall or controller (see app/configchange.py). Administrators only: rules and port forwards are sensitive."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import audit, configadvice, configchange
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


class AcceptBody(BaseModel):
    reason: str = ""


def _device(conn, device_id: int) -> None:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="no such device")


@router.get("/devices/{device_id}/config/advice")
def device_advice(device_id: int, request: Request, conn=Depends(get_conn)) -> dict:
    """The recommendations from the rules, the accepted ones, and the last review of the language model."""
    require_admin(request)
    _device(conn, device_id)
    advice = configadvice.for_device(conn, device_id)
    if advice is None:
        return {"plugin": None}
    from app import insights

    return {**advice, "review": configadvice.last_review(conn, device_id), "review_available": bool(insights.allowed(conn) and insights.llm_ready(conn))}


@router.put("/devices/{device_id}/config/advice/{finding_id:path}")
def accept_finding(device_id: int, finding_id: str, body: AcceptBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Accept a finding with a reason: it leaves the problem list and stays visible on the device."""
    require_admin(request)
    _device(conn, device_id)
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=422, detail="say why this is intended")
    advice = configadvice.for_device(conn, device_id) or {}
    if finding_id not in {x["id"] for x in advice.get("findings", []) + advice.get("accepted", [])}:
        raise HTTPException(status_code=404, detail="no such finding")
    configadvice.accept(conn, device_id, finding_id, reason, getattr(getattr(request.state, "user", None), "username", "") or "an admin")
    return configadvice.for_device(conn, device_id)


@router.delete("/devices/{device_id}/config/advice/{finding_id:path}")
def unaccept_finding(device_id: int, finding_id: str, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    _device(conn, device_id)
    configadvice.unaccept(conn, device_id, finding_id)
    return configadvice.for_device(conn, device_id) or {"plugin": None}


@router.post("/devices/{device_id}/config/review")
def review_config(device_id: int, request: Request, force: bool = False, conn=Depends(get_conn)) -> dict:
    """Ask the language model for a second opinion (Settings → AI must be set up). The settings are sent through the same anonymiser as every other question to the model."""
    require_admin(request)
    _device(conn, device_id)
    try:
        result = configadvice.review(conn, device_id, force=force)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return result


@router.get("/config-advice")
def all_advice(request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    return {"findings": configadvice.attention(conn)}
