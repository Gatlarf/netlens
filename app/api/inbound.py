"""Settings for the SNMP trap and syslog listeners (see app/inbound.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app import inbound
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["inbound"])


def _receiver(request: Request):
    receiver = getattr(request.app.state, "inbound", None)
    if receiver is None:
        raise HTTPException(status_code=404, detail="receiving traps and syslog is not available here")
    return receiver


@router.get("/inbound")
def get_inbound(request: Request, conn=Depends(get_conn)) -> dict:
    """Policy and status of the SNMP trap and syslog listeners."""
    return _receiver(request).status(conn)


@router.put("/inbound")
async def put_inbound(body: dict, request: Request, conn=Depends(get_conn)) -> dict:
    """Save the policy and start, stop or move the listeners to match it."""
    receiver = _receiver(request)
    try:
        inbound.save_policy(conn, body)
    except inbound.InboundError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    await receiver.apply()
    return receiver.status(conn)
