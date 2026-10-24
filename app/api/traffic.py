"""The combined traffic of the monitored devices and the WAN line (see app/traffic.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app import interface_settings, traffic
from app.api.devices import get_conn
from app.auth import scope_of

router = APIRouter(prefix="/api", tags=["traffic"])


@router.get("/traffic")
def get_traffic(request: Request, range: str = Query("1h"), mode: str = Query("all"), conn=Depends(get_conn)) -> dict:
    """In and out bandwidth of all monitored devices combined and of the internet connection, `range` 1h, 6h, 24h or 7d, points [unix time, bits per second]. `mode=all` (default) adds up every interface of every monitored device; `mode=endpoints` leaves out switches, routers, access points and virtual interfaces so the same traffic is not counted twice."""
    if scope_of(request) is not None:
        raise HTTPException(status_code=403, detail="the traffic of the whole network is not part of a customer view")
    if range not in traffic.RANGES:
        raise HTTPException(status_code=422, detail=f"range must be one of {', '.join(traffic.RANGES)}")
    if mode not in ("all", "endpoints"):
        raise HTTPException(status_code=422, detail="mode must be all or endpoints")
    chosen = interface_settings.get(conn)["wan"]
    wan = (int(chosen.split("|", 1)[0]), chosen.split("|", 1)[1]) if chosen else None
    return traffic.build(conn, range, wan, mode=mode)
