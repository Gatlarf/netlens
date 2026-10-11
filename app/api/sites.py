"""Sites a reverse proxy plugin publishes (Nginx Proxy Manager ...): the list, for the plugin card and the device pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import sites
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["sites"])


@router.get("/sites")
def list_sites(device_id: int | None = None, conn=Depends(get_conn)) -> dict:
    return {"sites": sites.list_sites(conn, device_id), "summary": sites.summary(conn)}
