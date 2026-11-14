"""Sites a reverse proxy plugin publishes (Nginx Proxy Manager ...): the list, for the plugin card and the device pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import sites
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["sites"])


@router.get("/sites")
def list_sites(device_id: int | None = None, conn=Depends(get_conn)) -> dict:
    return {"sites": sites.list_sites(conn, device_id), "summary": sites.summary(conn)}


class RestoreBody(BaseModel):
    plugin_id: str
    proxy_id: str = ""
    site_id: str


@router.post("/sites/check")
def restore_site_check(body: RestoreBody, conn=Depends(get_conn)) -> dict:
    """Bring back the service check of a site that was deleted (a plugin's sync does not make it again by itself)."""
    if not sites.restore_check(conn, body.plugin_id, body.proxy_id, body.site_id):
        raise HTTPException(status_code=404, detail="this site cannot have a check")
    return {"restored": True}
