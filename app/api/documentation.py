"""The network documentation (see app/documentation.py): the settings for it and the export. Administrators only: it lists addresses, MAC addresses and notes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app import documentation
from app.api.devices import get_conn
from app.auth import require_admin
from app.scanner.netinfo import detect_ranges

router = APIRouter(prefix="/api", tags=["documentation"], dependencies=[Depends(require_admin)])


class SettingsBody(BaseModel):
    company: str | None = None
    customer: str | None = None
    prepared_by: str | None = None
    contact: str | None = None
    footer: str | None = None
    accent: str | None = None
    logo: str | None = None
    sections: list[str] | None = None


@router.get("/documentation")
def get_settings(conn=Depends(get_conn)) -> dict[str, Any]:
    return {"settings": documentation.get_settings(conn), "sections": [{"id": s, "label": label} for s, label in documentation.SECTIONS]}


@router.put("/documentation")
def put_settings(body: SettingsBody, conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        return {"settings": documentation.save_settings(conn, body.model_dump(exclude_unset=True))}
    except documentation.DocError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/documentation/export", response_class=HTMLResponse)
async def export(request: Request, download: bool = False, conn=Depends(get_conn)) -> HTMLResponse:
    settings = documentation.get_settings(conn)
    ranges = list(request.app.state.settings.ranges) or await detect_ranges()
    page = documentation.render(documentation.collect(conn, ranges), settings)
    name = "".join(c if c.isalnum() else "-" for c in (settings["customer"] or "network")).strip("-").lower() or "network"
    headers = {"Content-Disposition": f'attachment; filename="{name}-network-documentation.html"'} if download else {}
    return HTMLResponse(page, headers=headers)


@router.get("/documentation/site/{probe_id}", response_class=HTMLResponse)
def export_site(probe_id: int, download: bool = False, conn=Depends(get_conn)) -> HTMLResponse:
    """The documentation of a remote site, from what the site reports; named after its customer."""
    doc = documentation.collect_site(conn, probe_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="remote site not found")
    settings = documentation.get_settings(conn)
    settings = {**settings, "customer": doc["site"]["customer"] or doc["site"]["name"], "sections": [s for s in settings["sections"] if s in ("summary", "devices", "services", "security", "points")]}
    page = documentation.render(doc, settings)
    name = "".join(c if c.isalnum() else "-" for c in doc["site"]["name"]).strip("-").lower() or "site"
    headers = {"Content-Disposition": f'attachment; filename="{name}-network-documentation.html"'} if download else {}
    return HTMLResponse(page, headers=headers)
