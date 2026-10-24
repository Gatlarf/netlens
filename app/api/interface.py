"""Interface settings (Settings → Interface): the look of Netlens for everybody. Reading is open to every signed-in user; changing needs an administrator."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import interface_settings
from app.api.devices import get_conn
from app.auth import require_admin

router = APIRouter(prefix="/api", tags=["interface"])


@router.get("/interface")
def get_interface(conn=Depends(get_conn)) -> dict:
    return {"settings": interface_settings.get(conn), "defaults": interface_settings.DEFAULTS, "choices": {k: list(v) for k, v in interface_settings.CHOICES.items()}}


class InterfaceBody(BaseModel):
    default_look: str | None = None
    pulse_seconds: float | None = None
    pulse_scope: str | None = None
    pulse_for: str | None = None
    hud_sweep: bool | None = None
    hud_lines: bool | None = None


@router.put("/interface")
def put_interface(body: InterfaceBody, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    try:
        return {"settings": interface_settings.save(conn, body.model_dump(exclude_unset=True))}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
