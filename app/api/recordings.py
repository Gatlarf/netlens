"""Terminal session recordings (app/recordings.py). Administrators only; watching or downloading is an audit line and, with step-up on, needs a fresh confirmation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app import audit, recordings, secpolicy
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin

router = APIRouter(prefix="/api", tags=["recordings"])


def _note(request: Request, conn, text: str) -> None:
    audit.record_by(conn, identify(request), client_ip(request), request.method, request.url.path, 200, text)


@router.get("/recordings")
def list_recordings(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    pol = secpolicy.get(conn)
    return {"recordings": recordings.listing(conn), "enabled": pol["record_sessions"], "days": pol["recording_days"]}


@router.get("/recordings/{rec_id}")
def watch(rec_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        rec = recordings.get(conn, request.app.state.settings.data_dir, rec_id)
    except recordings.RecordingError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    _note(request, conn, f"Watched the recording #{rec_id} ({rec['user']} on {rec['device']})")
    return rec


@router.get("/recordings/{rec_id}/download")
def download(rec_id: int, request: Request, conn=Depends(get_conn)) -> PlainTextResponse:
    require_admin(request)
    try:
        text = recordings.asciicast(conn, request.app.state.settings.data_dir, rec_id)
    except recordings.RecordingError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    _note(request, conn, f"Downloaded the recording #{rec_id}")
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="netlens-session-{rec_id}.cast"'})


@router.delete("/recordings/{rec_id}")
def remove(rec_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if not recordings.delete(conn, request.app.state.settings.data_dir, rec_id):
        raise HTTPException(status_code=404, detail="no such recording")
    _note(request, conn, f"Deleted the recording #{rec_id}")
    return {"deleted": True}
