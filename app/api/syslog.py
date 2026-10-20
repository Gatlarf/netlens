"""Scans & events → System log: the application's own log (see app/syslog.py). Administrators only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import PlainTextResponse

from app import syslog

router = APIRouter(prefix="/api/system-log", tags=["system-log"])


@router.get("")
def get_log(request: Request, level: str = Query("info"), q: str = Query("", max_length=100), limit: int = Query(300, ge=1, le=2000)) -> dict[str, Any]:
    return syslog.entries(request.app.state.settings.data_dir, level=level, query=q, limit=limit)


@router.get("/download")
def download(request: Request) -> PlainTextResponse:
    return PlainTextResponse(syslog.download(request.app.state.settings.data_dir), media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": 'attachment; filename="netlens.log"'})
