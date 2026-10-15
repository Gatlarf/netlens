"""Acknowledge and snooze (see app/snooze.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import snooze
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["snooze"])


class SnoozeBody(BaseModel):
    subject: str
    minutes: int
    note: str = ""


@router.get("/snoozes")
def list_snoozes(conn=Depends(get_conn)) -> dict:
    return {"snoozes": list(snooze.active(conn).values())}


@router.post("/snoozes", status_code=201)
def create_snooze(body: SnoozeBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        entry = snooze.snooze(conn, body.subject, body.minutes, by=getattr(request.state.user, "username", ""), note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    from app.api.stats import _cache_clear

    _cache_clear(request)
    return entry


@router.delete("/snoozes")
def delete_snooze(subject: str, request: Request, conn=Depends(get_conn)) -> dict:
    if not snooze.clear(conn, subject):
        raise HTTPException(status_code=404, detail="that is not snoozed")
    from app.api.stats import _cache_clear

    _cache_clear(request)
    return {"cleared": subject}
