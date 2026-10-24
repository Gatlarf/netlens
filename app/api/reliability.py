"""Reliability figures (outages, time to recover, availability against a target, alert quality)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import reliability
from app.api.devices import get_conn
from app.auth import require_admin

router = APIRouter(prefix="/api", tags=["reliability"])


@router.get("/reliability")
def get_reliability(days: int = 30, conn=Depends(get_conn)) -> dict:
    return reliability.build(conn, days)


class TargetBody(BaseModel):
    target: float


@router.put("/reliability/target")
def put_target(body: TargetBody, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    try:
        return {"target": reliability.set_target(conn, body.target)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
