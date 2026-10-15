"""What changed: events and, for administrators, the changes people made (see app/changes.py)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app import changes
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["changes"])


@router.get("/changes")
def list_changes(request: Request, period: str = Query("24h", pattern="^(6h|24h|3d|7d|30d)$"), category: str = "", limit: int = Query(300, ge=1, le=1000),
                 conn=Depends(get_conn)) -> dict:
    user = getattr(request.state, "user", None)
    return changes.timeline(conn, period, category, include_audit=bool(user and user.role == "admin"), limit=limit)
