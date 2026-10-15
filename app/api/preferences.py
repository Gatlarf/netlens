"""The signed-in user's own preferences (the page to start on)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import preferences
from app.api.devices import get_conn

router = APIRouter(prefix="/api/me", tags=["preferences"])


class PreferencesBody(BaseModel):
    start_page: str | None = None


@router.get("/preferences")
def get_preferences(request: Request, conn=Depends(get_conn)) -> dict:
    return {**preferences.get(conn, request.state.user), "start_pages": preferences.options(request.state.user)}


@router.put("/preferences")
def put_preferences(body: PreferencesBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        saved = preferences.set_start_page(conn, request.state.user, body.start_page)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {**saved, "start_pages": preferences.options(request.state.user)}
