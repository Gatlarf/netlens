"""Card layouts: a user's own, and the templates an administrator pushes to everybody (per device type)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import layouts
from app.api.devices import get_conn
from app.auth import require_admin

router = APIRouter(prefix="/api/layouts", tags=["layouts"])


def _guard(call):
    try:
        return call()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/{page}")
def get_layout(page: str, request: Request, type: str = "*", conn=Depends(get_conn)) -> dict:
    return _guard(lambda: layouts.resolve(conn, request.state.user, page, type))


@router.put("/{page}/mine")
def put_mine(page: str, request: Request, body: dict[str, Any], type: str = "*", conn=Depends(get_conn)) -> dict:
    return _guard(lambda: layouts.save_mine(conn, request.state.user, page, type, body))


@router.delete("/{page}/mine")
def delete_mine(page: str, request: Request, type: str = "*", conn=Depends(get_conn)) -> dict:
    _guard(lambda: layouts.reset_mine(conn, request.state.user, page, type))
    return {"ok": True}


@router.get("/{page}/templates", dependencies=[Depends(require_admin)])
def list_templates(page: str, conn=Depends(get_conn)) -> dict:
    return {"types": layouts.templates(conn, page)}


@router.put("/{page}/template", dependencies=[Depends(require_admin)])
def put_template(page: str, body: dict[str, Any], type: str = "*", conn=Depends(get_conn)) -> dict:
    return _guard(lambda: layouts.save_template(conn, page, type, body))


@router.delete("/{page}/template", dependencies=[Depends(require_admin)])
def delete_template(page: str, type: str = "*", conn=Depends(get_conn)) -> dict:
    _guard(lambda: layouts.reset_template(conn, page, type))
    return {"ok": True}
