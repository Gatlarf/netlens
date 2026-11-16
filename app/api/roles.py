"""Custom roles (app/roles.py). Administrators only; creating and changing roles is part of the Enterprise edition (or the trial)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import licence, roles
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["roles"])


class RoleBody(BaseModel):
    name: str
    base: str = "viewer"
    grants: list[str] = []


def _need(conn) -> None:
    if not licence.allows(conn, "privileged"):
        raise HTTPException(status_code=402, detail="custom roles are part of the Enterprise edition (or the free trial)")


@router.get("/roles")
def list_roles(conn=Depends(get_conn)) -> dict[str, Any]:
    return {**roles.public(conn), "allowed": licence.allows(conn, "privileged")}


class StartPagesBody(BaseModel):
    role: str
    page: str | None = None


def _start_pages(conn) -> dict[str, Any]:
    from app import preferences

    rows = [{"key": "admin", "label": "Administrator", "base": "admin"}, {"key": "operator", "label": "Operator", "base": "operator"}, {"key": "viewer", "label": "Viewer", "base": "viewer"},
            *[{"key": r["id"], "label": r["name"], "base": r["base"]} for r in roles.load(conn)]]
    return {"roles": rows, "pages": [{"value": k, "label": label, "admin_only": only} for k, (label, only) in preferences.START_PAGES.items()], "start_pages": preferences.role_pages(conn)}


@router.get("/roles/start-pages")
def get_start_pages(conn=Depends(get_conn)) -> dict[str, Any]:
    """Where each role lands after signing in (until the person chooses their own page under My account)."""
    return _start_pages(conn)


@router.put("/roles/start-pages")
def put_start_page(body: StartPagesBody, conn=Depends(get_conn)) -> dict[str, Any]:
    from app import preferences

    try:
        preferences.set_role_page(conn, body.role, body.page)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return _start_pages(conn)


@router.post("/roles", status_code=201)
def create_role(body: RoleBody, conn=Depends(get_conn)) -> dict[str, Any]:
    _need(conn)
    try:
        roles.save(conn, body.name, body.base, body.grants)
    except roles.RoleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {**roles.public(conn), "allowed": True}


@router.put("/roles/{role_id}")
def change_role(role_id: str, body: RoleBody, conn=Depends(get_conn)) -> dict[str, Any]:
    _need(conn)
    try:
        roles.save(conn, body.name, body.base, body.grants, role_id)
    except roles.RoleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {**roles.public(conn), "allowed": True}


@router.delete("/roles/{role_id}")
def delete_role(role_id: str, conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        roles.delete(conn, role_id)
    except roles.RoleError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return {**roles.public(conn), "allowed": licence.allows(conn, "privileged")}
