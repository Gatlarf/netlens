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
