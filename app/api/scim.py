"""SCIM 2.0 (app/scim.py): the provisioning endpoints the identity provider calls (/scim/v2, own bearer token) and the administrator's settings (/api/scim)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import audit, licence, scim
from app.api.devices import get_conn
from app.auth import LoginLimiter, client_ip, identify, require_admin
from app.db import connect

CONTENT = "application/scim+json"
router = APIRouter(prefix="/scim/v2", tags=["scim"])
admin = APIRouter(prefix="/api", tags=["scim"])


def _reply(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, media_type=CONTENT)


def _error(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
    return _reply({"schemas": [scim.ERROR_SCHEMA], "status": str(status), "detail": detail, **({"scimType": scim_type} if scim_type else {})}, status)


def _db_for(request: Request, action: str):
    """The connection, once the bearer token has been checked (a wrong one is counted against the address like a wrong password)."""
    limiter: LoginLimiter = request.app.state.login_limiter
    host = client_ip(request)
    if not limiter.allowed(host):
        raise _Refused(429, "too many attempts")
    conn = connect(request.app.state.db_path)
    header = request.headers.get("authorization") or ""
    if not scim.authenticate(conn, header[7:] if header.startswith("Bearer ") else None, host):
        conn.close()
        limiter.record_failure(host)
        raise _Refused(401, "a valid SCIM token is needed")
    return conn


class _Refused(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status, self.detail = status, detail


def _run(request: Request, action: str, work) -> JSONResponse:
    try:
        conn = _db_for(request, action)
    except _Refused as exc:
        return _error(exc.status, exc.detail)
    try:
        data, status = work(conn)
        audit.record(conn, "scim", "system", client_ip(request), request.method, request.url.path[:200], status, f"SCIM: {action}")
        return _reply(data, status) if data is not None else JSONResponse(None, status_code=status, media_type=CONTENT)
    except scim.ScimError as exc:
        audit.record(conn, "scim", "system", client_ip(request), request.method, request.url.path[:200], exc.status, f"SCIM refused: {action} ({exc.detail[:100]})")
        return _error(exc.status, exc.detail, exc.scim_type)
    finally:
        conn.close()


async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        raise scim.ScimError(400, "the body is not JSON", "invalidSyntax") from None
    if not isinstance(body, dict):
        raise scim.ScimError(400, "the body must be a JSON object", "invalidSyntax")
    return body


@router.get("/ServiceProviderConfig")
def provider_config(request: Request) -> JSONResponse:
    return _run(request, "read the service provider configuration", lambda c: ({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"], "patch": {"supported": True}, "bulk": {"supported": False}, "filter": {"supported": True, "maxResults": 100},
        "changePassword": {"supported": False}, "sort": {"supported": False}, "etag": {"supported": False},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "description": "the SCIM token from Netlens (Settings -> Provisioning)"}]}, 200))


@router.get("/ResourceTypes")
def resource_types(request: Request) -> JSONResponse:
    return _run(request, "read the resource types", lambda c: ({"schemas": [scim.LIST_SCHEMA], "totalResults": 1, "Resources": [
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/Users", "schema": scim.USER_SCHEMA}]}, 200))


@router.get("/Schemas")
def schemas(request: Request) -> JSONResponse:
    return _run(request, "read the schemas", lambda c: ({"schemas": [scim.LIST_SCHEMA], "totalResults": 1, "Resources": [{"id": scim.USER_SCHEMA, "name": "User"}]}, 200))


@router.get("/Users")
def list_users(request: Request, filter: str = "", startIndex: int = 1, count: int = 100) -> JSONResponse:
    return _run(request, "listed the accounts it manages", lambda c: (scim.listing(c, filter, startIndex, count), 200))


@router.post("/Users")
async def create_user(request: Request) -> JSONResponse:
    try:
        body = await _json(request)
    except scim.ScimError as exc:
        return _error(exc.status, exc.detail, exc.scim_type)

    def work(c):
        made = scim.create(c, body, licence.allows(c, "privileged"))
        return made, 201

    return _run(request, f"created the account {str(body.get('userName', ''))[:60]!r}", work)


@router.get("/Users/{user_id}")
def get_user(user_id: str, request: Request) -> JSONResponse:
    return _run(request, f"read the account {user_id[:12]}", lambda c: (scim.resource(scim._managed(c, user_id)), 200))


@router.put("/Users/{user_id}")
async def put_user(user_id: str, request: Request) -> JSONResponse:
    try:
        body = await _json(request)
    except scim.ScimError as exc:
        return _error(exc.status, exc.detail, exc.scim_type)
    return _run(request, f"changed the account {user_id[:12]}", lambda c: (scim.replace(c, user_id, body), 200))


@router.patch("/Users/{user_id}")
async def patch_user(user_id: str, request: Request) -> JSONResponse:
    try:
        body = await _json(request)
    except scim.ScimError as exc:
        return _error(exc.status, exc.detail, exc.scim_type)
    return _run(request, f"changed the account {user_id[:12]}", lambda c: (scim.patch(c, user_id, body), 200))


@router.delete("/Users/{user_id}")
def delete_user(user_id: str, request: Request) -> JSONResponse:
    def work(c):
        scim.delete(c, user_id)
        return None, 204

    return _run(request, f"removed the account {user_id[:12]}", work)


# ----------------------------------------------------------------------------- the administrator's side
class ConfigBody(BaseModel):
    enabled: bool | None = None
    role: str | None = None
    networks: list[str] | None = None


class TokenBody(BaseModel):
    name: str = "identity provider"


def _need(conn) -> None:
    if not licence.allows(conn, "privileged"):
        raise HTTPException(status_code=402, detail="provisioning by SCIM is part of the Enterprise edition (or the free trial)")


@admin.get("/scim")
def scim_status(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return {**scim.public(conn), "allowed": licence.allows(conn, "privileged"), "address": str(request.base_url).rstrip("/") + "/scim/v2"}


@admin.put("/scim")
def scim_configure(body: ConfigBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need(conn)
    try:
        done = scim.configure(conn, body.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    audit.record_by(conn, identify(request), client_ip(request), "PUT", request.url.path, 200, f"Changed provisioning by SCIM (enabled: {done['enabled']}, default role: {done['role']})")
    return {**done, "allowed": True}


@admin.post("/scim/token")
def scim_token(body: TokenBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need(conn)
    token = scim.new_token(conn, body.name)
    audit.record_by(conn, identify(request), client_ip(request), "POST", request.url.path, 200, "Made a new SCIM token (the old one stopped working; the token is shown once and never logged)")
    return {"token": token, **scim.public(conn)}


@admin.delete("/scim/token")
def scim_revoke(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    scim.revoke_token(conn)
    audit.record_by(conn, identify(request), client_ip(request), "DELETE", request.url.path, 200, "Revoked the SCIM token and switched provisioning off")
    return scim.public(conn)
