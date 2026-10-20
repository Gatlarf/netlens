"""The MCP endpoint (POST /mcp) and its settings (/api/mcp). See app/mcp.py."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from app import assistant, licence, mcp
from app.api.devices import get_conn
from app.auth import identify
from app.db import connect
from app.version import VERSION

router = APIRouter(prefix="/api", tags=["mcp"])
endpoint = APIRouter(tags=["mcp"])          # /mcp itself: it checks the token on its own (a browser session is not accepted)


class McpSettings(BaseModel):
    enabled: bool | None = None
    allow_changes: bool | None = None
    disabled_groups: list[str] | None = None
    rate_per_minute: int | None = None


@router.get("/mcp")
def get_mcp(request: Request, conn=Depends(get_conn)) -> dict:
    settings = mcp.get_settings(conn)
    rows = conn.execute("SELECT COUNT(*) AS n FROM api_tokens WHERE assistant IS NOT NULL").fetchone()
    base = f"{request.headers.get('x-forwarded-proto') or request.url.scheme}://{request.headers.get('x-forwarded-host') or request.headers.get('host') or request.url.netloc}"
    return {**settings, "url": base + "/mcp", "groups": mcp.catalogue(), "tokens": rows["n"], "change_allowed": licence.allows(conn, "assistant"), "version": VERSION,
            "protocols": list(mcp.PROTOCOLS), "default_rate": mcp.DEFAULT_RATE}


@router.put("/mcp")
def put_mcp(body: McpSettings, conn=Depends(get_conn)) -> dict:
    try:
        mcp.set_settings(conn, body.enabled, body.allow_changes, body.disabled_groups, body.rate_per_minute)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return get_mcp_dict(conn)


def get_mcp_dict(conn) -> dict:
    return {**mcp.get_settings(conn), "groups": mcp.catalogue()}


def _rpc_error(status: int, code: int, text: str, headers: dict | None = None) -> Response:
    return Response(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": text}}), status_code=status, media_type="application/json", headers=headers)


@endpoint.api_route("/mcp", methods=["GET", "DELETE"], include_in_schema=False)
def mcp_no_stream() -> Response:
    """This server never starts a message stream and keeps no session: say so, as the specification asks."""
    return Response(status_code=405, headers={"Allow": "POST"})


@endpoint.post("/mcp", include_in_schema=False)
async def mcp_post(request: Request) -> Response:
    db = connect(request.app.state.db_path)
    try:
        settings = mcp.get_settings(db)
    finally:
        db.close()
    if not settings["enabled"]:
        return _rpc_error(404, -32000, "The MCP server is switched off. The owner can switch it on under Settings → AI → MCP server.")
    authorization = request.headers.get("authorization") or ""
    if not authorization.startswith("Bearer "):
        return _rpc_error(401, -32001, "Send the assistant token as 'Authorization: Bearer <token>' (Settings → AI → MCP server makes one).", {"WWW-Authenticate": 'Bearer realm="netlens"'})
    bearer_only = Request({**request.scope, "headers": [(k, v) for k, v in request.scope["headers"] if k != b"cookie"]}, request.receive)     # a browser session is never accepted here
    principal = identify(bearer_only)
    if principal is None:
        return _rpc_error(401, -32001, "That token is not valid (it may have been deleted).", {"WWW-Authenticate": 'Bearer realm="netlens", error="invalid_token"'})
    if not principal.assistant:
        return _rpc_error(403, -32001, "MCP needs an assistant token, not a full access token. Make one under Settings → AI → MCP server; it can read, or read and change, but never reaches users, secrets or backups.")
    if not mcp.rate_ok(principal.username, settings["rate_per_minute"]):
        return _rpc_error(429, -32002, "Too many calls this minute. Wait a little and try again.", {"Retry-After": "30"})
    try:
        payload = await request.json()
    except ValueError:
        return _rpc_error(400, -32700, "The body is not valid JSON.")
    if isinstance(payload, list):
        replies = [r for r in [await mcp.handle(request.app, request, principal.assistant, settings, m if isinstance(m, dict) else {}) for m in payload] if r is not None]
        if not replies:
            return Response(status_code=202)
        return Response(json.dumps(replies), media_type="application/json")
    if not isinstance(payload, dict):
        return _rpc_error(400, -32600, "The body must be a JSON-RPC message.")
    reply = await mcp.handle(request.app, request, principal.assistant, settings, payload)
    if reply is None:
        return Response(status_code=202)
    return Response(json.dumps(reply), media_type="application/json")
