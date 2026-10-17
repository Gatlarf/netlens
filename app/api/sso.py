"""Single sign-on (OpenID Connect): the two public addresses of the flow, and the administrator's settings (see app/oidc.py)."""

from __future__ import annotations

import asyncio
import html
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from app import licence, oidc
from app.api.auth import _audit, _is_https, _session_cookie
from app.api.devices import get_conn
from app.db import connect

public_router = APIRouter(prefix="/api/auth/oidc", tags=["sso"])
router = APIRouter(prefix="/api", tags=["sso"])


def _base(request: Request) -> str:
    host = request.headers.get("host") or request.url.netloc
    return f"{'https' if _is_https(request) else 'http'}://{host}"


def _page(message: str, status: int = 400) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Sign-in failed</title><body style='font:16px system-ui;max-width:32em;margin:15vh auto;padding:0 1em'>"
                        f"<h1>Sign-in failed</h1><p>{html.escape(message)}</p><p><a href='/'>Back to Netlens</a></p>", status_code=status)


@public_router.get("/login")
async def login(request: Request):
    db = connect(request.app.state.db_path)
    try:
        url = await asyncio.to_thread(oidc.begin, db, _base(request))
    except oidc.OidcError as exc:
        return _page(str(exc))
    finally:
        db.close()
    return RedirectResponse(url, status_code=302)


@public_router.get("/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    if error:
        return _page(f"The identity provider refused the sign-in: {error_description or error}")
    db = connect(request.app.state.db_path)
    try:
        cookie = await asyncio.to_thread(oidc.finish, db, state, code)
        user = db.execute("SELECT u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id ORDER BY s.created DESC LIMIT 1").fetchone()
    except oidc.OidcError as exc:
        _audit(request, "", "", "Failed single sign-on", 401)
        return _page(str(exc), 401)
    finally:
        db.close()
    # the browser arrives from another site; a page that moves on by itself makes the next request a same-site one, so the strict session cookie is sent
    response = HTMLResponse("<!doctype html><meta charset=utf-8><meta http-equiv='refresh' content='0;url=/'><title>Signing in…</title><body style='font:16px system-ui;padding:2em'>Signing in… <a href='/'>continue</a>")
    _session_cookie(response, request, cookie)
    if user:
        _audit(request, user["username"], user["role"], "Signed in with single sign-on", 200)
    return response


class SsoBody(BaseModel):
    enabled: bool | None = None
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    admin_groups: str | None = None
    groups_claim: str | None = None
    default_role: str | None = None
    label: str | None = None
    redirect_base: str | None = None


def _doc(conn, request: Request) -> dict[str, Any]:
    return {**oidc.settings(conn), "allowed": licence.allows(conn, "sso"), "redirect_uri": oidc.redirect_uri(conn, _base(request))}


@router.get("/sso")
def get_sso(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    return _doc(conn, request)


@router.put("/sso")
def put_sso(body: SsoBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    if not licence.allows(conn, "sso"):
        raise HTTPException(status_code=402, detail="single sign-on needs a licence or the free trial (Settings → Licence)")
    try:
        oidc.save_settings(conn, body.model_dump(exclude_none=True))
    except oidc.OidcError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _doc(conn, request)


@router.post("/sso/test")
async def test_sso(conn=Depends(get_conn)) -> dict[str, Any]:
    cfg = oidc.settings(conn)
    if not cfg["issuer"]:
        raise HTTPException(status_code=422, detail="enter the address of the identity provider first")
    try:
        doc = await asyncio.to_thread(oidc.discovery, cfg["issuer"])
    except oidc.OidcError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True, "authorization_endpoint": doc["authorization_endpoint"]}
