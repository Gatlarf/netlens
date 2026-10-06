Modify app/api/auth.py (output the COMPLETE file; current file below). Keep ALL behaviour. Change: the session cookie set by POST /login must also carry secure=True when the connection is HTTPS: request.url.scheme == "https" or the header x-forwarded-proto (first comma-separated value, lowercased, stripped) equals "https". Plain HTTP keeps secure=False (the UI must keep working on a LAN without TLS). Apply the same condition to the delete_cookie call in POST /logout (secure=<same flag>).
CURRENT FILE:
import hmac
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth import COOKIE_NAME, is_authorized, session_value, LoginLimiter


class LoginBody(BaseModel):
    token: str


router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/login")
async def login(request: Request, body: LoginBody) -> JSONResponse:
    settings = request.app.state.settings
    limiter: LoginLimiter = request.app.state.login_limiter

    key = request.client.host if request.client else "unknown"

    if not limiter.allowed(key):
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="too many attempts")

    if not hmac.compare_digest(body.token.encode(), settings.token.encode()):
        limiter.record_failure(key)
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="invalid token")

    limiter.reset(key)

    response = JSONResponse({"ok": True})
    response.set_cookie(
        COOKIE_NAME,
        session_value(settings.token),
        httponly=True,
        samesite="strict",
        path="/",
        max_age=30 * 24 * 3600,
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@router.get("/session")
async def session(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    authenticated = is_authorized(
        settings.token,
        request.cookies.get(COOKIE_NAME),
        request.headers.get("authorization"),
    )
    return JSONResponse({"authenticated": authenticated})