Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The logout deletion cookie must carry the same attributes as the login cookie: call response.delete_cookie(COOKIE_NAME, path='/', httponly=True, samesite='strict', secure=<same secure flag>).

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


def _is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    x_forwarded_proto = request.headers.get("x-forwarded-proto", "")
    first_value = x_forwarded_proto.split(",")[0].strip().lower()
    return first_value == "https"


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
        secure=_is_https(request),
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/", secure=_is_https(request))
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