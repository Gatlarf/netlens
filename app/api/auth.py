import hmac
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import users
from app.auth import COOKIE_NAME, BUILTIN, LoginLimiter, client_ip, identify, session_value
from app.db import connect


class LoginBody(BaseModel):
    token: Optional[str] = None  # the access token (administrator), or
    username: Optional[str] = None  # a user name and password
    password: Optional[str] = None


class PasswordBody(BaseModel):
    current: str
    new: str


router = APIRouter(prefix="/api", tags=["auth"])


def _is_https(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    x_forwarded_proto = request.headers.get("x-forwarded-proto", "")
    first_value = x_forwarded_proto.split(",")[0].strip().lower()
    return first_value == "https"


def _session_cookie(response: JSONResponse, request: Request, value: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        value,
        httponly=True,
        samesite="strict",
        path="/",
        max_age=30 * 24 * 3600,
        secure=_is_https(request),
    )


@router.post("/login")
async def login(request: Request, body: LoginBody) -> JSONResponse:
    from fastapi import HTTPException

    settings = request.app.state.settings
    limiter: LoginLimiter = request.app.state.login_limiter
    host = client_ip(request)
    user_limiter: LoginLimiter = request.app.state.user_limiter
    # a wrong guess counts against the address (5 a minute) and, for user logins, against the user name as well (20 in a quarter of an hour,
    # more generous because anybody can type the owner's name: a stricter limit would let a stranger lock the owner out)
    user_key = f"user:{body.username.strip().lower()}" if body.username else None

    if not limiter.allowed(host) or (user_key and not user_limiter.allowed(user_key)):
        raise HTTPException(status_code=429, detail="too many attempts")

    if body.username is not None:
        db = connect(request.app.state.db_path)
        try:
            cookie = users.login(db, body.username, body.password or "")
        finally:
            db.close()
        if cookie is None:
            limiter.record_failure(host)
            user_limiter.record_failure(user_key)
            raise HTTPException(status_code=401, detail="wrong user name or password")
        limiter.reset(host)
        user_limiter.reset(user_key)
        response = JSONResponse({"ok": True})
        _session_cookie(response, request, cookie)
        return response

    if not settings.token or body.token is None or not hmac.compare_digest(body.token.encode(), settings.token.encode()):
        limiter.record_failure(host)
        raise HTTPException(status_code=401, detail="invalid token")

    limiter.reset(host)
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, session_value(settings.token))
    return response


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    db = connect(request.app.state.db_path)
    try:
        users.end_session(db, request.cookies.get(COOKIE_NAME))
    finally:
        db.close()
    response = JSONResponse({"ok": True})
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="strict",
        secure=_is_https(request),
    )
    return response


@router.get("/session")
async def session(request: Request) -> JSONResponse:
    principal = identify(request)
    if principal is None:
        from app.api.setup import setup_required

        db = connect(request.app.state.db_path)
        try:
            needs_setup = setup_required(request, db)
        finally:
            db.close()
        return JSONResponse({
            "authenticated": False,
            "setup_required": needs_setup,
            "token_login": bool(request.app.state.settings.token),  # False: only user name and password sign in
        })
    return JSONResponse({
        "authenticated": True,
        "user": {"username": principal.username, "role": principal.role, "builtin": principal.builtin},
    })


@router.post("/me/password")
async def change_password(request: Request, body: PasswordBody) -> JSONResponse:
    """A signed-in user changes their own password (all their other logins end)."""
    from fastapi import HTTPException

    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if principal.user_id is None:
        raise HTTPException(status_code=400, detail="the access token login has no password; change NETLENS_TOKEN instead")
    db = connect(request.app.state.db_path)
    try:
        row = users.get_user(db, principal.user_id)
        if not users.verify_password(body.current, row["password_hash"]):
            raise HTTPException(status_code=403, detail="the current password is wrong")
        try:
            users.update_user(db, principal.user_id, password=body.new)
        except users.UserError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        cookie = users.login(db, row["username"], body.new)  # keep this browser signed in
    finally:
        db.close()
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, cookie)
    return response
