"""A user's own second factor (TOTP): status, set-up, confirm, remove, new recovery codes. Every change asks for the password again; a code is needed to remove the
factor or to make new recovery codes. Never for an API token or the access token (they are not interactive), and never for an assistant."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import audit, totp, users
from app.auth import client_ip, identify
from app.db import connect

router = APIRouter(prefix="/api", tags=["totp"])


class PasswordBody(BaseModel):
    password: str


class CodeBody(BaseModel):
    code: str


class PasswordCodeBody(BaseModel):
    password: str
    code: str


def _me(request: Request):
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if principal.user_id is None or principal.assistant is not None:
        raise HTTPException(status_code=400, detail="a second factor belongs to a user account: sign in with a user name and password")
    return principal


def _check_password(request: Request, db, principal, password: str):
    """The password again, with the same limits as a sign-in (a stolen session must not be a way to guess the password)."""
    limiter = request.app.state.user_limiter
    key = f"user:{principal.username.lower()}"
    if not limiter.allowed(key):
        raise HTTPException(status_code=429, detail="too many attempts")
    row = users.get_user(db, principal.user_id)
    if row is None or not users.verify_password(password or "", row["password_hash"]):
        limiter.record_failure(key)
        raise HTTPException(status_code=403, detail="the password is wrong")
    return row


def _audit(request: Request, principal, text: str) -> None:
    db = connect(request.app.state.db_path)
    try:
        audit.record_by(db, principal, client_ip(request), request.method, request.url.path, 200, text)
    finally:
        db.close()


@router.get("/me/totp")
def totp_status(request: Request) -> dict:
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        return totp.status(db, principal.user_id)
    finally:
        db.close()


@router.post("/me/totp/begin")
def totp_begin(request: Request, body: PasswordBody) -> dict:
    """Make a new secret (not active until a code confirms it). The secret is shown here and nowhere else, ever."""
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        _check_password(request, db, principal, body.password)
        try:
            secret, uri = totp.begin(db, principal.user_id)
        except totp.TotpError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    finally:
        db.close()
    return {"secret": secret, "uri": uri, "issuer": "Netlens", "digits": totp.DIGITS, "period": totp.STEP}


@router.post("/me/totp/confirm")
def totp_confirm(request: Request, body: CodeBody) -> dict:
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        try:
            codes = totp.confirm(db, principal.user_id, body.code)
        except totp.TotpError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        db.close()
    _audit(request, principal, "Switched on the second factor (authenticator app)")
    return {"recovery_codes": codes}


@router.post("/me/totp/disable")
def totp_disable(request: Request, body: PasswordCodeBody) -> dict:
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        _check_password(request, db, principal, body.password)
        if totp.check_second_factor(db, principal.user_id, body.code) is None:
            raise HTTPException(status_code=403, detail="the code is wrong")
        totp.remove(db, principal.user_id)
    finally:
        db.close()
    _audit(request, principal, "Switched off the second factor")
    return {"enabled": False}


@router.post("/me/totp/recovery")
def totp_recovery(request: Request, body: PasswordCodeBody) -> dict:
    """Ten new recovery codes; the old ones stop working."""
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        _check_password(request, db, principal, body.password)
        if totp.check_second_factor(db, principal.user_id, body.code) is None:
            raise HTTPException(status_code=403, detail="the code is wrong")
        codes = totp.new_recovery_codes(db, principal.user_id)
    finally:
        db.close()
    _audit(request, principal, "Made new recovery codes for the second factor")
    return {"recovery_codes": codes}
