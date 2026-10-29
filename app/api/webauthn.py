"""Security keys and passkeys as a second factor (app/webauthn.py): a user's own keys, the second step of a sign-in, and the proof for step-up.

Adding a key needs the password again and the Enterprise edition (or the trial); keys that exist keep working when a licence ends, and removing one is always allowed.
Never for an API token, the access token or an assistant."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import audit, licence, totp, users, webauthn
from app.api.totp import _check_password, _me
from app.auth import client_ip
from app.db import connect

router = APIRouter(prefix="/api", tags=["webauthn"])


class BeginBody(BaseModel):
    password: str


class FinishBody(BaseModel):
    credential: dict
    name: str = ""


class RemoveBody(BaseModel):
    id: int
    password: str


class LoginKeyBody(BaseModel):
    challenge: str
    credential: dict


def _store(request: Request) -> webauthn.Challenges:
    state = request.app.state
    if getattr(state, "webauthn_challenges", None) is None:
        state.webauthn_challenges = webauthn.Challenges()
    return state.webauthn_challenges


def _rp_id(request: Request) -> str:
    host = (request.headers.get("host") or "").strip()
    name = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
    return name.strip("[]").lower()


def _verify_context(request: Request) -> tuple[str, str]:
    try:
        return webauthn.rp_for(request.headers.get("host") or "", request.headers.get("origin"))
    except webauthn.WebAuthnError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def login_options(request: Request, db, user_id: int, login_token: str) -> dict | None:
    """The `navigator.credentials.get` options for the second step of a sign-in, or None when this page cannot use security keys (not https)."""
    keys = webauthn.keys_of(db, user_id)
    rp_id = _rp_id(request)
    if not keys or not rp_id:
        return None
    return webauthn.request_options([k["credential_id"] for k in keys], rp_id, _store(request).issue(f"login:{login_token}", user_id, "login"))


def step_up_options(request: Request, db, user_id: int) -> dict | None:
    keys = webauthn.keys_of(db, user_id)
    if not keys or not _rp_id(request):
        return None
    return webauthn.request_options([k["credential_id"] for k in keys], _rp_id(request), _store(request).issue(f"step:{user_id}", user_id, "step"))


def prove(request: Request, db, user_id: int, credential: dict, kind: str, key: str) -> None:
    """Check an assertion for this user; counts the key as used. Raises HTTPException(403) with a sentence when it does not hold."""
    rp_id, origin = _verify_context(request)
    try:
        challenge = _store(request).take(key, user_id, kind)
        row, counter = webauthn.verify_assertion(credential, webauthn.keys_of(db, user_id), challenge, rp_id, origin)
    except webauthn.WebAuthnError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    webauthn.used(db, row["id"], counter)


@router.get("/me/webauthn")
def my_keys(request: Request) -> dict[str, Any]:
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        return {"keys": webauthn.listing(db, principal.user_id), "allowed": licence.allows(db, "privileged"), "rp_id": _rp_id(request), "max": webauthn.MAX_KEYS}
    finally:
        db.close()


@router.post("/me/webauthn/begin")
def begin(request: Request, body: BeginBody) -> dict[str, Any]:
    """Start adding a key: the password again, then the options for `navigator.credentials.create`."""
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        if not licence.allows(db, "privileged"):
            raise HTTPException(status_code=402, detail="security keys and passkeys are part of the Enterprise edition (or the free trial)")
        _check_password(request, db, principal, body.password)
        keys = webauthn.keys_of(db, principal.user_id)
        if len(keys) >= webauthn.MAX_KEYS:
            raise HTTPException(status_code=409, detail=f"at most {webauthn.MAX_KEYS} keys per account")
        rp_id = _rp_id(request)
        if not rp_id:
            raise HTTPException(status_code=400, detail="the host name of this request is missing")
        challenge = _store(request).issue(f"reg:{principal.user_id}", principal.user_id, "register")
        return webauthn.creation_options(principal.user_id, principal.username, [k["credential_id"] for k in keys], rp_id, challenge)
    finally:
        db.close()


@router.post("/me/webauthn/finish")
def finish(request: Request, body: FinishBody) -> dict[str, Any]:
    principal = _me(request)
    rp_id, origin = _verify_context(request)
    db = connect(request.app.state.db_path)
    try:
        if not licence.allows(db, "privileged"):
            raise HTTPException(status_code=402, detail="security keys and passkeys are part of the Enterprise edition (or the free trial)")
        try:
            challenge = _store(request).take(f"reg:{principal.user_id}", principal.user_id, "register")
            verified = webauthn.verify_registration(body.credential, challenge, rp_id, origin)
            first_factor = not users.get_user(db, principal.user_id)["totp_enabled"] and not webauthn.keys_of(db, principal.user_id)
            webauthn.add_key(db, principal.user_id, body.name, verified)
        except webauthn.WebAuthnError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        codes = totp.new_recovery_codes(db, principal.user_id) if first_factor else []          # the way back in if the key is lost
        audit.record_by(db, principal, client_ip(request), "POST", request.url.path, 200, f"Added a security key ({' '.join(body.name.split())[:40] or 'Security key'})")
        return {"keys": webauthn.listing(db, principal.user_id), "recovery_codes": codes}
    finally:
        db.close()


@router.post("/me/webauthn/remove")
def remove(request: Request, body: RemoveBody) -> dict[str, Any]:
    principal = _me(request)
    db = connect(request.app.state.db_path)
    try:
        _check_password(request, db, principal, body.password)
        if not webauthn.remove_key(db, principal.user_id, body.id):
            raise HTTPException(status_code=404, detail="no such key")
        row = users.get_user(db, principal.user_id)
        if not row["totp_enabled"] and not row["webauthn_enabled"]:
            db.execute("DELETE FROM user_recovery_codes WHERE user_id = ?", (principal.user_id,))
            db.commit()
        audit.record_by(db, principal, client_ip(request), "POST", request.url.path, 200, "Removed a security key")
        return {"keys": webauthn.listing(db, principal.user_id)}
    finally:
        db.close()


class LoginOptionsBody(BaseModel):
    challenge: str


async def login_options_again(request: Request, body: LoginOptionsBody) -> dict:
    """A new challenge for the key during a sign-in that is still going (a try with the key uses its challenge up, so a second try needs a new one)."""
    from app.api.auth import _challenges

    item = _challenges(request).get(body.challenge)
    if item is None:
        raise HTTPException(status_code=401, detail="this sign-in has expired: enter the password again")
    db = connect(request.app.state.db_path)
    try:
        options = login_options(request, db, item["user_id"], body.challenge)
    finally:
        db.close()
    if options is None:
        raise HTTPException(status_code=400, detail="security keys cannot be used on this page (they need https)")
    return options


async def login_webauthn(request: Request, body: LoginKeyBody) -> JSONResponse:
    """The second step of a sign-in with a security key: the single-use login challenge, and what the key signed."""
    from app.api.auth import _alarm, _alarm_kind, _audit, _challenges, _clean, _session_cookie

    limiter, user_limiter, host = request.app.state.login_limiter, request.app.state.user_limiter, client_ip(request)
    challenges = _challenges(request)
    item = challenges.get(body.challenge)
    if item is None:
        raise HTTPException(status_code=401, detail="this sign-in has expired: enter the password again")
    user_key = f"user:{item['username'].lower()}"
    if not limiter.allowed(host) or not user_limiter.allowed(user_key):
        raise HTTPException(status_code=429, detail="too many attempts")
    name = _clean(item["username"])
    db = connect(request.app.state.db_path)
    try:
        row = users.get_user(db, item["user_id"])
        problem = None
        cookie = None
        if row is None or row["disabled"]:
            problem = "the sign-in did not work"
        else:
            try:
                prove(request, db, item["user_id"], body.credential, "login", f"login:{body.challenge}")
                cookie = users.start_session(db, item["user_id"], host, request.headers.get("user-agent", ""), "webauthn")
            except HTTPException as exc:
                problem = str(exc.detail)
    finally:
        db.close()
    if cookie is None:
        limiter.record_failure(host)
        user_limiter.record_failure(user_key)
        tries = challenges.fail(body.challenge)
        _audit(request, name, "", f"Security key refused for {name!r}: {problem}", 401)
        if limiter.reached(host):
            _alarm(request, f"{limiter.max_failures} wrong second-factor attempts from {host} within a minute (user {name!r}); that address is blocked for a minute")
        raise HTTPException(status_code=401, detail=problem if tries else f"{problem}: this sign-in has ended, enter the password again")
    challenges.done(body.challenge)
    limiter.reset(host)
    user_limiter.reset(user_key)
    _audit(request, name, "", "Signed in (security key)", 200)
    if row is not None and row["break_glass"]:
        _alarm_kind(request, "break_glass_login", f"Break-glass sign-in: {name} signed in from {host}")
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, cookie)
    return response
