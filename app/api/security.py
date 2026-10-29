"""Sign-in security: the policy (who must have a second factor, session limits), sessions that can be listed and ended, and the reset of someone's second factor.
Administrators only, except a user's own sessions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import audit, licence, secpolicy, stepup, totp, users, webauthn
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin
from app.db import add_event
from app.terminal.access import ensure_allowed

router = APIRouter(prefix="/api", tags=["security"])


class SessionRef(BaseModel):
    id: str


class ProofBody(BaseModel):
    password: str | None = None
    code: str | None = None
    credential: dict | None = None          # what a security key signed (app/webauthn.py)


def _principal(request: Request):
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if principal.user_id is None:
        raise HTTPException(status_code=400, detail="this is for user accounts; the access token has no sessions")
    return principal


# ----------------------------------------------------------------------------- the policy
def _doc(conn) -> dict[str, Any]:
    pol = secpolicy.get(conn)
    total = conn.execute("SELECT COUNT(*) FROM users WHERE disabled = 0").fetchone()[0]
    with_totp = conn.execute("SELECT COUNT(*) FROM users WHERE disabled = 0 AND (totp_enabled = 1 OR webauthn_enabled = 1)").fetchone()[0]
    return {"policy": pol, "token_configured": False, "allowed": {"mfa_policy": licence.allows(conn, "mfa_policy"), "privileged": licence.allows(conn, "privileged")},
            "users": {"total": total, "with_second_factor": with_totp}, "without_second_factor": secpolicy.users_without_factor(conn)}


def _doc_for(request: Request, conn) -> dict[str, Any]:
    doc = _doc(conn)
    doc["token_configured"] = bool(request.app.state.settings.token)         # NETLENS_TOKEN is set in the environment
    return doc


@router.get("/security-policy")
def get_policy(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return _doc_for(request, conn)


@router.put("/security-policy", dependencies=[Depends(ensure_allowed)])
def put_policy(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    before = secpolicy.get(conn)
    try:
        secpolicy.save(conn, body, may_mfa=licence.allows(conn, "mfa_policy"), may_privileged=licence.allows(conn, "privileged"))
    except secpolicy.PolicyError as exc:
        raise HTTPException(status_code=402 if "edition" in str(exc) else 422, detail=str(exc))
    after = secpolicy.get(conn)
    changes = ", ".join(f"{k}: {before[k]} -> {after[k]}" for k in secpolicy.DEFAULTS if k != "require_since" and before[k] != after[k])
    audit.record_by(conn, identify(request), client_ip(request), "PUT", request.url.path, 200, "Changed the sign-in security policy" + (f" ({changes})" if changes else ""))
    return _doc_for(request, conn)


# ----------------------------------------------------------------------------- a user's own sessions (every edition)
@router.get("/me/sessions")
def my_sessions(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    p = _principal(request)
    return {"sessions": users.list_sessions(conn, p.user_id, request.cookies.get("netlens_session"))}


@router.post("/me/sessions/end")
def end_my_session(body: SessionRef, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    p = _principal(request)
    n = users.end_sessions(conn, p.user_id, body.id, request.cookies.get("netlens_session"))       # never the one in use: that is "log out"
    audit.record_by(conn, p, client_ip(request), "POST", request.url.path, 200, "Ended one of their own sessions")
    return {"ended": n, "sessions": users.list_sessions(conn, p.user_id, request.cookies.get("netlens_session"))}


@router.post("/me/sessions/revoke-others")
def revoke_my_other_sessions(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    p = _principal(request)
    n = users.end_sessions(conn, p.user_id, None, request.cookies.get("netlens_session"))
    audit.record_by(conn, p, client_ip(request), "POST", request.url.path, 200, f"Ended all their other sessions ({n})")
    return {"ended": n, "sessions": users.list_sessions(conn, p.user_id, request.cookies.get("netlens_session"))}


# ----------------------------------------------------------------------------- an administrator and somebody else's sessions and second factor
def _need(conn, feature: str, text: str) -> None:
    if not licence.allows(conn, feature):
        raise HTTPException(status_code=402, detail=text)


def _target(conn, user_id: int):
    row = users.get_user(conn, user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no such user")
    return row


@router.get("/users/{user_id}/sessions")
def user_sessions(user_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need(conn, "privileged", "seeing and ending the sessions of other users is part of the Enterprise edition (or the free trial)")
    _target(conn, user_id)
    return {"sessions": users.list_sessions(conn, user_id)}


@router.post("/users/{user_id}/sessions/end", dependencies=[Depends(ensure_allowed)])
def end_user_sessions(user_id: int, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need(conn, "privileged", "seeing and ending the sessions of other users is part of the Enterprise edition (or the free trial)")
    row = _target(conn, user_id)
    sid = body.get("id") if isinstance(body.get("id"), str) else None
    n = users.end_sessions(conn, user_id, sid)
    audit.record_by(conn, identify(request), client_ip(request), "POST", request.url.path, 200, f"Ended {n} session{'s' if n != 1 else ''} of {row['username']}")
    return {"ended": n, "sessions": users.list_sessions(conn, user_id)}


@router.post("/users/{user_id}/totp/reset", dependencies=[Depends(ensure_allowed)])
def reset_user_totp(user_id: int, body: ProofBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Switch off somebody's second factor (they lost the authenticator and the recovery codes). The administrator proves who they are again first (a code if they have
    a second factor, else their password); the user's sessions end, and they must set a factor up again at the next sign-in if the policy requires one."""
    require_admin(request)
    _need(conn, "mfa_policy", "resetting the second factor of other users is part of the Small business and Enterprise editions (or the free trial); on the console: python -m app.cli reset-totp <user>")
    principal = identify(request)
    if principal.user_id is None:
        raise HTTPException(status_code=400, detail="sign in as a user to reset a second factor (the access token cannot prove who you are)")
    if principal.user_id == user_id:
        raise HTTPException(status_code=400, detail="use Settings → Account to switch off your own second factor")
    limiter = request.app.state.user_limiter
    key = f"user:{principal.username.lower()}"
    if not limiter.allowed(key):
        raise HTTPException(status_code=429, detail="too many attempts")
    me = users.get_user(conn, principal.user_id)
    has_factor = bool(me["totp_enabled"] or me["webauthn_enabled"])
    if body.credential is not None:
        from app.api import webauthn as webauthn_api

        try:
            webauthn_api.prove(request, conn, principal.user_id, body.credential, "step", f"step:{principal.user_id}")
            ok = True
        except HTTPException:
            ok = False
    elif has_factor:
        ok = totp.check_second_factor(conn, principal.user_id, body.code or "") is not None
    else:
        ok = users.verify_password(body.password or "", me["password_hash"])
    if not ok:
        limiter.record_failure(key)
        raise HTTPException(status_code=403, detail="the code is wrong" if has_factor else "the password is wrong")
    target = _target(conn, user_id)
    totp.remove(conn, user_id)
    webauthn.remove_all(conn, user_id)
    users.end_sessions(conn, user_id)
    add_event(conn, "totp_reset", f"The second factor of {target['username']} was reset by {principal.username}")
    audit.record_by(conn, principal, client_ip(request), "POST", request.url.path, 200, f"Reset the second factor of {target['username']}")
    return {"reset": True}


# ----------------------------------------------------------------------------- step-up: confirm who is acting before a privileged action
@router.get("/me/stepup")
def stepup_status(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Whether a privileged action would be accepted now, and how this user confirms (the interface asks before opening a terminal, which cannot be retried after a refusal)."""
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    pol = secpolicy.get_by_path(getattr(request.app.state, "db_path", None))
    if not pol["step_up"]:
        return {"enabled": False, "fresh": True}
    if principal.user_id is None or principal.auth_method is None:
        return {"enabled": True, "fresh": False, "available": False, "minutes": pol["step_up_minutes"]}
    answer = {"enabled": True, "fresh": stepup.fresh(principal, pol["step_up_minutes"]), "available": True, "method": stepup.method_for(principal), "minutes": pol["step_up_minutes"]}
    if answer["method"] == "webauthn":
        from app.api import webauthn as webauthn_api

        options = webauthn_api.step_up_options(request, conn, principal.user_id)
        if options:
            answer["webauthn"] = options
        elif principal.mfa.get("totp"):
            answer["method"] = "totp"              # a page that cannot use keys (not https) falls back to the code
        else:
            answer["available"] = False
    answer["alternatives"] = [m for m in ("totp",) if principal.mfa and principal.mfa.get(m) and answer["method"] != m]
    return answer


@router.post("/me/stepup")
def stepup_confirm(body: ProofBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Prove who is acting again: a code (or recovery code) for a user with a second factor, the password for one without. Starts a window of `step_up_minutes`."""
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if principal.user_id is None or principal.auth_method is None or principal.assistant:
        raise HTTPException(status_code=400, detail="only a person signed in with a user account can confirm; the access token and API tokens cannot")
    how = stepup.method_for(principal)
    if how == "oidc":
        raise HTTPException(status_code=400, detail="confirm with your identity provider: open /api/auth/oidc/stepup")
    limiter, user_limiter = request.app.state.login_limiter, request.app.state.user_limiter
    host, key = client_ip(request), f"user:{principal.username.lower()}"
    if not limiter.allowed(host) or not user_limiter.allowed(key):
        raise HTTPException(status_code=429, detail="too many attempts")
    row = users.get_user(conn, principal.user_id)
    enrolled = bool(principal.mfa and principal.mfa.get("enrolled"))
    if body.credential is not None:
        from app.api import webauthn as webauthn_api

        try:
            webauthn_api.prove(request, conn, principal.user_id, body.credential, "step", f"step:{principal.user_id}")
            ok, how = True, "security key"
        except HTTPException as exc:
            limiter.record_failure(host)
            user_limiter.record_failure(key)
            audit.record_by(conn, principal, host, "POST", request.url.path, 403, "Failed confirmation of a privileged action")
            raise exc
    elif enrolled:
        ok, how = totp.check_second_factor(conn, principal.user_id, body.code or "") is not None, "code"
    else:
        ok, how = users.verify_password(body.password or "", row["password_hash"]), "password"
    if not ok:
        limiter.record_failure(host)
        user_limiter.record_failure(key)
        audit.record_by(conn, principal, host, "POST", request.url.path, 403, "Failed confirmation of a privileged action")
        raise HTTPException(status_code=403, detail="the code is wrong" if how == "code" else "the password is wrong")
    limiter.reset(host)
    user_limiter.reset(key)
    users.mark_auth(conn, request.cookies.get("netlens_session"))
    audit.record_by(conn, principal, host, "POST", request.url.path, 200, f"Confirmed their identity for privileged actions ({how})")
    return {"fresh": True, "minutes": secpolicy.get_by_path(request.app.state.db_path)["step_up_minutes"]}
