import hmac
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import secpolicy, totp, users
from app.api import webauthn as webauthn_api
from app.auth import COOKIE_NAME, BUILTIN, LoginLimiter, client_ip, identify, session_value
from app.db import add_event, connect


class LoginBody(BaseModel):
    token: Optional[str] = None  # the access token (administrator), or
    username: Optional[str] = None  # a user name and password
    password: Optional[str] = None


class TotpLoginBody(BaseModel):
    challenge: str
    code: str


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


def _alarm(request: Request, text: str) -> None:
    """A login attack is an event like any other (so it reaches the notification channels). Never lets a full disk or a locked
    database turn a wrong password into a server error."""
    try:
        conn = connect(request.app.state.db_path)
        try:
            add_event(conn, "login_failed", text)
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass


def _clean(name: str) -> str:
    return "".join(c for c in name if c.isprintable())[:40]


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
            row = users.authenticate(db, body.username, body.password or "")
            cookie = challenge = refusal = key_options = None
            factors = {}
            if row is not None:
                pol = secpolicy.get(db)
                if row["role"] == "admin" and not row["break_glass"] and pol["admin_networks"] and not secpolicy.admin_allowed(pol, host):
                    refusal = "administrators can sign in only from certain networks (Settings → Sign-in security)"
                elif pol["local_login"] == "break_glass_only" and not row["break_glass"]:
                    refusal = "password sign-in is switched off: use single sign-on (Settings → Sign-in security)"
                elif row["break_glass"] and not (row["totp_enabled"] or row["webauthn_enabled"]):
                    refusal = "a break-glass account must have a second factor before it can sign in"
                elif row["totp_enabled"] or row["webauthn_enabled"]:
                    challenge = _challenges(request).issue(row["id"], row["username"])      # no session yet: only the code (or the key) can make one
                    factors = {"totp": bool(row["totp_enabled"]), "webauthn": bool(row["webauthn_enabled"])}
                    key_options = webauthn_api.login_options(request, db, row["id"], challenge) if row["webauthn_enabled"] else None
                else:
                    cookie = users.start_session(db, row["id"], host, request.headers.get("user-agent", ""), "password")
        finally:
            db.close()
        if row is None:
            limiter.record_failure(host)
            user_limiter.record_failure(user_key)
            _audit(request, _clean(body.username)[:40] if body.username else "", "", f"Failed sign-in as {_clean(body.username)[:40]!r}", 401)
            if limiter.reached(host):
                _alarm(request, f"{limiter.max_failures} wrong sign-in attempts from {host} within a minute (last user name tried: {_clean(body.username)!r}); that address is blocked for a minute")
            if user_limiter.reached(user_key):
                _alarm(request, f"{user_limiter.max_failures} wrong passwords for the user {_clean(body.username)!r} within 15 minutes (latest from {host}); further attempts are blocked for a while")
            raise HTTPException(status_code=401, detail="wrong user name or password")
        if refusal:
            _audit(request, _clean(body.username)[:40], "", f"Refused a password sign-in for {_clean(body.username)[:40]!r}: {refusal}", 403)
            raise HTTPException(status_code=403, detail=refusal)
        if challenge is not None:
            # the failures stay counted until the code is right too: a correct password must not give an unlimited number of tries at the code
            _audit(request, body.username.strip(), "", "Password accepted; waiting for the second factor", 200)
            return JSONResponse({"totp_required": True, "challenge": challenge, "methods": factors, **({"webauthn": key_options} if key_options else {})})
        limiter.reset(host)
        user_limiter.reset(user_key)
        _audit(request, body.username.strip(), "", "Signed in", 200)
        response = JSONResponse({"ok": True})
        _session_cookie(response, request, cookie)
        return response

    from app.auth import _static_token_allowed

    if settings.token and body.token is not None and not _static_token_allowed(request):
        _audit(request, "access token", "", "Refused: the access token sign-in is switched off or limited to the local network (Settings → Sign-in security)", 401)
        raise HTTPException(status_code=401, detail="the access token sign-in is switched off here")
    if not settings.token or body.token is None or not hmac.compare_digest(body.token.encode(), settings.token.encode()):
        limiter.record_failure(host)
        if limiter.reached(host):
            _alarm(request, f"{limiter.max_failures} wrong access tokens from {host} within a minute; that address is blocked for a minute")
        raise HTTPException(status_code=401, detail="invalid token")

    limiter.reset(host)
    _audit(request, "access token", "admin", "Signed in with the access token", 200)
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, session_value(settings.token))
    return response


def _cert_present(request: Request) -> bool:
    """Whether this request carries a client certificate that the proxy vouches for (the sign-in page then offers the certificate button)."""
    try:
        from app import certlogin, licence

        db = connect(request.app.state.db_path)
        try:
            return certlogin.identity_from(request, certlogin.get(db)) is not None and licence.allows(db, "privileged")
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - the sign-in page must always load
        return False


def _challenges(request: Request) -> totp.Challenges:
    state = request.app.state
    if getattr(state, "totp_challenges", None) is None:
        state.totp_challenges = totp.Challenges()
    return state.totp_challenges


@router.post("/login/totp")
async def login_totp(request: Request, body: TotpLoginBody) -> JSONResponse:
    """The second step of a sign-in: the single-use challenge from the password step, and a code from the authenticator (or a recovery code)."""
    from fastapi import HTTPException

    limiter: LoginLimiter = request.app.state.login_limiter
    user_limiter: LoginLimiter = request.app.state.user_limiter
    host = client_ip(request)
    challenges = _challenges(request)
    item = challenges.get(body.challenge)
    if item is None:
        raise HTTPException(status_code=401, detail="this sign-in has expired: enter the password again")
    user_key = f"user:{item['username'].lower()}"
    if not limiter.allowed(host) or not user_limiter.allowed(user_key):
        raise HTTPException(status_code=429, detail="too many attempts")
    db = connect(request.app.state.db_path)
    try:
        row = users.get_user(db, item["user_id"])
        how = totp.check_second_factor(db, item["user_id"], body.code) if row is not None and not row["disabled"] else None      # a disabled account does not use up a code
        cookie = users.start_session(db, item["user_id"], host, request.headers.get("user-agent", ""), "recovery" if how == "recovery" else "totp") if how else None
        left = db.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used = 0", (item["user_id"],)).fetchone()[0] if how == "recovery" else 0
    finally:
        db.close()
    name = _clean(item["username"])
    if how is None:
        limiter.record_failure(host)
        user_limiter.record_failure(user_key)
        tries = challenges.fail(body.challenge)
        _audit(request, name, "", f"Wrong second-factor code for {name!r}", 401)
        if limiter.reached(host):
            _alarm(request, f"{limiter.max_failures} wrong second-factor codes from {host} within a minute (user {name!r}); that address is blocked for a minute")
        if user_limiter.reached(user_key):
            _alarm(request, f"{user_limiter.max_failures} wrong codes or passwords for the user {name!r} within 15 minutes (latest from {host}); further attempts are blocked for a while")
        raise HTTPException(status_code=401, detail="wrong code" if tries else "wrong code: this sign-in has ended, enter the password again")
    challenges.done(body.challenge)
    limiter.reset(host)
    user_limiter.reset(user_key)
    _audit(request, name, "", "Signed in (recovery code)" if how == "recovery" else "Signed in (second factor)", 200)
    if row is not None and row["break_glass"]:
        _alarm_kind(request, "break_glass_login", f"Break-glass sign-in: {name} signed in from {host}")
    if how == "recovery":
        _alarm_kind(request, "totp_recovery_used", f"{name} signed in with a recovery code ({left} left): the authenticator may be lost")
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, cookie)
    return response


@router.post("/login/certificate")
async def login_certificate(request: Request) -> JSONResponse:
    """Sign in with a client certificate that the reverse proxy in front of Netlens has checked (app/certlogin.py). The certificate replaces the password only: a user
    with a second factor still gives it."""
    from fastapi import HTTPException

    from app import certlogin, licence

    limiter: LoginLimiter = request.app.state.login_limiter
    host = client_ip(request)
    if not limiter.allowed(host):
        raise HTTPException(status_code=429, detail="too many attempts")
    db = connect(request.app.state.db_path)
    try:
        policy = certlogin.get(db)
        identity = certlogin.identity_from(request, policy) if licence.allows(db, "privileged") else None
        if identity is None:
            raise HTTPException(status_code=401, detail="no valid client certificate was presented (or certificate sign-in is not set up for this address)")
        row = certlogin.user_for(db, identity)
        if row is None:
            limiter.record_failure(host)
            _audit(request, _clean(identity)[:40], "", f"Client certificate {_clean(identity)[:60]!r} is not linked to any user", 401)
            raise HTTPException(status_code=401, detail="this certificate is not linked to a user")
        pol = secpolicy.get(db)
        cookie = challenge = refusal = key_options = None
        factors: dict = {}
        if row["role"] == "admin" and not row["break_glass"] and pol["admin_networks"] and not secpolicy.admin_allowed(pol, host):
            refusal = "administrators can sign in only from certain networks (Settings → Sign-in security)"
        elif row["break_glass"] and not (row["totp_enabled"] or row["webauthn_enabled"]):
            refusal = "a break-glass account must have a second factor before it can sign in"
        elif row["totp_enabled"] or row["webauthn_enabled"]:
            challenge = _challenges(request).issue(row["id"], row["username"])
            factors = {"totp": bool(row["totp_enabled"]), "webauthn": bool(row["webauthn_enabled"])}
            key_options = webauthn_api.login_options(request, db, row["id"], challenge) if row["webauthn_enabled"] else None
        else:
            cookie = users.start_session(db, row["id"], host, request.headers.get("user-agent", ""), "certificate")
    finally:
        db.close()
    name = _clean(row["username"])
    if refusal:
        _audit(request, name, "", f"Refused a certificate sign-in for {name!r}: {refusal}", 403)
        raise HTTPException(status_code=403, detail=refusal)
    if challenge is not None:
        _audit(request, name, "", "Client certificate accepted; waiting for the second factor", 200)
        return JSONResponse({"totp_required": True, "challenge": challenge, "methods": factors, **({"webauthn": key_options} if key_options else {})})
    limiter.reset(host)
    _audit(request, name, "", "Signed in (client certificate)", 200)
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, cookie)
    return response


@router.post("/login/webauthn")
async def login_webauthn(request: Request, body: webauthn_api.LoginKeyBody) -> JSONResponse:
    """The second step of a sign-in with a security key (app/api/webauthn.py)."""
    return await webauthn_api.login_webauthn(request, body)


@router.post("/login/webauthn/options")
async def login_webauthn_options(request: Request, body: webauthn_api.LoginOptionsBody) -> dict:
    return await webauthn_api.login_options_again(request, body)


def _alarm_kind(request: Request, kind: str, text: str) -> None:
    try:
        conn = connect(request.app.state.db_path)
        try:
            add_event(conn, kind, text)
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    who = identify(request)
    if who is not None:
        _audit(request, who.username, who.role, "Signed out", 200)
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


def _demo_info(request: Request) -> dict:
    """In demo mode the sign-in page shows the demo account, and every page a banner."""
    settings = request.app.state.settings
    if not getattr(settings, "demo", False):
        return {}
    from app.demo.seed import DEMO_PASSWORD, DEMO_USER

    return {"demo": {"username": DEMO_USER, "password": DEMO_PASSWORD, "reset": settings.demo_reset}}


def _interface(request: Request) -> dict:
    """The look the administrator chose (Settings → Interface): even the sign-in page applies it."""
    from app import interface_settings

    db = connect(request.app.state.db_path)
    try:
        return interface_settings.get(db)
    except Exception:  # noqa: BLE001 - the page works with its built-in look
        return dict(interface_settings.DEFAULTS)
    finally:
        db.close()


def _audit(request: Request, user: str, role: str, action: str, status: int) -> None:
    try:
        from app import audit

        db = connect(request.app.state.db_path)
        try:
            audit.record(db, user, role, client_ip(request), request.method, request.url.path, status, action)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - the log must never stop a sign-in
        pass


def _oidc_public(request: Request) -> dict:
    from app import oidc

    db = connect(request.app.state.db_path)
    try:
        return oidc.public(db)
    except Exception:  # noqa: BLE001 - the sign-in page must load whatever happens here
        return {"enabled": False, "label": ""}
    finally:
        db.close()


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
            "oidc": _oidc_public(request),
            **({"certificate_login": True} if _cert_present(request) else {}),
            **_demo_info(request),
            "interface": _interface(request),
        })
    from app import preferences

    db = connect(request.app.state.db_path)
    try:
        start_page = preferences.get(db, principal)["start_page"]
    finally:
        db.close()
    return JSONResponse({
        "authenticated": True,
        "user": {"username": principal.username, "role": principal.role, "builtin": principal.builtin, **({"mfa": principal.mfa} if principal.mfa and principal.mfa["required"] else {}), **({"grants": list(principal.grants)} if principal.grants else {}), **({"scoped": True, "sites": bool(principal.sites), "devices": bool(principal.scope)} if principal.scope is not None else {})},
        "start_page": (("#/remote-sites" if principal.sites and not principal.scope else "#/devices") if principal.scope is not None else start_page),
        **_demo_info(request),
        "interface": _interface(request),
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
        cookie = users.start_session(db, row["id"], client_ip(request), request.headers.get("user-agent", ""), "password")  # keep this browser signed in (the user is already authenticated; a user with a second factor could not use login())
    finally:
        db.close()
    response = JSONResponse({"ok": True})
    _session_cookie(response, request, cookie)
    return response
