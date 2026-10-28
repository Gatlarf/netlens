from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import licence, secpolicy, users
from app.db import connect

router = APIRouter(prefix="/api", tags=["users"])


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    scope: list[int] | None = None         # group ids a viewer is limited to (None = no limit)
    sites: list[int] | None = None         # remote site ids a viewer is limited to (a customer who sees its own sites)


class UserPatch(BaseModel):
    break_glass: bool | None = None
    role: str | None = None
    password: str | None = None
    disabled: bool | None = None
    scope: list[int] | None = None
    sites: list[int] | None = None


class NewToken(BaseModel):
    name: str
    readonly: bool = False
    expires_days: int | None = None        # the life of the token (the policy may cap it, Enterprise)
    allowed_ips: list[str] | None = None   # addresses or networks it may be used from (Enterprise)


def _db(request: Request):
    return connect(request.app.state.db_path)


NEEDS_LICENCE = "operators and customer views (viewers limited to some groups) are part of the Small business and Enterprise editions (or the free trial): Settings → Licence"


def _check_teams(db, role: str | None, scope) -> None:
    """Operators and customer views are business features. Existing ones keep working; only creating or changing them asks for a licence."""
    if (role == "operator" or scope) and not licence.allows(db, "teams"):
        raise HTTPException(status_code=402, detail=NEEDS_LICENCE)


def _fail(exc: users.UserError, status: int = 422) -> HTTPException:
    if isinstance(exc, users.LastAdminError):
        status = 409
    return HTTPException(status_code=404 if str(exc).startswith("no such") else status, detail=str(exc))


@router.get("/users")
def get_users(request: Request) -> dict:
    db = _db(request)
    try:
        return {
            "users": users.list_users(db), "roles": list(users.ROLES), "min_password": max(users.MIN_PASSWORD, secpolicy.get(db)["min_password"]),
            "token_configured": bool(request.app.state.settings.token),  # NETLENS_TOKEN is set in the environment
            "teams_allowed": licence.allows(db, "teams"),
            "token_policy": {"max_days": secpolicy.get(db)["api_token_max_days"], "may_restrict": licence.allows(db, "privileged")},
            "privileged_allowed": licence.allows(db, "privileged"),
            "sites": [{"id": r["id"], "name": r["name"], "customer": r["customer"] or ""} for r in db.execute("SELECT id, name, customer FROM probes ORDER BY LOWER(name)")],
        }
    finally:
        db.close()


@router.post("/users", status_code=201)
def add_user(request: Request, body: NewUser) -> dict:
    db = _db(request)
    try:
        _check_teams(db, body.role, body.scope or body.sites)
        try:
            user_id = users.create_user(db, body.username, body.password, body.role, body.scope, body.sites)
        except users.UserError as exc:
            raise _fail(exc, 409 if "taken" in str(exc) else 422)
        return {"id": user_id, "users": users.list_users(db)}
    finally:
        db.close()


@router.patch("/users/{user_id}")
def edit_user(request: Request, user_id: int, body: UserPatch) -> dict:
    db = _db(request)
    try:
        _check_teams(db, body.role, (body.scope if "scope" in body.model_fields_set else None) or (body.sites if "sites" in body.model_fields_set else None))
        if body.break_glass is not None:
            if not licence.allows(db, "privileged"):
                raise HTTPException(status_code=402, detail="break-glass accounts are part of the Enterprise edition (or the free trial)")
            target = users.get_user(db, user_id)
            if target is None:
                raise HTTPException(status_code=404, detail="no such user")
            if body.break_glass and (target["role"] != "admin" or target["oidc_sub"]):
                raise HTTPException(status_code=422, detail="a break-glass account is a local administrator account (not a single-sign-on user)")
            if not body.break_glass and target["break_glass"] and secpolicy.get(db)["local_login"] == "break_glass_only" and db.execute(
                    "SELECT COUNT(*) FROM users WHERE disabled = 0 AND role = 'admin' AND break_glass = 1 AND totp_enabled = 1 AND id != ?", (user_id,)).fetchone()[0] < 1:
                raise HTTPException(status_code=409, detail="this is the last break-glass account while password sign-in is limited to them: allow password sign-in again first")
            db.execute("UPDATE users SET break_glass = ? WHERE id = ?", (1 if body.break_glass else 0, user_id))
            db.commit()
        try:
            users.update_user(db, user_id, role=body.role, password=body.password, disabled=body.disabled,
                              **({"scope": body.scope} if "scope" in body.model_fields_set else {}), **({"sites": body.sites} if "sites" in body.model_fields_set else {}))
        except users.UserError as exc:
            raise _fail(exc)
        return {"users": users.list_users(db)}
    finally:
        db.close()


@router.delete("/users/{user_id}")
def remove_user(request: Request, user_id: int) -> dict:
    db = _db(request)
    try:
        try:
            users.delete_user(db, user_id)
        except users.UserError as exc:
            raise _fail(exc)
        return {"users": users.list_users(db)}
    finally:
        db.close()


@router.post("/users/{user_id}/tokens", status_code=201)
def add_token(request: Request, user_id: int, body: NewToken) -> dict:
    """Create an API token for a user. The token itself is in the answer once and is never shown again."""
    db = _db(request)
    try:
        try:
            if (body.allowed_ips or body.expires_days) and not licence.allows(db, "privileged") and not secpolicy.get(db)["api_token_max_days"]:
                raise HTTPException(status_code=402, detail="limiting a token to addresses or a life time is part of the Enterprise edition (or the free trial)")
            token_id, secret = users.create_api_token(db, user_id, body.name, body.readonly, expires_days=body.expires_days, allowed_ips=body.allowed_ips)
        except users.UserError as exc:
            raise _fail(exc)
        return {"id": token_id, "token": secret, "users": users.list_users(db)}
    finally:
        db.close()


@router.delete("/users/{user_id}/tokens/{token_id}")
def remove_token(request: Request, user_id: int, token_id: int) -> dict:
    db = _db(request)
    try:
        try:
            users.delete_api_token(db, user_id, token_id)
        except users.UserError as exc:
            raise _fail(exc)
        return {"users": users.list_users(db)}
    finally:
        db.close()
