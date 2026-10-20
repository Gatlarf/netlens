from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import licence, users
from app.db import connect

router = APIRouter(prefix="/api", tags=["users"])


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"
    scope: list[int] | None = None         # group ids a viewer is limited to (None = no limit)
    sites: list[int] | None = None         # remote site ids a viewer is limited to (a customer who sees its own sites)


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None
    disabled: bool | None = None
    scope: list[int] | None = None
    sites: list[int] | None = None


class NewToken(BaseModel):
    name: str
    readonly: bool = False


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
            "users": users.list_users(db), "roles": list(users.ROLES), "min_password": users.MIN_PASSWORD,
            "token_configured": bool(request.app.state.settings.token),  # NETLENS_TOKEN is set in the environment
            "teams_allowed": licence.allows(db, "teams"),
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
            token_id, secret = users.create_api_token(db, user_id, body.name, body.readonly)
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
