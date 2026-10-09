from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import users
from app.db import connect

router = APIRouter(prefix="/api", tags=["users"])


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None
    disabled: bool | None = None


class NewToken(BaseModel):
    name: str


def _db(request: Request):
    return connect(request.app.state.db_path)


def _fail(exc: users.UserError, status: int = 422) -> HTTPException:
    return HTTPException(status_code=404 if str(exc).startswith("no such") else status, detail=str(exc))


@router.get("/users")
def get_users(request: Request) -> dict:
    db = _db(request)
    try:
        return {"users": users.list_users(db), "roles": list(users.ROLES), "min_password": users.MIN_PASSWORD}
    finally:
        db.close()


@router.post("/users", status_code=201)
def add_user(request: Request, body: NewUser) -> dict:
    db = _db(request)
    try:
        try:
            user_id = users.create_user(db, body.username, body.password, body.role)
        except users.UserError as exc:
            raise _fail(exc, 409 if "taken" in str(exc) else 422)
        return {"id": user_id, "users": users.list_users(db)}
    finally:
        db.close()


@router.patch("/users/{user_id}")
def edit_user(request: Request, user_id: int, body: UserPatch) -> dict:
    db = _db(request)
    try:
        try:
            users.update_user(db, user_id, role=body.role, password=body.password, disabled=body.disabled)
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
            token_id, secret = users.create_api_token(db, user_id, body.name)
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
