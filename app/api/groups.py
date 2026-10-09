from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import groups
from app.db import connect

router = APIRouter(prefix="/api", tags=["groups"])


class NewGroup(BaseModel):
    name: str
    color: str | None = None


class GroupPatch(BaseModel):
    name: str | None = None
    color: str | None = None


def _db(request: Request):
    return connect(request.app.state.db_path)


@router.get("/groups")
def get_groups(request: Request) -> dict:
    conn = _db(request)
    try:
        return {"groups": groups.list_groups(conn)}
    finally:
        conn.close()


@router.post("/groups", status_code=201)
def add_group(request: Request, body: NewGroup) -> dict:
    conn = _db(request)
    try:
        try:
            group_id = groups.create(conn, body.name, body.color)
        except groups.GroupError as exc:
            raise HTTPException(status_code=409 if "exists" in str(exc) else 422, detail=str(exc))
        return {"id": group_id, "groups": groups.list_groups(conn)}
    finally:
        conn.close()


@router.patch("/groups/{group_id}")
def edit_group(request: Request, group_id: int, body: GroupPatch) -> dict:
    conn = _db(request)
    try:
        try:
            groups.update(conn, group_id, body.name, body.color)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such group")
        except groups.GroupError as exc:
            raise HTTPException(status_code=409 if "exists" in str(exc) else 422, detail=str(exc))
        return {"groups": groups.list_groups(conn)}
    finally:
        conn.close()


@router.delete("/groups/{group_id}")
def remove_group(request: Request, group_id: int) -> dict:
    conn = _db(request)
    try:
        try:
            groups.delete(conn, group_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such group")
        return {"groups": groups.list_groups(conn)}
    finally:
        conn.close()
