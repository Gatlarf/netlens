"""Link groups (app/linkgroups.py): which switch ports carry a host's bond."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import linkgroups
from app.auth import scope_of
from app.db import connect

router = APIRouter(prefix="/api", tags=["link groups"])


class NewGroup(BaseModel):
    name: str = Field(max_length=60)
    host_device_id: int
    switch_device_id: int
    ports: list[int] = Field(max_length=linkgroups.MAX_PORTS)


class GroupPatch(BaseModel):
    name: str | None = Field(default=None, max_length=60)
    ports: list[int] | None = Field(default=None, max_length=linkgroups.MAX_PORTS)


def _db(request: Request):
    return connect(request.app.state.db_path)


@router.get("/link-groups")
def list_groups(request: Request, device_id: int | None = None) -> dict:
    if scope_of(request) is not None:           # a viewer limited to some groups or sites sees the devices of those only: no bonds here
        return {"groups": []}
    db = _db(request)
    try:
        return {"groups": linkgroups.listing(db, device_id)}
    finally:
        db.close()


@router.get("/link-groups/switches")
def switches(request: Request) -> dict:
    """The devices that report switch ports, with their ports: what the form for a new group offers."""
    if scope_of(request) is not None:
        return {"switches": []}
    db = _db(request)
    try:
        names = linkgroups._names(db)
        out = []
        for row in db.execute("SELECT DISTINCT device_id FROM switch_ports").fetchall():
            ports = [{"port": r["port"], "name": r["name"], "up": bool(r["up"]), "speed_mbps": r["speed_mbps"]} for r in db.execute("SELECT port, name, up, speed_mbps FROM switch_ports WHERE device_id = ? ORDER BY port", (row["device_id"],))]
            out.append({"id": row["device_id"], "name": names.get(row["device_id"]), "ports": ports})
        return {"switches": sorted(out, key=lambda x: (x["name"] or "").lower())}
    finally:
        db.close()


@router.post("/link-groups", status_code=201)
def add_group(request: Request, body: NewGroup) -> dict:
    db = _db(request)
    try:
        try:
            group_id = linkgroups.create(db, body.name, body.host_device_id, body.switch_device_id, body.ports)
        except linkgroups.LinkGroupError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"id": group_id, "groups": linkgroups.listing(db, body.host_device_id)}
    finally:
        db.close()


@router.patch("/link-groups/{group_id}")
def edit_group(request: Request, group_id: int, body: GroupPatch) -> dict:
    db = _db(request)
    try:
        try:
            linkgroups.update(db, group_id, body.name, body.ports)
        except linkgroups.LinkGroupError as exc:
            raise HTTPException(status_code=404 if str(exc) == "no such group" else 422, detail=str(exc)) from None
        return {"groups": [g for g in linkgroups.listing(db) if g["id"] == group_id]}
    finally:
        db.close()


@router.delete("/link-groups/{group_id}")
def remove_group(request: Request, group_id: int) -> dict:
    db = _db(request)
    try:
        if not linkgroups.delete(db, group_id):
            raise HTTPException(status_code=404, detail="no such group")
        return {"ok": True}
    finally:
        db.close()
