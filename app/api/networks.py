"""Networks (app/networks.py): the scanned ranges with their state, and their names."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import networks
from app.auth import scope_of
from app.db import connect

router = APIRouter(prefix="/api", tags=["networks"])


class NetworkPatch(BaseModel):
    name: str = Field(max_length=60)


def _db(request: Request):
    return connect(request.app.state.db_path)


@router.get("/networks")
def list_networks(request: Request) -> dict:
    if scope_of(request) is not None:           # a viewer limited to some groups or sites does not see the layout of the network
        return {"networks": []}
    db = _db(request)
    try:
        return {"networks": networks.listing(db)}
    finally:
        db.close()


@router.patch("/networks/{network_id}")
def rename_network(request: Request, network_id: int, body: NetworkPatch) -> dict:
    db = _db(request)
    try:
        try:
            found = networks.rename(db, network_id, body.name)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if not found:
            raise HTTPException(status_code=404, detail="no such network")
        return {"networks": networks.listing(db)}
    finally:
        db.close()
