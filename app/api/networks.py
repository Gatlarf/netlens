"""Networks (app/networks.py): the ranges Netlens scans (and can scan), their state, names and the Scan switch."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app import networks
from app.api.config import apply_ranges
from app.auth import scope_of
from app.db import connect

router = APIRouter(prefix="/api", tags=["networks"])


class NewNetwork(BaseModel):
    cidr: str = Field(max_length=64)
    name: str = Field(default="", max_length=60)


class NetworkPatch(BaseModel):
    name: str | None = Field(default=None, max_length=60)
    scan: bool | None = None


def _db(request: Request):
    return connect(request.app.state.db_path)


async def _look_around(request: Request) -> None:
    """List the networks of this host's own network cards, so the list is complete before the first scan."""
    try:
        detected = list(await asyncio.wait_for(request.app.state.scan_manager.ranges_provider(), timeout=3))
    except Exception:  # noqa: BLE001 - detection only suggests
        return
    db = _db(request)
    try:
        networks.refresh_detected(db, detected)
    finally:
        db.close()


def _answer(request: Request) -> dict:
    db = _db(request)
    try:
        return {"networks": networks.listing(db)}
    finally:
        db.close()


@router.get("/networks")
async def list_networks(request: Request) -> dict:
    if scope_of(request) is not None:           # a viewer limited to some groups or sites does not see the layout of the network
        return {"networks": []}
    await _look_around(request)
    return _answer(request)


@router.post("/networks", status_code=201)
async def add_network(request: Request, body: NewNetwork) -> dict:
    db = _db(request)
    try:
        try:
            networks.add(db, body.cidr, body.name)
        except ValueError as exc:
            raise HTTPException(status_code=409 if "in the list already" in str(exc) else 422, detail=str(exc)) from None
    finally:
        db.close()
    apply_ranges(request.app)
    return _answer(request)


@router.patch("/networks/{network_id}")
async def edit_network(request: Request, network_id: int, body: NetworkPatch) -> dict:
    db = _db(request)
    try:
        try:
            if body.name is not None and not networks.rename(db, network_id, body.name):
                raise HTTPException(status_code=404, detail="no such network")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        if body.scan is not None and not networks.set_scan(db, network_id, body.scan):
            raise HTTPException(status_code=404, detail="no such network")
        if body.name is None and body.scan is None and db.execute("SELECT 1 FROM networks WHERE id = ?", (network_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="no such network")
    finally:
        db.close()
    apply_ranges(request.app)
    return _answer(request)


@router.delete("/networks/{network_id}")
async def remove_network(request: Request, network_id: int) -> dict:
    db = _db(request)
    try:
        try:
            found = networks.remove(db, network_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        if not found:
            raise HTTPException(status_code=404, detail="no such network")
    finally:
        db.close()
    apply_ranges(request.app)
    return _answer(request)
