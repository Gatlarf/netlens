"""This installation as a remote site of a central Netlens (see app/central.py)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import central
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["central"])


class LinkBody(BaseModel):
    url: str | None = None
    token: str | None = None
    enabled: bool | None = None
    interval_s: int | None = None
    accept_config: bool | None = None
    allow_view: bool | None = None             # let the central Netlens show this site's pages (read only, through app/relay.py)
    trust_certificate: bool | None = None       # True: trust the certificate the central Netlens shows now (self-signed); False: back to normal checking


@router.get("/central")
def get_link(conn=Depends(get_conn)) -> dict[str, Any]:
    return central.public_link(conn)


@router.put("/central")
def put_link(body: LinkBody, conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        return central.set_link(conn, body.model_dump(exclude_unset=True))
    except central.LinkError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/central/push")
async def push_now(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Send a report now and say what happened."""
    link = central.get_link(conn)
    if not link["url"] or not link["token"]:
        raise HTTPException(status_code=422, detail="enter the address of the central Netlens and the token first")
    status = await asyncio.to_thread(central.push_once, request.app.state.db_path, None, True)
    if status.get("commands"):
        await central.run_commands(status, request.app.state.scan_manager)
    return {"status": status, **central.public_link(conn)}
