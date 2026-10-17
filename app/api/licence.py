"""The licence of this installation: what it allows, installing a key, the free trial (see app/licence.py)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import licence
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["licence"])


class KeyBody(BaseModel):
    key: str


def _doc(conn) -> dict[str, Any]:
    from app import probes

    st = licence.status(conn)
    st["sites_used"] = conn.execute("SELECT COUNT(*) FROM probes").fetchone()[0]
    st["sites_frozen"] = len(probes.locked_ids(conn))
    return st


@router.get("/licence")
def get_licence(conn=Depends(get_conn)) -> dict[str, Any]:
    return _doc(conn)


@router.put("/licence")
def put_licence(body: KeyBody, conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        licence.install(conn, body.key)
    except licence.LicenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _doc(conn)


@router.delete("/licence")
def delete_licence(conn=Depends(get_conn)) -> dict[str, Any]:
    licence.remove(conn)
    return _doc(conn)


@router.post("/licence/trial")
def start_trial(conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        licence.start_trial(conn)
    except licence.LicenceError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _doc(conn)
