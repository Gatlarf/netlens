"""Log forwarding to a syslog server or SIEM (see app/siem.py)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app import licence, siem
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["siem"])


def _doc(conn) -> dict[str, Any]:
    return {"allowed": licence.allows(conn, "siem"), "policy": siem.get_policy(conn), "status": siem.status(conn), "facilities": sorted(siem.FACILITIES)}


@router.get("/siem")
def get_siem(conn=Depends(get_conn)) -> dict[str, Any]:
    return _doc(conn)


@router.put("/siem")
def put_siem(body: dict, conn=Depends(get_conn)) -> dict[str, Any]:
    if not licence.allows(conn, "siem"):
        raise HTTPException(status_code=402, detail="log forwarding is part of the Small business and Enterprise editions (or the free trial): Settings → Licence")
    try:
        siem.save_policy(conn, body)
    except siem.SiemError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _doc(conn)


@router.post("/siem/test")
async def test_siem(conn=Depends(get_conn)) -> dict[str, Any]:
    try:
        await asyncio.to_thread(siem.test_message, conn)
    except siem.SiemError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True}
