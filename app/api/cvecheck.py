"""Settings and control of the version-based CVE check (see app/cvecheck.py). Part of the vulnerabilities feature: without a licence it does nothing."""

from __future__ import annotations

import threading
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app import cvecheck, licence
from app.api.devices import get_conn
from app.db import connect

router = APIRouter(prefix="/api/cve-check", tags=["vulnerabilities"])
_running = threading.Lock()


class CveCheckBody(BaseModel):
    enabled: bool | None = None
    min_severity: Literal["critical", "high", "medium", "low"] | None = None
    api_key: str | None = Field(default=None, max_length=100)
    clear_api_key: bool = False


def _allowed(conn) -> None:
    if not licence.allows(conn, "vulnerabilities"):
        raise HTTPException(402, "The CVE check is part of the vulnerabilities feature, which needs a licence or the free trial.")


def run_in_background(db_path: str) -> bool:
    """Start a run unless one is going; False when one already is."""
    if not _running.acquire(blocking=False):
        return False

    def work() -> None:
        conn = connect(db_path)
        try:
            cvecheck.run(conn)
        finally:
            conn.close()
            _running.release()

    threading.Thread(target=work, daemon=True).start()
    return True


@router.get("")
def state(conn=Depends(get_conn)) -> dict:
    return {**cvecheck.public_state(conn), "allowed": licence.allows(conn, "vulnerabilities"), "running": _running.locked()}


@router.put("")
def change(body: CveCheckBody, request: Request, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    was = cvecheck.get_settings(conn)["enabled"]
    cvecheck.save_settings(conn, body.model_dump(exclude_none=True))
    if was and body.enabled is False:
        cvecheck.remove(conn)                  # switched off: what it found goes away
    elif body.enabled and not was:
        run_in_background(request.app.state.db_path)
    return state(conn)


@router.post("/run")
def run_now(request: Request, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    if not cvecheck.get_settings(conn)["enabled"]:
        raise HTTPException(409, "Switch the check on first.")
    if not run_in_background(request.app.state.db_path):
        raise HTTPException(409, "A check is already running.")
    return state(conn)
