"""Settings → Database: sizes, retention and the maintenance tools (see app/dbmaint.py). Administrators only."""

from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import dbmaint
from app.db import connect

router = APIRouter(prefix="/api/database", tags=["database"])
_busy = threading.Lock()


class RetentionBody(BaseModel):
    events_days: int | None = None
    scans_days: int | None = None
    checks_days: int | None = None
    service_results_days: int | None = None
    audit_days: int | None = None


class DryBody(BaseModel):
    dry_run: bool = False


def _work(request: Request, job, remember: str | None = None) -> dict[str, Any]:
    """Run one maintenance job on a connection of its own; only one runs at a time."""
    if not _busy.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="another maintenance job is running; wait for it to finish")
    conn = connect(request.app.state.db_path)
    try:
        result = job(conn)
        if remember:
            dbmaint._remember(conn, remember, {"summary": result})
        return result
    except dbmaint.MaintError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    finally:
        conn.close()
        _busy.release()


@router.get("")
def get_overview(request: Request) -> dict[str, Any]:
    conn = connect(request.app.state.db_path)
    try:
        return {**dbmaint.overview(conn), "busy": _busy.locked()}
    finally:
        conn.close()


@router.put("/retention")
def put_retention(body: RetentionBody, request: Request) -> dict[str, Any]:
    conn = connect(request.app.state.db_path)
    try:
        return {"retention": dbmaint.save_retention(conn, body.model_dump(exclude_unset=True))}
    except dbmaint.MaintError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()


@router.post("/purge")
def post_purge(body: DryBody, request: Request) -> dict[str, Any]:
    return {"dry_run": body.dry_run, "removed": _work(request, lambda c: dbmaint.purge(c, dry_run=body.dry_run), None if body.dry_run else "purge")}


@router.post("/orphans")
def post_orphans(body: DryBody, request: Request) -> dict[str, Any]:
    return {"dry_run": body.dry_run, "removed": _work(request, lambda c: dbmaint.orphans(c, dry_run=body.dry_run), None if body.dry_run else "orphans")}


@router.post("/optimize")
def post_optimize(request: Request) -> dict[str, Any]:
    return _work(request, dbmaint.optimize, "optimize")


@router.post("/reindex")
def post_reindex(request: Request) -> dict[str, Any]:
    return _work(request, dbmaint.reindex, "reindex")


@router.post("/compact")
def post_compact(request: Request) -> dict[str, Any]:
    return _work(request, dbmaint.compact, "compact")


@router.post("/integrity")
def post_integrity(request: Request) -> dict[str, Any]:
    return _work(request, dbmaint.integrity, "integrity")


@router.post("/tidy")
def post_tidy(request: Request) -> dict[str, Any]:
    return _work(request, dbmaint.run_tidy)
