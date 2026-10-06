Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
Routes must receive the connection through FastAPI dependency injection: add 'conn: sqlite3.Connection = Depends(get_conn)' as a parameter of each route function (import Depends from fastapi, sqlite3) and remove the direct get_conn() calls. get_conn is a generator dependency; it must never be called directly.

CURRENT FILE:
from typing import Any

from fastapi import APIRouter, Query

from app.api.devices import get_conn
from app.scanner.scans import list_scans, running_scan

router = APIRouter(prefix="/api", tags=["scans"])


@router.get("/scans")
def get_scans(
    limit: int = Query(50, ge=1, le=200),
) -> list[dict[str, Any]]:
    conn = get_conn()
    return list_scans(conn, limit)


@router.get("/scans/current")
def get_current_scan() -> dict[str, Any]:
    conn = get_conn()
    scan = running_scan(conn)
    return {"running": scan is not None, "scan": scan}