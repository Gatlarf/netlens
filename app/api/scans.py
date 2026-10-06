from typing import Any

import sqlite3

from fastapi import APIRouter, Depends, Query

from app.api.devices import get_conn
from app.scanner.scans import list_scans, running_scan

router = APIRouter(prefix="/api", tags=["scans"])


@router.get("/scans")
def get_scans(
    limit: int = Query(50, ge=1, le=200),
    conn: sqlite3.Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    return list_scans(conn, limit)


@router.get("/scans/current")
def get_current_scan(
    conn: sqlite3.Connection = Depends(get_conn),
) -> dict[str, Any]:
    scan = running_scan(conn)
    return {"running": scan is not None, "scan": scan}