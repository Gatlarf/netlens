import sqlite3
from typing import Any

from fastapi import APIRouter, Depends

from app.api.devices import get_conn
from app.hierarchy import hierarchy_payload

router = APIRouter(prefix="/api", tags=["hierarchy"])


@router.get("/hierarchy")
def get_hierarchy(conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
    """Which device sits below which: flat nodes with parent_id, how the parent was found, and counts."""
    return hierarchy_payload(conn)
