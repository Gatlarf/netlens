import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["ignored"])


@router.get("/ignored")
def list_ignored(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict[str, Any]]:
    """Devices that scans skip (deleted with 'ignore'). Newest first."""
    rows = conn.execute("SELECT id, mac, ip, label, added FROM ignored_devices ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


@router.delete("/ignored/{ignored_id}", status_code=204)
def stop_ignoring(ignored_id: int, conn: sqlite3.Connection = Depends(get_conn)) -> None:
    """Stop ignoring a device: the next scan adds it again if it is on the network."""
    cursor = conn.execute("DELETE FROM ignored_devices WHERE id = ?", (ignored_id,))
    conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="not on the ignore list")
