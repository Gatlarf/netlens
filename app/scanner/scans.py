import sqlite3
from typing import Optional

from app.db import utcnow


def create_scan(conn: sqlite3.Connection, kind: str, now: str | None = None) -> int:
    conn.row_factory = sqlite3.Row
    started = now or utcnow()
    cursor = conn.execute(
        "INSERT INTO scans (kind, status, started) VALUES (?, ?, ?)",
        (kind, "running", started),
    )
    conn.commit()
    return cursor.lastrowid


def finish_scan(
    conn: sqlite3.Connection,
    scan_id: int,
    status: str,
    hosts_found: int = 0,
    error: str | None = None,
    now: str | None = None,
) -> None:
    if status not in ("done", "failed"):
        raise ValueError("status must be 'done' or 'failed'")

    conn.row_factory = sqlite3.Row
    finished = now or utcnow()

    row = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise KeyError(f"scan_id {scan_id} not found")

    conn.execute(
        "UPDATE scans SET status = ?, finished = ?, hosts_found = ?, error = ? WHERE id = ?",
        (status, finished, hosts_found, error, scan_id),
    )
    conn.commit()


def list_scans(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def running_scan(conn: sqlite3.Connection) -> dict | None:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM scans WHERE status = 'running' ORDER BY id DESC LIMIT 1",
    ).fetchone()
    if row is None:
        return None
    return dict(row)