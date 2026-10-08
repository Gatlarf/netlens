import sqlite3
import statistics
from datetime import datetime, timezone
from typing import Optional

from app.db import utcnow


def create_scan(conn: sqlite3.Connection, kind: str, now: str | None = None, target: str | None = None) -> int:
    conn.row_factory = sqlite3.Row
    started = now or utcnow()
    cursor = conn.execute(
        "INSERT INTO scans (kind, status, started, target) VALUES (?, ?, ?, ?)",
        (kind, "running", started, target),
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
    if status not in ("done", "failed", "cancelled"):
        raise ValueError("status must be 'done', 'failed' or 'cancelled'")

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

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _seconds_between(start: str, end: str) -> float:
    return (datetime.strptime(end, _TS_FORMAT) - datetime.strptime(start, _TS_FORMAT)).total_seconds()


def typical_duration(conn: sqlite3.Connection, kind: str, limit: int = 20) -> tuple[int | None, int]:
    """Typical (median) duration in seconds of the last `limit` successfully finished scans of `kind`.

    The median is used instead of the mean so one scan that hung for an hour does not distort it.
    Returns (typical or None, number of scans used). Failed or unfinished scans are ignored.
    """
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT started, finished FROM scans WHERE kind = ? AND status = 'done' AND finished IS NOT NULL "
        "ORDER BY id DESC LIMIT ?",
        (kind, limit),
    ).fetchall()
    durations = []
    for row in rows:
        try:
            seconds = _seconds_between(row["started"], row["finished"])
        except (TypeError, ValueError):
            continue
        if seconds >= 0:
            durations.append(seconds)
    if not durations:
        return None, 0
    return round(statistics.median(durations)), len(durations)


def elapsed_seconds(started: str, now: datetime | None = None) -> int | None:
    """Seconds since `started` (never negative); None when the timestamp is unreadable."""
    try:
        begin = datetime.strptime(started, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return max(0, round(((now or datetime.now(timezone.utc)) - begin).total_seconds()))
