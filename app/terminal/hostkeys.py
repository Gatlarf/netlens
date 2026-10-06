from __future__ import annotations

import sqlite3
from typing import Optional

from app.db import utcnow


def get_fingerprint(conn: sqlite3.Connection, device_id: int) -> Optional[str]:
    """Return the stored fingerprint for a device, or None if not stored."""
    row = conn.execute(
        "SELECT fingerprint FROM host_keys WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    return row["fingerprint"]


def remember_fingerprint(
    conn: sqlite3.Connection,
    device_id: int,
    fingerprint: str,
    now: Optional[str] = None,
) -> None:
    """Store a fingerprint for a device. If a row already exists, leave it unchanged."""
    ts = now or utcnow()
    conn.execute(
        "INSERT OR IGNORE INTO host_keys (device_id, fingerprint, first_seen) VALUES (?, ?, ?)",
        (device_id, fingerprint, ts),
    )
    conn.commit()


def forget_fingerprint(conn: sqlite3.Connection, device_id: int) -> bool:
    """Delete the stored fingerprint for a device. Return True if a row was deleted."""
    cursor = conn.execute(
        "DELETE FROM host_keys WHERE device_id = ?",
        (device_id,),
    )
    conn.commit()
    return cursor.rowcount > 0


def check_fingerprint(
    conn: sqlite3.Connection,
    device_id: int,
    fingerprint: str,
) -> str:
    """
    Check a fingerprint against the stored value.

    Returns:
        "new"     – nothing is stored for this device (does NOT store it)
        "match"   – stored fingerprint equals the given one
        "mismatch" – stored fingerprint differs from the given one
    """
    stored = get_fingerprint(conn, device_id)
    if stored is None:
        return "new"
    if stored == fingerprint:
        return "match"
    return "mismatch"