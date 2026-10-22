"""The one switch for application statistics (which application and which device used how much traffic).

Off by default: in some countries this kind of data may not be collected at all, or only with consent, so nothing is read from a router and nothing
is stored until an administrator turns it on (Settings > Statistics). Switching it off again removes what was stored.
"""

from __future__ import annotations

import sqlite3

from app.db import get_setting, set_setting

KEY = "usage.collect"
TABLES = ("app_usage", "client_usage", "client_app_usage")


def enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, KEY) == "1"


def set_enabled(conn: sqlite3.Connection, on: bool) -> int:
    """Turn collecting on or off. Returns the number of stored rows that were removed (switching off removes them)."""
    set_setting(conn, KEY, "1" if on else "0")
    removed = 0
    if not on:
        for table in TABLES:
            removed += conn.execute(f"DELETE FROM {table}").rowcount
        conn.commit()
    return removed


def stored_rows(conn: sqlite3.Connection) -> int:
    return sum(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES)
