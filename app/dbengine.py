"""The few things that differ between database engines, in one place.

Netlens runs on SQLite today. Everything that is SQLite-only and that ordinary application code needs (listing the tables, a light "refresh the statistics",
copying the whole database) is here, so that a second engine is a matter of adding its version of these functions. The rest of the application sticks to the
portable SQL in docs/SQL-RULES.md; tests/test_portable_sql.py fails when it does not.

Modules that are SQLite files by nature (app/db.py with the schema and its migrations, app/tsdb.py, app/backup.py, app/dbmaint.py) may use SQLite directly;
they are listed in that test and are the work list for a second engine.
"""
from __future__ import annotations

import os
import sqlite3


def table_names(conn: sqlite3.Connection) -> list[str]:
    """The tables of the application (no engine-internal ones), by name."""
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def epoch_sql(column: str) -> str:
    """An SQL expression that turns a stored ISO timestamp column (2026-10-20T10:00:00Z) into whole seconds since 1970."""
    return f"CAST(strftime('%s', {column}) AS INTEGER)"


def optimize(conn: sqlite3.Connection) -> None:
    """Let the engine refresh its query statistics when a table has changed a lot (cheap when nothing changed)."""
    conn.execute("PRAGMA optimize")


def copy_database(conn: sqlite3.Connection, dest_path: str | os.PathLike) -> None:
    """A consistent copy of the whole database in a new file (works while the database is in use)."""
    dst = sqlite3.connect(os.fspath(dest_path))
    try:
        conn.backup(dst)
    finally:
        dst.close()
