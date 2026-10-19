"""The outcome of every plugin sync, kept like the results of a service check: a heartbeat bar, the share of good syncs and how long a sync took.

A plugin is shown on the Services page next to the service checks (see /api/plugin-runs); the graph comes from the metrics store under the entity "plugin".
"""

from __future__ import annotations

import sqlite3
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any

from app import tsdb
from app.db import utcnow

RETENTION_DAYS = 30
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def series_id(plugin_id: str) -> int:
    """The number a plugin has in the metrics store (which numbers its things): stable, from the plugin id."""
    return zlib.crc32(plugin_id.encode()) & 0x7FFFFFFF


def record(conn: sqlite3.Connection, plugin_id: str, ok: bool, ms: float | None, detail: str = "") -> None:
    """One sync finished. The time is only kept for a good sync (a timeout says nothing about how fast the plugin is)."""
    now = utcnow()
    conn.execute("INSERT INTO plugin_runs (plugin_id, ts, ok, ms, detail) VALUES (?, ?, ?, ?, ?)", (plugin_id, now, 1 if ok else 0, ms if ok else None, detail[:300]))
    conn.execute("DELETE FROM plugin_runs WHERE plugin_id = ? AND ts < ?", (plugin_id, (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).strftime(STAMP)))
    conn.commit()
    store = tsdb.for_conn(conn)
    if store is not None:
        sid = series_id(plugin_id)
        points = [("plugin", sid, "up", 1 if ok else 0, "", "state")]
        if ok and ms is not None:
            points.append(("plugin", sid, "response_ms", ms, "", "ms"))
        store.record(points, ts=int(datetime.now(timezone.utc).timestamp()))


def history(conn: sqlite3.Connection, plugin_id: str, limit: int = 60) -> list[dict[str, Any]]:
    """The newest `limit` syncs, oldest first."""
    rows = conn.execute("SELECT ts, ok, ms, detail FROM plugin_runs WHERE plugin_id = ? ORDER BY id DESC LIMIT ?", (plugin_id, limit)).fetchall()
    return [{"ts": r["ts"], "up": bool(r["ok"]), "ms": r["ms"], "detail": r["detail"]} for r in reversed(rows)]


def uptime_24h(conn: sqlite3.Connection, plugin_id: str) -> float | None:
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(STAMP)
    row = conn.execute("SELECT SUM(ok) AS u, COUNT(*) AS n FROM plugin_runs WHERE plugin_id = ? AND ts >= ?", (plugin_id, since)).fetchone()
    return round(row["u"] / row["n"] * 100, 2) if row["n"] else None


def forget(conn: sqlite3.Connection, plugin_id: str) -> None:
    conn.execute("DELETE FROM plugin_runs WHERE plugin_id = ?", (plugin_id,))
