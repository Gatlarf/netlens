"""Database maintenance: what the data takes, how long it is kept, and the tools to tidy it (Settings → Database).

Netlens keeps two SQLite files: `netlens.db` (devices, events, scans, settings ...) and `metrics.db` (the graphs, in three tiers that
prune themselves). Most tables are pruned as they go (checks, service results, the audit log); the events and the scan list used to grow
for ever. This module adds the retention for those, a check for rows that point at things that no longer exist (a removed device,
check or remote site), and the usual upkeep: ANALYZE, REINDEX, a WAL checkpoint, VACUUM and an integrity check. A weekly run does the safe
parts by itself (purge, orphans, optimize, checkpoint); compacting is a button because it needs free disk space and blocks writes for a moment.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app import dbengine, tsdb
from app.db import get_setting, set_setting

log = logging.getLogger(__name__)

RETENTION_KEY = "maintenance.retention"
LAST_KEY = "maintenance.last"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
# name -> (default days, lowest, highest); 0 for "keep for ever" is allowed where the default is not 0 only for events and scans
RETENTION = {
    "events_days": (730, 30, 3650, "Events (alerts, changes)"),
    "scans_days": (365, 30, 3650, "The list of finished scans"),
    "checks_days": (90, 7, 365, "Presence checks of devices (the uptime history)"),
    "service_results_days": (30, 7, 365, "Results of service checks"),
    "audit_days": (365, 30, 3650, "The audit log"),
}
FOREVER = {"events_days", "scans_days"}          # these may also be switched off (0)


class MaintError(ValueError):
    pass


# ----------------------------------------------------------------------------- the settings
def retention(conn: sqlite3.Connection) -> dict[str, int]:
    try:
        saved = json.loads(get_setting(conn, RETENTION_KEY) or "{}")
    except ValueError:
        saved = {}
    out = {}
    for key, (default, low, high, _) in RETENTION.items():
        value = saved.get(key, default) if isinstance(saved, dict) else default
        ok = isinstance(value, int) and not isinstance(value, bool) and (low <= value <= high or (value == 0 and key in FOREVER))
        out[key] = value if ok else default
    return out


def save_retention(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, int]:
    current = retention(conn)
    for key, value in (data or {}).items():
        if key not in RETENTION:
            raise MaintError(f"unknown setting {key}")
        _, low, high, label = RETENTION[key]
        if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high or (value == 0 and key in FOREVER)):
            raise MaintError(f"{label}: between {low} and {high} days" + (", or 0 to keep it for ever" if key in FOREVER else ""))
        current[key] = value
    set_setting(conn, RETENTION_KEY, json.dumps(current))
    conn.commit()
    return current


def days(conn: sqlite3.Connection, key: str) -> int:
    """For the code that prunes by itself."""
    return retention(conn)[key]


# ----------------------------------------------------------------------------- what there is
def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def main_path(conn: sqlite3.Connection) -> Path | None:
    p = tsdb.db_file(conn)
    return Path(p) if p else None


def table_names(conn: sqlite3.Connection) -> list[str]:
    return dbengine.table_names(conn)


def table_sizes(conn: sqlite3.Connection) -> dict[str, int] | None:
    """Bytes per table (with its indexes) when SQLite was built with the dbstat view; None otherwise."""
    try:
        owner = {r[0]: (r[1] if r[2] == "index" else r[0]) for r in conn.execute("SELECT name, tbl_name, type FROM sqlite_master")}
        out: dict[str, int] = {}
        for name, size in conn.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name"):
            table = owner.get(name)
            if table:
                out[table] = out.get(table, 0) + int(size or 0)
        return out
    except sqlite3.Error:
        return None


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    path = main_path(conn)
    page = conn.execute("PRAGMA page_size").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    sizes = table_sizes(conn)
    tables = []
    for name in table_names(conn):
        try:
            rows = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.Error:
            continue
        tables.append({"name": name, "rows": rows, "bytes": (sizes or {}).get(name)})
    tables.sort(key=lambda t: (-(t["bytes"] or 0), -t["rows"]))
    metrics = Path(tsdb.for_conn(conn).path) if tsdb.for_conn(conn) else None
    series = {}
    if metrics and metrics.exists():
        try:
            m = tsdb.for_conn(conn)._connect()
            try:
                series = {"series": m.execute("SELECT COUNT(*) FROM series").fetchone()[0], "raw": m.execute("SELECT COUNT(*) FROM raw").fetchone()[0],
                          "m5": m.execute("SELECT COUNT(*) FROM m5").fetchone()[0], "h1": m.execute("SELECT COUNT(*) FROM h1").fetchone()[0]}
            finally:
                m.close()
        except sqlite3.Error:
            series = {}
    disk = shutil.disk_usage(path.parent) if path else None
    oldest = {}
    for key, sql in (("events", "SELECT MIN(ts) FROM events"), ("scans", "SELECT MIN(started) FROM scans"), ("checks", "SELECT MIN(ts) FROM checks"),
                     ("service_results", "SELECT MIN(ts) FROM service_results"), ("audit", "SELECT MIN(ts) FROM audit_log")):
        try:
            oldest[key] = conn.execute(sql).fetchone()[0]
        except sqlite3.Error:
            oldest[key] = None
    return {"main": {"bytes": _file_size(path) if path else 0, "wal_bytes": _file_size(Path(str(path) + "-wal")) if path else 0, "page_size": page, "pages": pages,
                     "reclaimable_bytes": free * page},
            "metrics": {"bytes": _file_size(metrics) if metrics else 0, "wal_bytes": _file_size(Path(str(metrics) + "-wal")) if metrics else 0, **series},
            "disk": {"free_bytes": disk.free, "total_bytes": disk.total} if disk else None, "tables": tables, "retention": retention(conn),
            "retention_info": {k: {"default": v[0], "min": v[1], "max": v[2], "label": v[3], "forever": k in FOREVER} for k, v in RETENTION.items()},
            "oldest": oldest, "last": last_run(conn)}


def last_run(conn: sqlite3.Connection) -> dict[str, Any] | None:
    try:
        data = json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _remember(conn: sqlite3.Connection, what: str, result: dict[str, Any]) -> None:
    last = last_run(conn) or {}
    last[what] = {"ts": datetime.now(timezone.utc).strftime(STAMP), **result}
    set_setting(conn, LAST_KEY, json.dumps(last))
    conn.commit()


# ----------------------------------------------------------------------------- purging
def _cutoff(n_days: int, now: datetime) -> str:
    return (now - timedelta(days=n_days)).strftime(STAMP)


def purge(conn: sqlite3.Connection, dry_run: bool = False, now: datetime | None = None) -> dict[str, int]:
    """Remove what is older than the retention. With dry_run only count it."""
    now = now or datetime.now(timezone.utc)
    keep = retention(conn)
    jobs = [("events", "events", "ts", keep["events_days"]), ("scans", "scans", "started", keep["scans_days"]), ("checks", "checks", "ts", keep["checks_days"]),
            ("service_results", "service_results", "ts", keep["service_results_days"]), ("audit", "audit_log", "ts", keep["audit_days"])]
    out: dict[str, int] = {}
    for name, table, column, n_days in jobs:
        if not n_days:
            out[name] = 0
            continue
        cutoff = _cutoff(n_days, now)
        extra = " AND status != 'running'" if table == "scans" else ""
        try:
            if dry_run:
                out[name] = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} < ?{extra}", (cutoff,)).fetchone()[0]
            else:
                out[name] = conn.execute(f"DELETE FROM {table} WHERE {column} < ?{extra}", (cutoff,)).rowcount
        except sqlite3.Error:
            out[name] = 0
    now_s = now.strftime(STAMP)
    try:       # a sign-in session that has run out is of no use to anybody
        if dry_run:
            out["sessions"] = conn.execute("SELECT COUNT(*) FROM sessions WHERE expires < ?", (now_s,)).fetchone()[0]
        else:
            out["sessions"] = conn.execute("DELETE FROM sessions WHERE expires < ?", (now_s,)).rowcount
    except sqlite3.Error:
        out["sessions"] = 0
    try:      # the remote sites with a retention of their own
        from app import probes

        out.update(probes.trim_history(conn, now=now.timestamp(), dry_run=dry_run))
    except sqlite3.Error:
        pass
    if not dry_run:
        conn.commit()
    return out


# ----------------------------------------------------------------------------- rows that point at nothing
# (table, column, parent table, parent column): a row whose parent is gone is left over from a removal
ORPHANS = (
    ("service_results", "check_id", "service_checks", "id"),
    ("metric_state", "monitor_id", "host_monitors", "id"),
    ("probe_snapshots", "device_id", "devices", "id"),
    ("checks", "device_id", "devices", "id"),
    ("checks_hourly", "device_id", "devices", "id"),
    ("port_baselines", "device_id", "devices", "id"),
    ("wifi_samples", "device_id", "devices", "id"),
    ("remote_devices", "probe_id", "probes", "id"),
    ("remote_services", "probe_id", "probes", "id"),
)
# graph series whose subject is gone: entity -> (table, column)
SERIES_OWNERS = {"device": ("devices", "id"), "service": ("service_checks", "id"), "remote": ("remote_devices", "id"), "remote_service": ("remote_services", "id"),
                 "probe": ("probes", "id")}
SETTING_PREFIXES = (("probe.config.", "probes"), ("probe.commands.", "probes"))


def orphans(conn: sqlite3.Connection, dry_run: bool = False) -> dict[str, int]:
    out: dict[str, int] = {}
    for table, column, parent, pcolumn in ORPHANS:
        try:
            sql = f"FROM {table} WHERE {column} IS NOT NULL AND {column} NOT IN (SELECT {pcolumn} FROM {parent})"
            out[table] = conn.execute(f"SELECT COUNT(*) {sql}").fetchone()[0] if dry_run else conn.execute(f"DELETE {sql}").rowcount
        except sqlite3.Error:
            continue
    # the settings a removed remote site left behind
    left = 0
    live = {str(r[0]) for r in conn.execute("SELECT id FROM probes")}
    for key, in conn.execute("SELECT key FROM settings WHERE key LIKE 'probe.config.%' OR key LIKE 'probe.commands.%'").fetchall():
        if key.rsplit(".", 1)[1] not in live:
            left += 1
            if not dry_run:
                conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    out["settings"] = left
    if not dry_run:
        conn.commit()
    out["graph_series"] = graph_orphans(conn, dry_run)
    return out


def graph_orphans(conn: sqlite3.Connection, dry_run: bool = False) -> int:
    """Forget the graph series of devices, checks and remote sites that no longer exist."""
    store = tsdb.for_conn(conn)
    if store is None:
        return 0
    gone = 0
    for entity, entity_id in store.series_owners():
        owner = SERIES_OWNERS.get(entity)
        if owner is None:
            continue
        if conn.execute(f"SELECT 1 FROM {owner[0]} WHERE {owner[1]} = ?", (entity_id,)).fetchone() is None:
            gone += 1
            if not dry_run:
                store.forget(entity, entity_id)
    return gone


# ----------------------------------------------------------------------------- upkeep
def optimize(conn: sqlite3.Connection) -> dict[str, Any]:
    started = time.monotonic()
    conn.execute("ANALYZE")
    conn.execute("PRAGMA optimize")
    conn.commit()
    return {"seconds": round(time.monotonic() - started, 1)}


def reindex(conn: sqlite3.Connection) -> dict[str, Any]:
    started = time.monotonic()
    conn.execute("REINDEX")
    conn.commit()
    return {"seconds": round(time.monotonic() - started, 1)}


def checkpoint(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    store = tsdb.for_conn(conn)
    if store is not None:
        m = store._connect()
        try:
            m.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            m.close()
    return {"busy": bool(row[0]) if row else False}


def compact(conn: sqlite3.Connection) -> dict[str, Any]:
    """VACUUM both files. Needs free disk space of about the size of the larger file; writers wait for a moment."""
    path = main_path(conn)
    if path is None:
        raise MaintError("this database lives in memory")
    store = tsdb.for_conn(conn)
    before = _file_size(path) + (_file_size(Path(store.path)) if store else 0)
    need = max(_file_size(path), _file_size(Path(store.path)) if store else 0) * 12 // 10
    free = shutil.disk_usage(path.parent).free
    if free < need:
        raise MaintError(f"not enough free disk space to compact: about {need // 1_000_000} MB is needed, {free // 1_000_000} MB is free")
    started = time.monotonic()
    conn.commit()
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        if store is not None:
            m = store._connect()
            try:
                m.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                m.execute("VACUUM")
            finally:
                m.close()
    except sqlite3.OperationalError as exc:
        raise MaintError(f"could not compact right now ({exc}); try again in a minute") from None
    after = _file_size(path) + (_file_size(Path(store.path)) if store else 0)
    return {"seconds": round(time.monotonic() - started, 1), "before_bytes": before, "after_bytes": after}


def integrity(conn: sqlite3.Connection) -> dict[str, Any]:
    main = [r[0] for r in conn.execute("PRAGMA integrity_check(5)")]
    keys = conn.execute("PRAGMA foreign_key_check").fetchall()
    metrics: list[str] = []
    store = tsdb.for_conn(conn)
    if store is not None:
        m = store._connect()
        try:
            metrics = [r[0] for r in m.execute("PRAGMA quick_check(5)")]
        finally:
            m.close()
    return {"main": main, "metrics": metrics, "foreign_key_problems": len(keys), "ok": main == ["ok"] and (metrics in ([], ["ok"])) and not keys}


def tidy(conn: sqlite3.Connection) -> dict[str, Any]:
    """The safe parts, as the weekly run does them: purge, orphans, optimize, checkpoint."""
    result = {"purged": purge(conn), "orphans": orphans(conn), "optimize": optimize(conn), "checkpoint": checkpoint(conn)}
    store = tsdb.for_conn(conn)
    if store is not None:
        store.maintain()
    return result


def run_tidy(conn: sqlite3.Connection) -> dict[str, Any]:
    result = tidy(conn)
    _remember(conn, "tidy", {"summary": result})
    return result


def due(conn: sqlite3.Connection, now: datetime | None = None) -> bool:
    """The automatic run: once a week, on the first check after Sunday 03:30 UTC has passed since the last one."""
    now = now or datetime.now(timezone.utc)
    last = (last_run(conn) or {}).get("tidy", {}).get("ts")
    if last:
        try:
            if now - datetime.strptime(last, STAMP).replace(tzinfo=timezone.utc) < timedelta(days=6, hours=20):
                return False
        except ValueError:
            pass
    return now.weekday() == 6 and (now.hour, now.minute) >= (3, 30) or bool(not last and now.hour == 4)
