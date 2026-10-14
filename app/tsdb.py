"""Time-series store for the performance graphs: response times, host metrics, service results.

It is a second SQLite file (`metrics.db`) next to the main database, so the steady stream of small writes never waits for,
or blocks, the rest of the application. The data is derived (it can always be measured again), so it is left out of backups.

A series is one measured value over time: (entity, entity id, metric, label). The entity is `device`, `service` or `probe`;
the label separates several instances of a metric (a disk mount point, a network interface).

Three tiers keep the file small however long Netlens runs:

    raw      every sample                         kept 7 days
    5 min    count / sum / min / max per bucket   kept 90 days
    1 hour   the same, per hour                   kept 2 years

`rollup` folds raw samples into the 5-minute tier and that into the hourly tier; `prune` removes what is older than the
retention. A query picks the tier that fits the time span and returns about as many points as the graph has pixels.
"""

from __future__ import annotations

import calendar
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)

RAW_SECONDS = 7 * 86400
M5_SECONDS = 90 * 86400
H1_SECONDS = 730 * 86400
STEP_5M, STEP_1H = 300, 3600
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "1y": 365 * 86400}
MAX_POINTS = 600
ENTITIES = ("device", "service", "probe", "remote", "remote_service")

_stores: dict[str, "Store"] = {}
_lock = threading.Lock()


def db_file(conn: sqlite3.Connection) -> str:
    try:
        for _seq, name, path in conn.execute("PRAGMA database_list"):
            if name == "main":
                return path or ""
    except sqlite3.Error:
        pass
    return ""


def for_conn(conn: sqlite3.Connection) -> "Store | None":
    """The store that belongs to this main database; None for an in-memory database (nothing is recorded)."""
    main = db_file(conn)
    return for_path(main) if main else None


def for_path(main_db: str | os.PathLike) -> "Store":
    path = str(Path(os.fspath(main_db)).resolve().with_name("metrics.db"))
    with _lock:
        store = _stores.get(path)
        if store is None:
            store = _stores[path] = Store(path)
        return store


def forget_all() -> None:
    """For tests: drop the cached stores."""
    with _lock:
        _stores.clear()


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        self._ids: dict[tuple, int] = {}
        self._ready = False
        self._guard = threading.Lock()

    # ------------------------------------------------------------------ connection and schema
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        if not self._ready:
            with self._guard:
                if not self._ready:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS series (
                            id INTEGER PRIMARY KEY,
                            entity TEXT NOT NULL,
                            entity_id INTEGER NOT NULL,
                            metric TEXT NOT NULL,
                            label TEXT NOT NULL DEFAULT '',
                            unit TEXT NOT NULL DEFAULT '',
                            UNIQUE (entity, entity_id, metric, label)
                        );
                        CREATE TABLE IF NOT EXISTS raw (series INTEGER NOT NULL, ts INTEGER NOT NULL, v REAL NOT NULL, PRIMARY KEY (series, ts)) WITHOUT ROWID;
                        CREATE TABLE IF NOT EXISTS m5 (series INTEGER NOT NULL, ts INTEGER NOT NULL, n INTEGER NOT NULL, s REAL NOT NULL, lo REAL NOT NULL, hi REAL NOT NULL, PRIMARY KEY (series, ts)) WITHOUT ROWID;
                        CREATE TABLE IF NOT EXISTS h1 (series INTEGER NOT NULL, ts INTEGER NOT NULL, n INTEGER NOT NULL, s REAL NOT NULL, lo REAL NOT NULL, hi REAL NOT NULL, PRIMARY KEY (series, ts)) WITHOUT ROWID;
                        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
                        """
                    )
                    conn.commit()
                    self._ready = True
        return conn

    def _series_id(self, conn: sqlite3.Connection, entity: str, entity_id: int, metric: str, label: str, unit: str) -> int:
        key = (entity, entity_id, metric, label)
        found = self._ids.get(key)
        if found is not None:
            return found
        row = conn.execute("SELECT id FROM series WHERE entity = ? AND entity_id = ? AND metric = ? AND label = ?", key).fetchone()
        if row is None:
            cur = conn.execute("INSERT INTO series (entity, entity_id, metric, label, unit) VALUES (?,?,?,?,?)", (*key, unit))
            sid = cur.lastrowid
        else:
            sid = row["id"]
            if unit:
                conn.execute("UPDATE series SET unit = ? WHERE id = ? AND unit != ?", (unit, sid, unit))
        self._ids[key] = sid
        return sid

    # ------------------------------------------------------------------ writing
    def record(self, points: Iterable[tuple], ts: int | None = None) -> int:
        """Store samples. A point is (entity, entity_id, metric, value) or (..., value, label) or (..., value, label, unit)."""
        ts = int(ts if ts is not None else time.time())
        rows = 0
        try:
            conn = self._connect()
            try:
                for p in points:
                    entity, entity_id, metric, value = p[0], p[1], p[2], p[3]
                    label = p[4] if len(p) > 4 and p[4] else ""
                    unit = p[5] if len(p) > 5 and p[5] else ""
                    if value is None or entity not in ENTITIES:
                        continue
                    try:
                        value = float(value)
                    except (TypeError, ValueError):
                        continue
                    if value != value or value in (float("inf"), float("-inf")):
                        continue
                    sid = self._series_id(conn, entity, int(entity_id), str(metric), str(label), str(unit))
                    conn.execute("INSERT OR REPLACE INTO raw (series, ts, v) VALUES (?,?,?)", (sid, ts, value))
                    rows += 1
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            log.exception("could not record metrics")
            self._ids.clear()
        return rows

    def record_bulk(self, rows: Iterable[tuple]) -> int:
        """Many samples with their own times in one go: (ts, entity, entity_id, metric, value, label, unit)."""
        n = 0
        try:
            conn = self._connect()
            try:
                for ts, entity, entity_id, metric, value, label, unit in rows:
                    if value is None or entity not in ENTITIES:
                        continue
                    sid = self._series_id(conn, entity, int(entity_id), str(metric), str(label or ""), str(unit or ""))
                    conn.execute("INSERT OR REPLACE INTO raw (series, ts, v) VALUES (?,?,?)", (sid, int(ts), float(value)))
                    n += 1
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            log.exception("could not record metrics")
            self._ids.clear()
        return n

    def forget(self, entity: str, entity_id: int) -> None:
        """Remove every series of an entity (the device or check was deleted)."""
        try:
            conn = self._connect()
            try:
                ids = [r["id"] for r in conn.execute("SELECT id FROM series WHERE entity = ? AND entity_id = ?", (entity, entity_id))]
                for sid in ids:
                    for table in ("raw", "m5", "h1"):
                        conn.execute(f"DELETE FROM {table} WHERE series = ?", (sid,))
                    conn.execute("DELETE FROM series WHERE id = ?", (sid,))
                conn.commit()
            finally:
                conn.close()
            self._ids = {k: v for k, v in self._ids.items() if not (k[0] == entity and k[1] == entity_id)}
        except sqlite3.Error:
            log.exception("could not forget metrics")

    def export_since(self, since: int, entities: tuple[str, ...] = ("device", "service"), limit: int = 20000) -> list[tuple]:
        """Raw samples newer than `since`: (ts, entity, entity_id, metric, label, value, unit), oldest first."""
        marks = ",".join("?" for _ in entities)
        try:
            conn = self._connect()
        except sqlite3.Error:
            return []
        try:
            rows = conn.execute(
                f"SELECT r.ts, s.entity, s.entity_id, s.metric, s.label, r.v, s.unit FROM raw r JOIN series s ON s.id = r.series "
                f"WHERE r.ts > ? AND s.entity IN ({marks}) ORDER BY r.ts LIMIT ?", (int(since), *entities, int(limit))).fetchall()
            return [tuple(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------ history from the main database
    def reset(self) -> None:
        """Remove everything (the demo starts over)."""
        conn = self._connect()
        try:
            for table in ("raw", "m5", "h1", "series", "meta"):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
        finally:
            conn.close()
        self._ids.clear()

    def backfill(self, main: sqlite3.Connection, now: int | None = None, force: bool = False) -> int:
        """Copy the presence checks and service results Netlens already holds into the store, once.

        So a graph shows weeks of history right after the update that brought it, not an empty page.
        """
        conn = self._connect()
        try:
            if not force and conn.execute("SELECT 1 FROM meta WHERE k = 'backfill_done'").fetchone():
                return 0
            count = 0

            def stamp(ts: str) -> int:
                return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))

            def feed(entity: str, rows) -> int:
                n = 0
                batch: list[tuple] = []
                for ident, ts, up, ms in rows:
                    try:
                        t = stamp(ts)
                    except ValueError:
                        continue
                    batch.append((entity, ident, "up", up, "", "state", t))
                    if ms is not None:
                        batch.append((entity, ident, "rtt_ms" if entity == "device" else "response_ms", ms, "", "ms", t))
                    if len(batch) >= 5000:
                        n += self._bulk(conn, batch)
                        batch = []
                return n + self._bulk(conn, batch)

            count += feed("device", ((r[0], r[1], r[2], r[3]) for r in main.execute("SELECT device_id, ts, up, rtt_ms FROM checks ORDER BY id")))
            count += feed("service", ((r[0], r[1], r[2], r[3]) for r in main.execute("SELECT check_id, ts, up, ms FROM service_results ORDER BY id")))
            conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('backfill_done', 1)")
            conn.commit()
        finally:
            conn.close()
        self.rollup(now)
        self.prune(now)
        return count

    def _bulk(self, conn: sqlite3.Connection, batch: list[tuple]) -> int:
        n = 0
        for entity, ident, metric, value, label, unit, ts in batch:
            sid = self._series_id(conn, entity, int(ident), metric, label, unit)
            conn.execute("INSERT OR IGNORE INTO raw (series, ts, v) VALUES (?,?,?)", (sid, ts, float(value)))
            n += 1
        conn.commit()
        return n

    # ------------------------------------------------------------------ maintenance
    def rollup(self, now: int | None = None) -> None:
        """Fold complete buckets of raw samples into the 5-minute tier and of the 5-minute tier into the hourly one."""
        now = int(now if now is not None else time.time())
        conn = self._connect()
        try:
            for src, dst, step, key in (("raw", "m5", STEP_5M, "m5_done"), ("m5", "h1", STEP_1H, "h1_done")):
                limit = now // step * step                      # only buckets that are over
                row = conn.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
                start = (row["v"] if row else 0) - step         # one bucket back: a late sample still lands in it
                start = max(start, 0) // step * step
                if src == "raw":
                    conn.execute(
                        f"INSERT OR REPLACE INTO {dst} (series, ts, n, s, lo, hi) "
                        f"SELECT series, ts / {step} * {step}, COUNT(*), SUM(v), MIN(v), MAX(v) FROM raw WHERE ts >= ? AND ts < ? GROUP BY series, ts / {step}",
                        (start, limit))
                else:
                    conn.execute(
                        f"INSERT OR REPLACE INTO {dst} (series, ts, n, s, lo, hi) "
                        f"SELECT series, ts / {step} * {step}, SUM(n), SUM(s), MIN(lo), MAX(hi) FROM m5 WHERE ts >= ? AND ts < ? GROUP BY series, ts / {step}",
                        (start, limit))
                conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (key, limit))
            conn.commit()
        finally:
            conn.close()

    def prune(self, now: int | None = None) -> None:
        now = int(now if now is not None else time.time())
        conn = self._connect()
        try:
            conn.execute("DELETE FROM raw WHERE ts < ?", (now - RAW_SECONDS,))
            conn.execute("DELETE FROM m5 WHERE ts < ?", (now - M5_SECONDS,))
            conn.execute("DELETE FROM h1 WHERE ts < ?", (now - H1_SECONDS,))
            gone = [r["id"] for r in conn.execute(
                "SELECT id FROM series WHERE id NOT IN (SELECT DISTINCT series FROM raw) AND id NOT IN (SELECT DISTINCT series FROM m5) AND id NOT IN (SELECT DISTINCT series FROM h1)")]
            for sid in gone:
                conn.execute("DELETE FROM series WHERE id = ?", (sid,))
            conn.commit()
            if gone:
                self._ids.clear()
        finally:
            conn.close()

    def maintain(self, now: int | None = None) -> None:
        self.rollup(now)
        self.prune(now)

    # ------------------------------------------------------------------ reading
    def metrics_of(self, entity: str, entity_id: int) -> list[dict]:
        """Which series an entity has: [{metric, label, unit, last_ts, last}]."""
        try:
            conn = self._connect()
        except sqlite3.Error:
            return []
        try:
            out = []
            for s in conn.execute("SELECT id, metric, label, unit FROM series WHERE entity = ? AND entity_id = ? ORDER BY metric, label", (entity, entity_id)):
                last = conn.execute("SELECT ts, v FROM raw WHERE series = ? ORDER BY ts DESC LIMIT 1", (s["id"],)).fetchone()
                if last is None:
                    last = conn.execute("SELECT ts + 0 AS ts, s / n AS v FROM m5 WHERE series = ? ORDER BY ts DESC LIMIT 1", (s["id"],)).fetchone()
                out.append({"metric": s["metric"], "label": s["label"], "unit": s["unit"], "last_ts": last["ts"] if last else None, "last": last["v"] if last else None})
            return out
        finally:
            conn.close()

    def latest(self, entity: str, entity_id: int, metric: str, label: str = "") -> tuple[int, float] | None:
        try:
            conn = self._connect()
        except sqlite3.Error:
            return None
        try:
            row = conn.execute(
                "SELECT r.ts, r.v FROM raw r JOIN series s ON s.id = r.series WHERE s.entity = ? AND s.entity_id = ? AND s.metric = ? AND s.label = ? ORDER BY r.ts DESC LIMIT 1",
                (entity, entity_id, metric, label)).fetchone()
            return (row["ts"], row["v"]) if row else None
        finally:
            conn.close()

    def query(self, entity: str, entity_id: int, metric: str, label: str = "", span: int = 86400, end: int | None = None, points: int = 240) -> dict:
        """Points [[t, avg, min, max], ...] for the last `span` seconds, oldest first, at most about `points` of them."""
        end = int(end if end is not None else time.time())
        start = end - int(span)
        points = max(10, min(int(points), MAX_POINTS))
        out = {"entity": entity, "entity_id": entity_id, "metric": metric, "label": label, "start": start, "end": end, "step": 0, "unit": "", "points": []}
        try:
            conn = self._connect()
        except sqlite3.Error:
            return out
        try:
            s = conn.execute("SELECT id, unit FROM series WHERE entity = ? AND entity_id = ? AND metric = ? AND label = ?", (entity, entity_id, metric, label)).fetchone()
            if s is None:
                return out
            out["unit"] = s["unit"]
            sid = s["id"]
            if span <= RAW_SECONDS:
                tier, base = "raw", 1
            elif span <= M5_SECONDS:
                tier, base = "m5", STEP_5M
            else:
                tier, base = "h1", STEP_1H
            wanted = max(span / points, base)
            step = int(-(-wanted // base) * base)               # a whole number of tier steps
            out["step"] = step
            def done(key: str) -> int:
                row = conn.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
                return row["v"] if row else 0

            # the complete buckets come from the tier, the newest (not yet rolled up) part from the finer tiers
            parts, args = [], []
            if tier == "raw":
                parts.append("SELECT ts, 1 AS n, v AS s, v AS lo, v AS hi FROM raw WHERE series = ? AND ts >= ? AND ts <= ?")
                args += [sid, start, end]
            elif tier == "m5":
                parts.append("SELECT ts, n, s, lo, hi FROM m5 WHERE series = ? AND ts >= ? AND ts <= ? AND ts < ?")
                args += [sid, start, end, done("m5_done")]
                parts.append("SELECT ts, 1, v, v, v FROM raw WHERE series = ? AND ts >= ? AND ts >= ? AND ts <= ?")
                args += [sid, start, done("m5_done"), end]
            else:
                parts.append("SELECT ts, n, s, lo, hi FROM h1 WHERE series = ? AND ts >= ? AND ts <= ? AND ts < ?")
                args += [sid, start, end, done("h1_done")]
                parts.append("SELECT ts, n, s, lo, hi FROM m5 WHERE series = ? AND ts >= ? AND ts >= ? AND ts <= ? AND ts < ?")
                args += [sid, start, done("h1_done"), end, done("m5_done")]
                parts.append("SELECT ts, 1, v, v, v FROM raw WHERE series = ? AND ts >= ? AND ts >= ? AND ts <= ?")
                args += [sid, start, done("m5_done"), end]
            cur = conn.execute(
                f"SELECT ts / {step} * {step} AS t, SUM(s) / SUM(n) AS a, MIN(lo) AS lo, MAX(hi) AS hi FROM (" + " UNION ALL ".join(parts) + ") GROUP BY t ORDER BY t", args)
            rows = {r["t"]: [r["t"], r["a"], r["lo"], r["hi"]] for r in cur}
            out["points"] = [rows[t] for t in sorted(rows)]
            return out
        finally:
            conn.close()
