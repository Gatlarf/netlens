"""Uptime numbers that stay quick on a big network: an hourly roll-up of the `checks` table.

Every scan writes one check per device. A page that shows availability over 7 or 30 days used to add up every one of those rows: with 2,000 devices that is millions
of rows and several seconds. `checks_hourly` keeps, per device and hour, how many checks there were, how many were up, and the sum of the response times, so the same
answer is a few thousand rows to add up. It is exact (the sums are the same numbers), it is kept up to date as checks are written, and it is rebuilt from the raw rows when
it is missing (after an update). The raw rows are still used for the part of the window that begins in the middle of an hour.

The roll-up follows the id of the last check it has counted (not the time), so a check written out of order is counted too. When the roll-up is far behind (the first
start after the update, on a big history) the readers fall back to the raw rows until `backfill` has caught up.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timedelta

from app.db import get_setting, set_setting

log = logging.getLogger(__name__)
KEY = "checks.rolled_id"
CHUNK = 150_000                      # rows folded in per transaction while catching up
INLINE_LIMIT = 200_000               # a reader catches up by itself when it is at most this many rows behind
HOURLY_KEEP_DAYS = 400
_lock = threading.Lock()


def _rolled(conn: sqlite3.Connection) -> int:
    try:
        return int(get_setting(conn, KEY) or 0)
    except ValueError:
        return 0


def _max_id(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM checks").fetchone()[0]


def fold(conn: sqlite3.Connection, limit: int | None = None) -> int:
    """Count the checks that are not counted yet into `checks_hourly`; returns how many rows were folded in (at most `limit`)."""
    with _lock:
        done = _rolled(conn)
        top = _max_id(conn)
        if done > top:                                             # the checks table was emptied or replaced: start over
            conn.execute("DELETE FROM checks_hourly")
            done = 0
        if done == top:
            return 0
        upto = top if limit is None else min(top, done + limit)
        conn.execute(
            "INSERT INTO checks_hourly (device_id, hour, n, up, rtt_sum, rtt_n) "
            "SELECT device_id, substr(ts, 1, 13), COUNT(*), SUM(up), COALESCE(SUM(rtt_ms), 0), COUNT(rtt_ms) FROM checks WHERE id > ? AND id <= ? GROUP BY device_id, substr(ts, 1, 13) "
            "ON CONFLICT(device_id, hour) DO UPDATE SET n = n + excluded.n, up = up + excluded.up, rtt_sum = rtt_sum + excluded.rtt_sum, rtt_n = rtt_n + excluded.rtt_n",
            (done, upto))
        set_setting(conn, KEY, str(upto))
        conn.commit()
        return upto - done


def backfill(conn: sqlite3.Connection) -> int:
    """Catch up completely, in chunks (used at start, so a big history does not hold up a request)."""
    total = 0
    while True:
        n = fold(conn, CHUNK)
        total += n
        if n == 0:
            return total


def prune(conn: sqlite3.Connection, now: str) -> None:
    cutoff = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=HOURLY_KEEP_DAYS)).strftime("%Y-%m-%dT%H")
    conn.execute("DELETE FROM checks_hourly WHERE hour < ?", (cutoff,))


def current(conn: sqlite3.Connection) -> bool:
    """True when the roll-up holds every check (catching up first when it is only a little behind)."""
    behind = _max_id(conn) - _rolled(conn)
    if behind == 0:
        return True
    if behind < 0 or behind <= INLINE_LIMIT:
        fold(conn)
        return _rolled(conn) == _max_id(conn)
    return False


Totals = dict[int, tuple[int, int, float, int]]       # device id -> (up, checks, response time sum, response time count)


def _raw(conn: sqlite3.Connection, since: str, before: str | None, core: bool | None) -> Totals:
    sql = "SELECT c.device_id, SUM(c.up), COUNT(*), COALESCE(SUM(c.rtt_ms), 0), COUNT(c.rtt_ms) FROM checks c"
    args: list = []
    if core is not None:
        sql += " JOIN devices d ON d.id = c.device_id AND d.always_on = ?"
        args.append(1 if core else 0)
    sql += " WHERE c.ts >= ?"
    args.append(since)
    if before is not None:
        sql += " AND c.ts < ?"
        args.append(before)
    return {r[0]: (r[1] or 0, r[2], r[3], r[4]) for r in conn.execute(sql + " GROUP BY c.device_id", args)}


def totals(conn: sqlite3.Connection, since: str, core: bool | None = None) -> Totals:
    """Per device the checks since `since` (ISO time): (up, count, response time sum, response time count). core=True: only always-on devices, False: only the others."""
    if not current(conn):
        return _raw(conn, since, None, core)
    first_full = since[:13]
    edge = None
    if since[14:] != "00:00Z":                                     # the window starts inside an hour: that hour comes from the raw rows
        first_full = (datetime.strptime(since[:13], "%Y-%m-%dT%H") + timedelta(hours=1)).strftime("%Y-%m-%dT%H")
        edge = first_full + ":00:00Z"
    sql = "SELECT h.device_id, SUM(h.up), SUM(h.n), SUM(h.rtt_sum), SUM(h.rtt_n) FROM checks_hourly h"
    args: list = []
    if core is not None:
        sql += " JOIN devices d ON d.id = h.device_id AND d.always_on = ?"
        args.append(1 if core else 0)
    sql += " WHERE h.hour >= ? GROUP BY h.device_id"
    args.append(first_full)
    out: Totals = {r[0]: (r[1] or 0, r[2], r[3] or 0.0, r[4]) for r in conn.execute(sql, args)}
    if edge is not None:
        for device, (u, n, rs, rn) in _raw(conn, since, edge, core).items():
            a = out.get(device, (0, 0, 0.0, 0))
            out[device] = (a[0] + u, a[1] + n, a[2] + rs, a[3] + rn)
    return out


def network(conn: sqlite3.Connection, since: str, core: bool | None = None) -> tuple[int, int]:
    """(up, count) of every check since `since`, all devices (or only the always-on ones)."""
    up = n = 0
    for u, c, _rs, _rn in totals(conn, since, core).values():
        up += u
        n += c
    return up, n


def range_totals(conn: sqlite3.Connection, start: str, end: str) -> Totals | None:
    """Per device the checks from `start` up to (not including) `end`, from the roll-up alone; both must be on the hour (a month or a day is). None when the
    roll-up cannot answer (it is behind, or the times are not on the hour)."""
    if start[14:] != "00:00Z" or end[14:] != "00:00Z" or not current(conn):
        return None
    rows = conn.execute("SELECT device_id, SUM(up), SUM(n), SUM(rtt_sum), SUM(rtt_n) FROM checks_hourly WHERE hour >= ? AND hour < ? GROUP BY device_id", (start[:13], end[:13]))
    return {r[0]: (r[1] or 0, r[2], r[3] or 0.0, r[4]) for r in rows}


def down_hours(conn: sqlite3.Connection, start: str, end: str) -> dict[int, list[str]]:
    """Per device the hours (as 'YYYY-MM-DDTHH', oldest first) from `start` up to `end` in which at least one check failed. Both times must be on the hour."""
    out: dict[int, list[str]] = {}
    for device, hour in conn.execute("SELECT device_id, hour FROM checks_hourly WHERE hour >= ? AND hour < ? AND up < n ORDER BY device_id, hour", (start[:13], end[:13])):
        out.setdefault(device, []).append(hour)
    return out


def change_windows(hours: list[str], start: str, end: str) -> list[tuple[str, str]]:
    """The time windows that hold every down period of a device: each hour with a failed check and the hour after it (where it came back), merged.
    Every other hour was up from its first check to its last, so it holds no state change."""
    windows: list[tuple[str, str]] = []
    for hour in hours:
        a = hour + ":00:00Z"
        b = (datetime.strptime(hour, "%Y-%m-%dT%H") + timedelta(hours=2)).strftime("%Y-%m-%dT%H:00:00Z")
        if windows and a <= windows[-1][1]:
            windows[-1] = (windows[-1][0], max(windows[-1][1], b))
        else:
            windows.append((a, b))
    return [(max(a, start), min(b, end)) for a, b in windows]
