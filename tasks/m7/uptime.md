
TASK: write app/uptime.py (full file, under 170 lines).

Purpose: uptime history ("heartbeats") for devices, like Uptime Kuma. One row in table `checks` per device per completed scan.
Only these imports: sqlite3, ipaddress, datetime (datetime, timedelta, timezone), and `from app.db import utcnow`.

Time helpers inside the file: parse with datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc); format with .strftime("%Y-%m-%dT%H:%M:%SZ"). A "cutoff" for N days is the formatted string of (now - N days); compare timestamps as strings (ts >= cutoff).

Functions (exact names and signatures, all take an open sqlite3 connection `conn` with row_factory=sqlite3.Row; `now` defaults to utcnow() when None):

def record_checks(conn, seen_ids: set[int], ranges: list[str], now: str | None = None, rtts: dict[int, float] | None = None, keep_days: int = 90) -> int
  - For every device row (table devices: id, primary_ip) that is either in seen_ids OR has a primary_ip that is a valid IPv4 address inside ANY network of `ranges` (ipaddress.ip_network(r, strict=False)), insert one row into checks(device_id, ts, up, rtt_ms): ts=now, up=1 if the id is in seen_ids else 0, rtt_ms=rtts.get(id) if up else None.
  - Ignore devices with a missing/invalid primary_ip unless they are in seen_ids. If `ranges` is empty only devices in seen_ids get a row.
  - Then DELETE checks with ts < cutoff(keep_days). conn.commit(). Return the number of rows inserted.

def uptime_percent(conn, device_id: int, days: int, now: str | None = None) -> float | None
  - Percentage 0-100 rounded to 2 decimals of checks with up=1 among that device's checks with ts >= cutoff(days). None when there are no checks in the window.

def recent_checks(conn, device_id: int, limit: int = 60) -> list[dict]
  - The newest `limit` checks as dicts {"ts": str, "up": bool, "rtt_ms": float | None}, returned OLDEST FIRST.

def device_uptime(conn, device_id: int, now: str | None = None, limit: int = 60) -> dict
  - Returns {"up_24h": uptime_percent(...,1), "up_7d": ...(7), "up_30d": ...(30), "checks": recent_checks(conn, device_id, limit),
    "avg_rtt_ms": mean of non-null rtt_ms over the last 24h rounded to 1 decimal or None,
    "since": ts of the oldest check of the device or None,
    "status_for_seconds": int or None}.
  - status_for_seconds: look at ALL checks of the device ordered by ts. Let latest = the newest check. Find the most recent check whose `up` differs from latest.up; the answer is seconds between `now` and the ts of the check right AFTER that one. If no check differs, seconds between now and the oldest check's ts. None when the device has no checks.

def uptime_overview(conn, bars: int = 60, now: str | None = None) -> list[dict]
  - One dict per row of table devices ordered by name (case-insensitive) then id: {"id": int, "name": str, "ip": primary_ip, "online": bool(online), "up_24h": float|None, "up_7d": float|None, "bars": list[int] (0/1 of the last `bars` checks, oldest first, may be shorter or empty), "last_ts": ts of the newest check or None}.
  - name = custom_name, else hostname, else primary_ip, else f"device {id}" (use the same expression for ordering via Python sorting after fetching).
  - Use few queries, NOT one query per device: two GROUP BY aggregate queries for the 24h and 7d percentages (SUM(up), COUNT(*) per device_id with ts >= cutoff), and ONE window-function query for the bars:
    SELECT device_id, up FROM (SELECT device_id, up, ts, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY ts DESC, id DESC) AS rn FROM checks) WHERE rn <= ? ORDER BY device_id, rn DESC
    (rn DESC gives oldest first). last_ts via one `SELECT device_id, MAX(ts) FROM checks GROUP BY device_id`.
