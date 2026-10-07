INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite; connections come from app.db.connect(path) and use row_factory=sqlite3.Row)
CREATE TABLE checks (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ts TEXT NOT NULL,
            up INTEGER NOT NULL,
            rtt_ms REAL
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        , notify_offline INTEGER NOT NULL DEFAULT 1)
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE proxmox_guests (
            vmid INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            node TEXT NOT NULL,
            status TEXT NOT NULL,
            macs TEXT NOT NULL DEFAULT '[]',
            ips TEXT NOT NULL DEFAULT '[]',
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            host_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            updated TEXT NOT NULL
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )

## app/db.py helpers
- utcnow() -> str            # 'YYYY-MM-DDTHH:MM:SSZ' (UTC, seconds precision, trailing Z)
- connect(path) -> sqlite3.Connection
- init_db(conn) -> None      # idempotent schema creation/migration
- get_or_create_device(conn, mac: str | None, ip: str, now: str | None = None) -> int   # returns device id
- add_event(conn, kind: str, detail: str | None = None, device_id: int | None = None, now: str | None = None) -> int   # commits, returns event id
- get_setting(conn, key: str) -> str | None
- set_setting(conn, key: str, value: str) -> None   # commits
- delete_setting(conn, key: str) -> None            # commits
All timestamps in the database are strings in the utcnow() format, so they compare correctly as strings.

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
