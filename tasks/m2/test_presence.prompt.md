INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
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
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
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
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/scanner/presence.py
8:def mark_offline(
9:    conn: sqlite3.Connection,
10:    seen_ids: set[int] | list[int] | tuple[int, ...],
11:    ranges: list[str],
12:    now: str | None = None,
27:    offline_ids: list[int] = []

## app/db.py
11:SCHEMA_VERSION = 1
14:def utcnow() -> str:
19:def connect(path: str | os.PathLike) -> sqlite3.Connection:
43:def init_db(conn: sqlite3.Connection) -> None:
210:def _normalize_mac(mac: str | None) -> str | None:
223:def get_or_create_device(
224:    conn: sqlite3.Connection,
225:    mac: str | None,
226:    ip: str,
227:    now: str | None = None,
236:    device_id: int | None = None
298:def add_event(
299:    conn: sqlite3.Connection,
300:    kind: str,
301:    detail: str | None = None,
302:    device_id: int | None = None,
303:    now: str | None = None,
321:def list_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:

TASK:
Create tests/test_presence.py with pytest for app.scanner.presence.mark_offline(conn, seen_ids, ranges, now=None) -> list[int]. Use app.db.connect(":memory:") + init_db and app.db.get_or_create_device(conn, mac, ip) to create devices (returns ids). Tests: an unseen device inside a range is marked offline (online=0) and a device_offline event with detail equal to its IP and device_id is recorded; a seen device stays online; an unseen device outside every range stays online; an already offline device is not touched and gets no new event; several ranges (192.168.1.0/24 and 10.0.0.0/24) cover devices in both; returns ascending ids; empty ranges returns [] and changes nothing; seen_ids may be a set or list; a device with primary_ip NULL (set directly with SQL) is skipped without error. At least 8 tests.
