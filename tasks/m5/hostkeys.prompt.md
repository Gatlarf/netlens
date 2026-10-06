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
Create app/terminal/hostkeys.py (stdlib sqlite3; connections use row_factory=sqlite3.Row; import utcnow from app.db). Table: host_keys(device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL).
- def get_fingerprint(conn, device_id: int) -> str | None.
- def remember_fingerprint(conn, device_id: int, fingerprint: str, now: str | None = None) -> None: insert (first_seen = now or utcnow()); if a row already exists leave it unchanged (never silently overwrite). Commit.
- def forget_fingerprint(conn, device_id: int) -> bool: delete the row, commit, return True if a row was deleted.
- def check_fingerprint(conn, device_id: int, fingerprint: str) -> str: returns "new" when nothing is stored (and does NOT store it), "match" when equal, "mismatch" when different.
