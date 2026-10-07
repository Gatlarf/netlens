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

TASK: write tests/test_backup.py (pytest, full file, under 130 lines, each test written once).

Module under test: app/backup.py exposing BackupError, create_backup(db_path, dest_path), validate_backup(path) -> int (schema version, raises BackupError with messages containing: "empty", "not a Netlens database", "damaged", "newer"), restore_backup(db_path, src_path) (validates, writes db_path + ".pre-restore" safety copy of the current db, then replaces the content of db_path in place and runs init_db).

Helpers (from app.db import SCHEMA_VERSION, connect, init_db, get_or_create_device, set_setting, get_setting): make a database at tmp_path / "live.db": c = connect(path); init_db(c); get_or_create_device(c, "aa:bb:cc:dd:ee:01", "192.168.1.10"); set_setting(c, "marker", "original"); c.close().

Cases (exactly these):
1. create_backup of live.db into tmp_path / "b.db": validate_backup(b) == SCHEMA_VERSION and the copy holds the device and marker "original".
2. validate_backup: an empty file -> BackupError containing "empty"; a text file with b"hello world, not sqlite" padded to > 100 bytes -> "not a Netlens"; a valid SQLite file that lacks the Netlens tables (create with sqlite3.connect, CREATE TABLE x(a)) -> "not a Netlens database"; a Netlens db whose schema_version row is set to SCHEMA_VERSION + 5 (UPDATE schema_version SET version = ?) -> "newer"; a file that starts with the SQLite header but is truncated garbage (valid db bytes cut to the first 100 bytes, then zero padded to 8192 bytes) -> BackupError (any message).
3. restore_backup happy path: make backup of live.db; then modify live.db (set_setting marker "changed", add another device 192.168.1.11); restore from the backup: marker is "original" again, only one device remains; a file live.db.pre-restore exists next to it and contains marker "changed".
4. restore keeps other connections working: open `other = connect(live)` before restoring, restore, then other.execute("SELECT value FROM settings WHERE key = 'marker'") returns "original" (the same file path stays in use).
5. restore of an older schema: build a db at tmp_path / "old.db" with init_db, then DROP TABLE checks, DROP TABLE proxmox_guests, ALTER TABLE devices DROP COLUMN notify_offline, UPDATE schema_version SET version = 1; restore it into live.db; afterwards live.db has the checks table and devices.notify_offline column and schema_version == SCHEMA_VERSION.
6. restore of an invalid file raises BackupError and leaves live.db untouched (marker still "original", no .pre-restore file created).
