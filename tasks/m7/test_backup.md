
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
