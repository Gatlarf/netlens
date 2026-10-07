
TASK: write app/backup.py (full file, under 120 lines). Imports allowed: os, shutil, sqlite3, tempfile, `from app.db import SCHEMA_VERSION, connect, init_db`.

Backup and restore of the whole SQLite database file while the app may still be using it (other connections, WAL mode).

class BackupError(Exception): message is shown to the user, keep it short and clear.

def create_backup(db_path: str, dest_path: str) -> None
  - Consistent snapshot using the sqlite3 online backup API: src = sqlite3.connect(db_path); dst = sqlite3.connect(dest_path); src.backup(dst); close both (in finally). Raise BackupError("could not create backup: " + str(exc)) on sqlite3.Error or OSError.

def validate_backup(path: str) -> int
  - Returns the schema version stored in the file. Raise BackupError with these messages: file missing/empty -> "the file is empty"; first 16 bytes are not b"SQLite format 3\x00" -> "this is not a Netlens database file"; sqlite3 error opening -> "the file is damaged: ..." ; PRAGMA integrity_check result is not exactly 'ok' -> "the database is damaged (integrity check failed)"; missing any of the tables devices, settings, schema_version -> "this is not a Netlens database (tables missing)"; stored version (SELECT version FROM schema_version) greater than SCHEMA_VERSION -> "this backup comes from a newer Netlens version (schema N); update Netlens first". Open the file read-only with sqlite3.connect(f"file:{path}?mode=ro", uri=True) and always close it.

def restore_backup(db_path: str, src_path: str) -> None
  - validate_backup(src_path) first (let its BackupError propagate).
  - Safety copy of the current database: create_backup(db_path, db_path + ".pre-restore") (overwrite an older one) before touching anything, only if db_path exists.
  - Then replace the live database CONTENT in place using the backup API in the other direction: src = sqlite3.connect(src_path); dst = connect(db_path) (from app.db); src.backup(dst); then init_db(dst) so an older schema is upgraded; dst.commit(); close both (in finally). Wrap sqlite3.Error in BackupError("restore failed: ..."). Do NOT delete or rename db_path (other open connections must keep working).
