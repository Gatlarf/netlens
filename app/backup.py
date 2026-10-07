import os
import shutil
import sqlite3
import tempfile
from app.db import SCHEMA_VERSION, connect, init_db


class BackupError(Exception):
    pass


def create_backup(db_path: "str | os.PathLike", dest_path: "str | os.PathLike") -> None:
    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
    except (sqlite3.Error, OSError) as exc:
        raise BackupError("could not create backup: " + str(exc))


def validate_backup(path: "str | os.PathLike") -> int:
    path = os.fspath(path)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise BackupError("the file is empty")

    with open(path, "rb") as f:
        header = f.read(16)
    if header != b"SQLite format 3\x00":
        raise BackupError("this is not a Netlens database file")

    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise BackupError("the file is damaged: " + str(exc))

    try:
        try:
            row = conn.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.Error as exc:
            raise BackupError("the file is damaged: " + str(exc))
        if row[0] != "ok":
            raise BackupError("the database is damaged (integrity check failed)")

        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error as exc:
            raise BackupError("the file is damaged: " + str(exc))
        required = {"devices", "settings", "schema_version"}
        if not required.issubset(tables):
            raise BackupError("this is not a Netlens database (tables missing)")

        try:
            row = conn.execute("SELECT version FROM schema_version").fetchone()
        except sqlite3.Error as exc:
            raise BackupError("the file is damaged: " + str(exc))
        if row is None:
            raise BackupError("this is not a Netlens database (tables missing)")
        stored_version = row[0]
        if stored_version > SCHEMA_VERSION:
            raise BackupError(
                f"this backup comes from a newer Netlens version (schema {stored_version}); update Netlens first"
            )
        return stored_version
    finally:
        conn.close()


def restore_backup(db_path: "str | os.PathLike", src_path: "str | os.PathLike") -> None:
    db_path, src_path = os.fspath(db_path), os.fspath(src_path)
    validate_backup(src_path)

    if os.path.exists(db_path):
        create_backup(db_path, db_path + ".pre-restore")

    try:
        src = sqlite3.connect(src_path)
        dst = connect(db_path)
        try:
            src.backup(dst)
            init_db(dst)
            dst.commit()
        finally:
            src.close()
            dst.close()
    except sqlite3.Error as exc:
        raise BackupError("restore failed: " + str(exc))