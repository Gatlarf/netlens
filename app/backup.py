import gzip
import hashlib
import io
import logging
import os
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

from app.db import SCHEMA_VERSION, connect, init_db

log = logging.getLogger(__name__)

METRICS_TABLE = "backup_metrics"    # only inside a backup file: a trimmed copy of metrics.db (the history behind the graphs and forecasts)
METRICS_KEEP_RAW = 86400            # what the copy holds: the last day in full, 14 days at 5 minutes, all hours
METRICS_KEEP_M5 = 14 * 86400
PLUGIN_TABLE = "backup_plugins"     # only exists inside a backup file: the installed plugins, so a restore brings them back too


class BackupError(Exception):
    pass


def _plugin_zips(data_dir: "str | os.PathLike") -> list[tuple[str, str, bytes]]:
    """(id, version, zip) of every plugin installed in the data folder (not the built-in ones)."""
    from app.plugins import registry

    out = []
    root = Path(data_dir) / "plugins"
    if not root.is_dir():
        return out
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or folder.name.startswith("."):
            continue
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(folder.rglob("*")):
                rel = path.relative_to(folder)
                if not path.is_file() or path.is_symlink() or "__pycache__" in rel.parts or path.suffix == ".pyc":
                    continue
                info = zipfile.ZipInfo(rel.as_posix(), (2000, 1, 1, 0, 0, 0))       # fixed time: the same plugin gives the same bytes
                info.external_attr = 0o644 << 16
                archive.writestr(info, path.read_bytes())
        data = buf.getvalue()
        try:
            _files, manifest = registry.read_zip(data)
        except registry.InstallError as exc:
            log.warning("plugin %s is not included in the backup: %s", folder.name, exc)
            continue
        if manifest["id"] == folder.name:
            out.append((folder.name, manifest["version"], data))
    return out


def _metrics_snapshot(db_path: "str | os.PathLike") -> bytes | None:
    """A compressed, trimmed copy of the metrics store that sits next to the main database; None when there is none."""
    src_path = Path(os.fspath(db_path)).resolve().with_name("metrics.db")
    if not src_path.is_file():
        return None
    now = int(time.time())
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "metrics.db")
        src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=15)
        dst = sqlite3.connect(copy)
        try:
            src.backup(dst)
            dst.execute("DELETE FROM raw WHERE ts < ?", (now - METRICS_KEEP_RAW,))
            dst.execute("DELETE FROM m5 WHERE ts < ?", (now - METRICS_KEEP_M5,))
            dst.commit()
            dst.execute("VACUUM")
        finally:
            src.close()
            dst.close()
        with open(copy, "rb") as f:
            return gzip.compress(f.read(), 6)


def _restore_metrics(src: sqlite3.Connection, db_path: "str | os.PathLike") -> bool:
    try:
        row = src.execute(f"SELECT data FROM {METRICS_TABLE} LIMIT 1").fetchone()
    except sqlite3.Error:
        return False                                  # a backup from before the history was included: keep what is here
    if row is None:
        return False
    from app import tsdb

    target = Path(os.fspath(db_path)).resolve().with_name("metrics.db")
    try:
        data = gzip.decompress(bytes(row[0]))
        if not data.startswith(b"SQLite format 3\x00"):
            return False
        tmp = target.with_name("metrics.db.restoring")
        tmp.write_bytes(data)
        if target.exists():
            os.replace(target, target.with_name("metrics.db.pre-restore"))
        for suffix in ("-wal", "-shm"):
            try:
                os.unlink(str(target) + suffix)
            except FileNotFoundError:
                pass
        os.replace(tmp, target)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        log.warning("could not restore the metrics history: %s", exc)
        return False
    tsdb.forget_all()
    return True


def create_backup(db_path: "str | os.PathLike", dest_path: "str | os.PathLike", data_dir: "str | os.PathLike | None" = None) -> None:
    """Copy the database to dest_path and put the installed plugins (their files) into the copy."""
    data_dir = data_dir if data_dir is not None else Path(os.fspath(db_path)).parent
    try:
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
            plugins = _plugin_zips(data_dir)
            dst.execute(f"CREATE TABLE IF NOT EXISTS {PLUGIN_TABLE} (plugin_id TEXT PRIMARY KEY, version TEXT, sha256 TEXT, data BLOB NOT NULL)")
            dst.execute(f"DELETE FROM {PLUGIN_TABLE}")
            dst.executemany(f"INSERT INTO {PLUGIN_TABLE} (plugin_id, version, sha256, data) VALUES (?,?,?,?)",
                            [(pid, version, hashlib.sha256(data).hexdigest(), data) for pid, version, data in plugins])
            dst.execute(f"CREATE TABLE IF NOT EXISTS {METRICS_TABLE} (id INTEGER PRIMARY KEY CHECK (id = 1), data BLOB NOT NULL)")
            dst.execute(f"DELETE FROM {METRICS_TABLE}")
            try:
                metrics = _metrics_snapshot(db_path)
            except (sqlite3.Error, OSError) as exc:        # the history is a convenience: a backup without it is still a backup
                log.warning("the metrics history is not included in the backup: %s", exc)
                metrics = None
            if metrics:
                dst.execute(f"INSERT INTO {METRICS_TABLE} (id, data) VALUES (1, ?)", (metrics,))
            dst.commit()
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


def _restore_plugins(src: sqlite3.Connection, data_dir: "str | os.PathLike") -> dict:
    """Install the plugins stored in the backup (the version that was installed then replaces what is installed now)."""
    from app.plugins import index_install, registry

    done, failed = [], []
    try:
        rows = src.execute(f"SELECT plugin_id, version, data FROM {PLUGIN_TABLE} ORDER BY plugin_id").fetchall()
    except sqlite3.Error:
        return {"plugins": done, "plugins_failed": failed}        # a backup from before plugins were included
    for plugin_id, version, data in rows:
        try:
            result = registry.install(data_dir, bytes(data), replace=True)
            if result["manifest"]["id"] != plugin_id:
                raise registry.InstallError("the plugin in the backup has another id")
            index_install.remember_zip(data_dir, plugin_id, result["manifest"]["version"], bytes(data))
            done.append(plugin_id)
        except (registry.InstallError, OSError) as exc:
            log.warning("could not restore plugin %s: %s", plugin_id, exc)
            failed.append(plugin_id)
    return {"plugins": done, "plugins_failed": failed}


def restore_backup(db_path: "str | os.PathLike", src_path: "str | os.PathLike", data_dir: "str | os.PathLike | None" = None) -> dict:
    """Replace the database with the backup and put its plugins back. Returns {"plugins": [ids], "plugins_failed": [ids]}."""
    db_path, src_path = os.fspath(db_path), os.fspath(src_path)
    data_dir = data_dir if data_dir is not None else Path(db_path).parent
    validate_backup(src_path)

    if os.path.exists(db_path):
        create_backup(db_path, db_path + ".pre-restore", data_dir)

    try:
        src = sqlite3.connect(src_path)
        dst = connect(db_path)
        try:
            src.backup(dst)
            dst.execute(f"DROP TABLE IF EXISTS {PLUGIN_TABLE}")      # the copies live in the plugin folder now
            dst.execute(f"DROP TABLE IF EXISTS {METRICS_TABLE}")     # the history lives in metrics.db next to it
            init_db(dst)
            dst.commit()
            result = _restore_plugins(src, data_dir)
            result["metrics"] = _restore_metrics(src, db_path)
            return result
        finally:
            src.close()
            dst.close()
    except sqlite3.Error as exc:
        raise BackupError("restore failed: " + str(exc))
