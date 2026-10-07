import sqlite3
from pathlib import Path

import pytest

from app.backup import BackupError, create_backup, validate_backup, restore_backup
from app.db import SCHEMA_VERSION, connect, init_db, get_or_create_device, set_setting, get_setting


def _make_live_db(path: Path) -> None:
    c = connect(path)
    init_db(c)
    get_or_create_device(c, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    set_setting(c, "marker", "original")
    c.close()


def test_create_backup_and_validate(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    _make_live_db(live)
    backup = tmp_path / "b.db"
    create_backup(live, backup)

    assert validate_backup(backup) == SCHEMA_VERSION

    c = connect(backup)
    assert get_setting(c, "marker") == "original"
    row = c.execute("SELECT COUNT(*) AS cnt FROM devices").fetchone()
    assert row["cnt"] == 1
    c.close()


def test_validate_backup_errors(tmp_path: Path) -> None:
    # empty file
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(BackupError, match="empty"):
        validate_backup(empty)

    # not a Netlens database (text file)
    text = tmp_path / "text.db"
    text.write_bytes(b"hello world, not sqlite" + b" " * 100)
    with pytest.raises(BackupError, match="not a Netlens"):
        validate_backup(text)

    # valid SQLite but lacks Netlens tables
    plain = tmp_path / "plain.db"
    c = sqlite3.connect(plain)
    c.execute("CREATE TABLE x(a)")
    c.commit()
    c.close()
    with pytest.raises(BackupError, match="not a Netlens database"):
        validate_backup(plain)

    # newer schema version
    newer = tmp_path / "newer.db"
    _make_live_db(newer)
    c = connect(newer)
    c.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 5,))
    c.commit()
    c.close()
    with pytest.raises(BackupError, match="newer"):
        validate_backup(newer)

    # truncated garbage with SQLite header
    truncated = tmp_path / "truncated.db"
    valid = tmp_path / "valid.db"
    _make_live_db(valid)
    raw = valid.read_bytes()
    truncated.write_bytes(raw[:100] + b"\x00" * 8192)
    with pytest.raises(BackupError):
        validate_backup(truncated)


def test_restore_backup_happy_path(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    _make_live_db(live)
    backup = tmp_path / "b.db"
    create_backup(live, backup)

    # modify live.db
    c = connect(live)
    set_setting(c, "marker", "changed")
    get_or_create_device(c, "aa:bb:cc:dd:ee:02", "192.168.1.11")
    c.close()

    restore_backup(live, backup)

    c = connect(live)
    assert get_setting(c, "marker") == "original"
    row = c.execute("SELECT COUNT(*) AS cnt FROM devices").fetchone()
    assert row["cnt"] == 1
    c.close()

    pre_restore = tmp_path / "live.db.pre-restore"
    assert pre_restore.exists()
    c = connect(pre_restore)
    assert get_setting(c, "marker") == "changed"
    c.close()


def test_restore_keeps_other_connections_working(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    _make_live_db(live)
    backup = tmp_path / "b.db"
    create_backup(live, backup)

    # modify live.db
    c = connect(live)
    set_setting(c, "marker", "changed")
    c.close()

    other = connect(live)
    restore_backup(live, backup)
    row = other.execute("SELECT value FROM settings WHERE key = 'marker'").fetchone()
    assert row["value"] == "original"
    other.close()


def test_restore_older_schema(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    _make_live_db(live)

    old = tmp_path / "old.db"
    c = connect(old)
    init_db(c)
    c.execute("DROP TABLE checks")
    c.execute("DROP TABLE proxmox_guests")
    c.execute("ALTER TABLE devices DROP COLUMN notify_offline")
    c.execute("UPDATE schema_version SET version = 1")
    c.commit()
    c.close()

    restore_backup(live, old)

    c = connect(live)
    assert c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='checks'").fetchone() is not None
    assert c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='proxmox_guests'").fetchone() is not None
    cols = [r[1] for r in c.execute("PRAGMA table_info(devices)").fetchall()]
    assert "notify_offline" in cols
    assert validate_backup(live) == SCHEMA_VERSION
    c.close()


def test_restore_invalid_file_raises_and_leaves_live_untouched(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    _make_live_db(live)

    invalid = tmp_path / "invalid.db"
    invalid.write_bytes(b"hello world, not sqlite" + b" " * 100)

    with pytest.raises(BackupError):
        restore_backup(live, invalid)

    c = connect(live)
    assert get_setting(c, "marker") == "original"
    c.close()

    pre_restore = tmp_path / "live.db.pre-restore"
    assert not pre_restore.exists()