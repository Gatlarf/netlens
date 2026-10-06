import sqlite3
from typing import Optional

import pytest

from app.db import connect, init_db, get_or_create_device
from app.terminal.hostkeys import (
    get_fingerprint,
    remember_fingerprint,
    forget_fingerprint,
    check_fingerprint,
)


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = connect(":memory:")
    init_db(c)
    return c


def _device_id(conn: sqlite3.Connection) -> int:
    return get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")


def test_get_fingerprint_none_when_nothing_stored(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    assert get_fingerprint(conn, device_id) is None


def test_check_fingerprint_new_when_nothing_stored(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    assert check_fingerprint(conn, device_id, "fp1") == "new"
    assert get_fingerprint(conn, device_id) is None


def test_remember_then_get_returns_fingerprint(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    assert get_fingerprint(conn, device_id) == "fp1"


def test_check_fingerprint_match(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    assert check_fingerprint(conn, device_id, "fp1") == "match"


def test_check_fingerprint_mismatch(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    assert check_fingerprint(conn, device_id, "fp2") == "mismatch"


def test_remember_twice_keeps_first_fingerprint(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    remember_fingerprint(conn, device_id, "fp2")
    assert get_fingerprint(conn, device_id) == "fp1"


def test_forget_returns_true_then_false(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    assert forget_fingerprint(conn, device_id) is True
    assert forget_fingerprint(conn, device_id) is False
    assert get_fingerprint(conn, device_id) is None


def test_delete_device_cascades_host_key(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    remember_fingerprint(conn, device_id, "fp1")
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    assert get_fingerprint(conn, device_id) is None


def test_first_seen_matches_given_now(conn: sqlite3.Connection) -> None:
    device_id = _device_id(conn)
    now = "2024-01-01T00:00:00Z"
    remember_fingerprint(conn, device_id, "fp1", now=now)
    row = conn.execute(
        "SELECT first_seen FROM host_keys WHERE device_id = ?", (device_id,)
    ).fetchone()
    assert row is not None
    assert row["first_seen"] == now