import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from app.db import connect, init_db, get_or_create_device


def test_connect_and_init_db_thread_safety(tmp_path: Path) -> None:
    """A connection created in the main thread can be used from another thread."""
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)

    def worker() -> None:
        try:
            # Basic query
            row = conn.execute("SELECT 1").fetchone()
            assert row[0] == 1

            # Devices count query
            count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            assert count == 0
        except Exception as exc:
            raise exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    conn.close()


def test_connect_and_init_db_thread_safety_memory() -> None:
    """A connection to :memory: can be used from another thread."""
    conn = connect(":memory:")
    init_db(conn)

    def worker() -> None:
        try:
            row = conn.execute("SELECT 1").fetchone()
            assert row[0] == 1

            count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            assert count == 0
        except Exception as exc:
            raise exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    conn.close()


def test_two_connections_read_each_other(tmp_path: Path) -> None:
    """Two connections to the same file can read each other's committed rows."""
    db_path = tmp_path / "t.db"

    conn_a = connect(db_path)
    conn_b = connect(db_path)

    init_db(conn_a)

    # Insert via conn_a
    device_id = get_or_create_device(conn_a, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    conn_a.commit()

    # Read via conn_b
    row = conn_b.execute("SELECT id, mac, primary_ip FROM devices WHERE mac = ?", ("aa:bb:cc:dd:ee:01",)).fetchone()
    assert row is not None
    assert row["id"] == device_id
    assert row["mac"] == "aa:bb:cc:dd:ee:01"
    assert row["primary_ip"] == "192.168.1.5"

    conn_a.close()
    conn_b.close()