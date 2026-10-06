import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.db import connect, init_db


def test_connect_creates_missing_parent_directories(tmp_path: Path) -> None:
    db_path = tmp_path / "a" / "b" / "x.db"
    conn = connect(db_path)
    try:
        init_db(conn)
        assert db_path.exists()
        assert db_path.is_file()
    finally:
        conn.close()


def test_connect_accepts_str_path(tmp_path: Path) -> None:
    db_path = str(tmp_path / "test.db")
    conn = connect(db_path)
    try:
        init_db(conn)
        assert Path(db_path).exists()
    finally:
        conn.close()


def test_connect_memory_does_not_create_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    conn = connect(":memory:")
    try:
        init_db(conn)
        # Ensure no files or directories were created in the current working directory
        assert list(tmp_path.iterdir()) == []
    finally:
        conn.close()


def test_foreign_keys_pragma_is_on(tmp_path: Path) -> None:
    conn = connect(tmp_path / "fk.db")
    try:
        cursor = conn.execute("PRAGMA foreign_keys")
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == 1
    finally:
        conn.close()


def test_row_factory_yields_sqlite3_row(tmp_path: Path) -> None:
    conn = connect(tmp_path / "row_factory.db")
    try:
        init_db(conn)
        row = conn.execute("SELECT 1 AS one").fetchone()
        assert isinstance(row, sqlite3.Row)
        assert row["one"] == 1
    finally:
        conn.close()