from datetime import datetime, timezone

import httpx
import pytest

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.scans import average_duration, elapsed_seconds

AUTH = {"Authorization": "Bearer secret"}


def _scan(conn, kind, status, started, finished=None):
    conn.execute(
        "INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES (?, ?, ?, ?, 0)",
        (kind, status, started, finished),
    )
    conn.commit()


@pytest.fixture
def conn():
    c = connect(":memory:")
    init_db(c)
    return c


def test_average_uses_only_finished_scans_of_that_kind(conn):
    _scan(conn, "quick", "done", "2026-03-10T10:00:00Z", "2026-03-10T10:00:10Z")   # 10 s
    _scan(conn, "quick", "done", "2026-03-10T11:00:00Z", "2026-03-10T11:00:20Z")   # 20 s
    _scan(conn, "quick", "failed", "2026-03-10T12:00:00Z", "2026-03-10T12:09:00Z")  # ignored
    _scan(conn, "quick", "running", "2026-03-10T13:00:00Z")                          # ignored
    _scan(conn, "deep", "done", "2026-03-10T10:00:00Z", "2026-03-10T10:05:00Z")     # other kind
    assert average_duration(conn, "quick") == (15, 2)
    assert average_duration(conn, "deep") == (300, 1)


def test_average_without_history_and_with_bad_rows(conn):
    assert average_duration(conn, "deep") == (None, 0)
    _scan(conn, "deep", "done", "garbage", "2026-03-10T10:05:00Z")
    _scan(conn, "deep", "done", "2026-03-10T10:10:00Z", "2026-03-10T10:00:00Z")  # negative duration
    assert average_duration(conn, "deep") == (None, 0)


def test_average_looks_only_at_the_most_recent_scans(conn):
    _scan(conn, "quick", "done", "2026-03-01T10:00:00Z", "2026-03-01T10:10:00Z")  # old slow scan: 600 s
    for i in range(3):
        _scan(conn, "quick", "done", f"2026-03-10T10:0{i}:00Z", f"2026-03-10T10:0{i}:10Z")  # 10 s each
    assert average_duration(conn, "quick", limit=3) == (10, 3)


def test_elapsed_seconds():
    now = datetime(2026, 3, 10, 12, 0, 30, tzinfo=timezone.utc)
    assert elapsed_seconds("2026-03-10T12:00:00Z", now) == 30
    assert elapsed_seconds("2026-03-10T12:05:00Z", now) == 0   # clock skew never gives a negative time
    assert elapsed_seconds("nonsense", now) is None
    assert elapsed_seconds(None, now) is None


@pytest.mark.asyncio
async def test_current_scan_reports_elapsed_and_average(tmp_path):
    db = tmp_path / "t.db"
    c = connect(db)
    init_db(c)
    _scan(c, "deep", "done", "2026-03-10T10:00:00Z", "2026-03-10T10:07:00Z")  # 420 s
    _scan(c, "deep", "done", "2026-03-10T11:00:00Z", "2026-03-10T11:05:00Z")  # 300 s
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _scan(c, "deep", "running", started)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=AUTH) as client:
        body = (await client.get("/api/scans/current")).json()
        assert body["running"] is True
        assert body["average_seconds"] == 360 and body["average_samples"] == 2
        assert 0 <= body["elapsed_seconds"] <= 5

        # nothing running: the extra fields are absent
        conn = connect(db)
        conn.execute("UPDATE scans SET status = 'failed' WHERE status = 'running'")
        conn.commit()
        conn.close()
        body = (await client.get("/api/scans/current")).json()
        assert body == {"running": False, "scan": None, "progress": None}


@pytest.mark.asyncio
async def test_first_scan_has_no_average(tmp_path):
    db = tmp_path / "t.db"
    c = connect(db)
    init_db(c)
    _scan(c, "quick", "running", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=AUTH) as client:
        body = (await client.get("/api/scans/current")).json()
        assert body["average_seconds"] is None and body["average_samples"] == 0
