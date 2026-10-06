import asyncio
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device, add_event, init_db
from app.main import create_app
from app.scanner.orchestrator import ScanManager, ScanBusy


class FakeScanManager:
    def __init__(self) -> None:
        self.recover_calls = 0
        self.start_calls: list[str] = []
        self._busy = False
        self._running = False

    def recover(self) -> int:
        self.recover_calls += 1
        return 0

    async def start(self, kind: str) -> int:
        if self._busy:
            raise ScanBusy("scan already running")
        self.start_calls.append(kind)
        return 42

    def is_running(self) -> bool:
        return self._running

    def set_busy(self, busy: bool) -> None:
        self._busy = busy

    def set_running(self, running: bool) -> None:
        self._running = running


def _seed_events(conn: sqlite3.Connection) -> int:
    init_db(conn)
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    add_event(conn, "device_new", "x", device_id=device_id)
    add_event(conn, "device_offline", "y", device_id=device_id)
    add_event(conn, "port_opened", "z", device_id=device_id)
    return device_id


def _make_client(
    settings: Any,
    db_path: Path,
    scan_manager: Any,
) -> TestClient:
    app = create_app(settings, db_path=db_path, scan_manager=scan_manager)
    return TestClient(app)


def test_post_scan_deep_returns_202_and_records_kind(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        resp = client.post("/api/scans", json={"kind": "deep"})
        assert resp.status_code == 202
        assert resp.json() == {"id": 42}
        assert fake.start_calls == ["deep"]


def test_post_scan_default_kind_is_quick(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        resp = client.post("/api/scans", json={})
        assert resp.status_code == 202
        assert resp.json() == {"id": 42}
        assert fake.start_calls == ["quick"]


def test_post_scan_invalid_kind_returns_422(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        resp = client.post("/api/scans", json={"kind": "full"})
        assert resp.status_code == 422


def test_post_scan_busy_returns_409(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    fake.set_busy(True)
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        resp = client.post("/api/scans", json={"kind": "quick"})
        assert resp.status_code == 409
        assert resp.json()["detail"] == "scan already running"


def test_get_events_returns_newest_first_with_expected_keys(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    device_id = _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events")
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 3
        for ev in events:
            assert set(ev.keys()) == {"id", "ts", "device_id", "kind", "detail"}
        # newest first: ids should be descending
        ids = [ev["id"] for ev in events]
        assert ids == sorted(ids, reverse=True)


def test_get_events_kind_filter(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"kind": "device_new"})
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 1
        assert events[0]["kind"] == "device_new"


def test_get_events_device_id_filter(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    device_id = _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"device_id": device_id})
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 3
        for ev in events:
            assert ev["device_id"] == device_id


def test_get_events_limit_works(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"limit": 2})
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 2


def test_get_events_limit_zero_returns_422(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"limit": 0})
        assert resp.status_code == 422


def test_get_events_limit_501_returns_422(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"limit": 501})
        assert resp.status_code == 422


def test_get_events_unknown_kind_filter_returns_empty(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    _seed_events(conn)
    conn.close()

    fake = FakeScanManager()
    client = _make_client(settings, db_path, fake)

    with client:
        resp = client.get("/api/events", params={"kind": "nonexistent"})
        assert resp.status_code == 200
        assert resp.json() == []


def test_health_endpoint_ok(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"


def test_lifespan_calls_recover_once(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    fake = FakeScanManager()
    client = _make_client(settings, tmp_path / "t.db", fake)

    with client:
        assert fake.recover_calls == 1


def test_end_to_end_real_scan_manager(
    tmp_path: Path,
) -> None:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"

    fixture_path = Path("tests/fixtures/deep.xml")
    fixture_text = fixture_path.read_text()

    async def fake_async_runner(*args: Any, **kwargs: Any) -> str:
        return fixture_text

    async def names_provider(*args: Any, **kwargs: Any) -> dict[str, str]:
        return {}

    async def ranges_provider(*args: Any, **kwargs: Any) -> list[str]:
        return ["192.168.1.0/24"]

    scan_manager = ScanManager(
        db_path,
        settings,
        runner=fake_async_runner,
        names_provider=names_provider,
        ranges_provider=ranges_provider,
    )

    client = _make_client(settings, db_path, scan_manager)

    with client:
        resp = client.post("/api/scans", json={"kind": "deep"})
        assert resp.status_code == 202

        # Poll until scan finishes
        deadline = time.time() + 5.0
        while time.time() < deadline:
            resp = client.get("/api/scans/current")
            if resp.status_code == 200:
                current = resp.json()
                if not scan_manager.is_running():
                    break
            time.sleep(0.05)

        # Assert devices
        resp = client.get("/api/devices")
        assert resp.status_code == 200
        devices = resp.json()
        assert len(devices) == 4

        # Assert events contain four device_new events
        resp = client.get("/api/events", params={"kind": "device_new"})
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) == 4