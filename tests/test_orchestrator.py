import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.config import load_settings
from app.db import connect, init_db, get_or_create_device, utcnow
from app.scanner.orchestrator import ScanBusy, ScanManager
from app.scanner.nmap_runner import ScanError


def _setup(tmp_path: Path, ranges: str | None = None) -> tuple[sqlite3.Connection, Any]:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    if ranges:
        settings.ranges = ranges
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    return conn, settings


def _fixture_text() -> str:
    return Path(__file__).parent / "fixtures" / "deep.xml"


@pytest.fixture
def db_conn(tmp_path: Path) -> sqlite3.Connection:
    conn, _ = _setup(tmp_path)
    return conn


@pytest.fixture
def settings(tmp_path: Path) -> Any:
    _, settings = _setup(tmp_path)
    return settings


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    return path


@pytest.fixture
def fixture_text() -> str:
    return _fixture_text().read_text(encoding="utf-8")


@pytest.fixture
def fake_runner(fixture_text: str) -> tuple[dict[str, Any], Any]:
    calls: list[tuple[str, list[str]]] = []

    async def runner(kind: str, targets: list[str], *, nmap_path: str = "nmap") -> str:
        calls.append((kind, targets))
        return fixture_text

    return calls, runner


@pytest.fixture
def fake_names() -> Any:
    async def names() -> dict[str, list[tuple[str, str]]]:
        return {}

    return names


@pytest.fixture
def fake_ranges() -> Any:
    async def ranges() -> list[str]:
        return ["192.168.1.0/24"]

    return ranges


def _create_scan(conn: sqlite3.Connection, kind: str, status: str, started: str, finished: str | None = None, error: str | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO scans (kind, status, started, finished, hosts_found, error) VALUES (?, ?, ?, ?, 0, ?)",
        (kind, status, started, finished, error),
    )
    conn.commit()
    return cur.lastrowid


def _get_scan(conn: sqlite3.Connection, scan_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else {}


def _get_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def _get_events(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def _get_device_names(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM device_names ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@pytest.mark.asyncio
async def test_start_returns_int_id(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    scan_id = await manager.start("quick")
    assert isinstance(scan_id, int)
    await manager.wait()
    conn = connect(db_path)
    scan = _get_scan(conn, scan_id)
    assert scan["status"] == "done"
    assert scan["hosts_found"] == 4
    assert scan["finished"] is not None
    devices = _get_devices(conn)
    assert len(devices) == 4
    conn.close()


@pytest.mark.asyncio
async def test_runner_receives_kind_and_targets(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    await manager.start("quick")
    await manager.wait()
    assert len(calls) == 1
    assert calls[0][0] == "quick"
    assert calls[0][1] == ["192.168.1.0/24"]


@pytest.mark.asyncio
async def test_settings_ranges_used_when_set(db_path: Path, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    settings = load_settings({"NETLENS_TOKEN": "t", "NETLENS_RANGES": "192.168.1.0/24"})
    ranges_called = False

    async def ranges() -> list[str]:
        nonlocal ranges_called
        ranges_called = True
        return ["192.168.1.0/24"]

    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=ranges)
    await manager.start("quick")
    await manager.wait()
    assert not ranges_called
    assert len(calls) == 1
    assert calls[0][1] == ["192.168.1.0/24"]


@pytest.mark.asyncio
async def test_no_ranges_fails_scan(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any) -> None:
    calls, runner = fake_runner

    async def empty_ranges() -> list[str]:
        return []

    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=empty_ranges)
    scan_id = await manager.start("quick")
    await manager.wait()
    conn = connect(db_path)
    scan = _get_scan(conn, scan_id)
    assert scan["status"] == "failed"
    assert "no scan ranges" in scan["error"]
    conn.close()


@pytest.mark.asyncio
async def test_scan_error_fails_scan(db_path: Path, settings: Any, fake_names: Any, fake_ranges: Any) -> None:
    async def error_runner(kind: str, targets: list[str], *, nmap_path: str = "nmap") -> str:
        raise ScanError("boom")

    manager = ScanManager(db_path, settings, runner=error_runner, names_provider=fake_names, ranges_provider=fake_ranges)
    scan_id = await manager.start("quick")
    await manager.wait()
    conn = connect(db_path)
    scan = _get_scan(conn, scan_id)
    assert scan["status"] == "failed"
    assert scan["error"] == "boom"
    conn.close()


@pytest.mark.asyncio
async def test_names_provider_exception_does_not_fail_scan(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_ranges: Any) -> None:
    calls, runner = fake_runner

    async def bad_names() -> dict[str, list[tuple[str, str]]]:
        raise RuntimeError("names error")

    manager = ScanManager(db_path, settings, runner=runner, names_provider=bad_names, ranges_provider=fake_ranges)
    scan_id = await manager.start("quick")
    await manager.wait()
    conn = connect(db_path)
    scan = _get_scan(conn, scan_id)
    assert scan["status"] == "done"
    conn.close()


@pytest.mark.asyncio
async def test_extra_names_from_provider(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_ranges: Any) -> None:
    calls, runner = fake_runner

    async def names_with_extra() -> dict[str, list[tuple[str, str]]]:
        return {"192.168.1.30": [("office-printer", "mdns")]}

    manager = ScanManager(db_path, settings, runner=runner, names_provider=names_with_extra, ranges_provider=fake_ranges)
    await manager.start("quick")
    await manager.wait()
    conn = connect(db_path)
    names = _get_device_names(conn)
    found = [n for n in names if n["name"] == "office-printer" and n["source"] == "mdns"]
    assert len(found) == 1
    conn.close()


@pytest.mark.asyncio
async def test_scan_busy_raises(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    event = asyncio.Event()

    async def blocking_runner(kind: str, targets: list[str], *, nmap_path: str = "nmap") -> str:
        await event.wait()
        return _fixture_text().read_text(encoding="utf-8")

    manager = ScanManager(db_path, settings, runner=blocking_runner, names_provider=fake_names, ranges_provider=fake_ranges)
    scan_id = await manager.start("quick")
    assert manager.is_running()
    with pytest.raises(ScanBusy):
        await manager.start("quick")
    event.set()
    await manager.wait()
    assert not manager.is_running()
    scan_id2 = await manager.start("quick")
    await manager.wait()
    conn = connect(db_path)
    scan1 = _get_scan(conn, scan_id)
    scan2 = _get_scan(conn, scan_id2)
    assert scan1["status"] == "done"
    assert scan2["status"] == "done"
    conn.close()


@pytest.mark.asyncio
async def test_is_running_true_during_false_after(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    assert not manager.is_running()
    await manager.start("quick")
    assert manager.is_running()
    await manager.wait()
    assert not manager.is_running()


@pytest.mark.asyncio
async def test_invalid_kind_raises_value_error(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    with pytest.raises(ValueError):
        await manager.start("invalid_kind")


@pytest.mark.asyncio
async def test_offline_marking(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    conn = connect(db_path)
    now = utcnow()
    get_or_create_device(conn, None, "192.168.1.77", now)
    get_or_create_device(conn, None, "10.9.9.9", now)
    conn.close()

    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    await manager.start("quick")
    await manager.wait()

    conn = connect(db_path)
    devices = _get_devices(conn)
    d77 = [d for d in devices if d["primary_ip"] == "192.168.1.77"]
    d99 = [d for d in devices if d["primary_ip"] == "10.9.9.9"]
    assert len(d77) == 1
    assert d77[0]["online"] == 0
    assert len(d99) == 1
    assert d99[0]["online"] == 1

    events = _get_events(conn)
    offline_events = [e for e in events if e["kind"] == "device_offline"]
    assert len(offline_events) >= 1
    conn.close()


@pytest.mark.asyncio
async def test_recover_marks_running_scan_failed(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    conn = connect(db_path)
    now = utcnow()
    scan_id = _create_scan(conn, "quick", "running", now)
    conn.close()

    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    count = manager.recover()
    assert count == 1

    conn = connect(db_path)
    scan = _get_scan(conn, scan_id)
    assert scan["status"] == "failed"
    assert scan["error"] == "interrupted by restart"
    conn.close()


@pytest.mark.asyncio
async def test_recover_returns_zero_when_nothing_running(db_path: Path, settings: Any, fake_runner: tuple[dict[str, Any], Any], fake_names: Any, fake_ranges: Any) -> None:
    calls, runner = fake_runner
    conn = connect(db_path)
    conn.close()

    manager = ScanManager(db_path, settings, runner=runner, names_provider=fake_names, ranges_provider=fake_ranges)
    count = manager.recover()
    assert count == 0