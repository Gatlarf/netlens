import asyncio
import os
import stat
import time

import httpx
import pytest

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_runner import run_nmap

AUTH = {"Authorization": "Bearer secret"}
EMPTY = '<?xml version="1.0"?><nmaprun></nmaprun>'


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a killed child that is not reaped yet shows up as a zombie: treat that as dead
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.asyncio
async def test_cancelling_run_nmap_kills_the_process(tmp_path):
    pidfile = tmp_path / "pid"
    fake = tmp_path / "nmap"
    fake.write_text(f'#!/bin/sh\necho $$ > {pidfile}\nexec sleep 60\n')
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    task = asyncio.create_task(run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake), progress=lambda p: None))
    for _ in range(50):  # wait until the fake nmap is running
        if pidfile.exists() and pidfile.read_text().strip():
            break
        await asyncio.sleep(0.1)
    pid = int(pidfile.read_text())
    assert _pid_alive(pid)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    deadline = time.time() + 5
    while _pid_alive(pid) and time.time() < deadline:
        await asyncio.sleep(0.1)
    assert not _pid_alive(pid), "nmap must not keep running after the scan was cancelled"


def _app(tmp_path):
    db = tmp_path / "t.db"
    init_db(connect(db))
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    return app, db


async def _names():
    return {}


async def _ranges():
    return ["192.168.1.0/24"]


@pytest.mark.asyncio
async def test_cancel_marks_the_scan_cancelled_and_runs_no_hooks(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    started = asyncio.Event()
    hook_calls = []

    async def runner(kind, targets, **kw):
        started.set()
        await asyncio.sleep(60)  # a scan that never finishes on its own
        return EMPTY

    async def hook(path):
        hook_calls.append(path)

    manager.runner, manager.names_provider, manager.ranges_provider = runner, _names, _ranges
    manager.after_scan = [hook]
    scan_id = await manager.start("deep")
    await asyncio.wait_for(started.wait(), 5)
    assert manager.can_cancel() is True

    assert await manager.cancel() is True
    assert not manager.is_running() and manager.progress is None
    conn = connect(db)
    row = conn.execute("SELECT status, error, finished FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert row["status"] == "cancelled" and row["error"] == "Cancelled by the user" and row["finished"]
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0  # nothing was saved
    assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 0   # and no uptime recorded
    conn.close()
    assert hook_calls == []  # no notifications / Proxmox sync for a cancelled scan

    # the manager is usable again
    async def ok_runner(kind, targets, **kw):
        return EMPTY

    manager.runner = ok_runner
    await manager.start("quick")
    await manager.wait()
    conn = connect(db)
    assert [r["status"] for r in conn.execute("SELECT status FROM scans ORDER BY id")] == ["cancelled", "done"]
    conn.close()


@pytest.mark.asyncio
async def test_cancelled_scans_do_not_count_towards_the_typical_duration(tmp_path):
    from app.scanner.scans import typical_duration

    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    started = asyncio.Event()

    async def runner(kind, targets, **kw):
        started.set()
        await asyncio.sleep(60)

    manager.runner, manager.names_provider, manager.ranges_provider = runner, _names, _ranges
    manager.after_scan = []
    await manager.start("quick")
    await asyncio.wait_for(started.wait(), 5)
    await manager.cancel()
    conn = connect(db)
    assert typical_duration(conn, "quick") == (None, 0)
    conn.close()


@pytest.mark.asyncio
async def test_cannot_cancel_while_saving_or_when_idle(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    assert manager.can_cancel() is False and await manager.cancel() is False

    gate = asyncio.Event()

    async def hook(path):
        await gate.wait()  # keeps the scan in its final "finishing" phase

    async def runner(kind, targets, **kw):
        return EMPTY

    manager.runner, manager.names_provider, manager.ranges_provider = runner, _names, _ranges
    manager.after_scan = [hook]
    await manager.start("quick")
    for _ in range(50):
        if (manager.progress or {}).get("phase") == "finishing":
            break
        await asyncio.sleep(0.05)
    assert manager.is_running() and manager.can_cancel() is False
    assert await manager.cancel() is False  # data is already saved: too late
    gate.set()
    await manager.wait()
    conn = connect(db)
    assert conn.execute("SELECT status FROM scans").fetchone()["status"] == "done"
    conn.close()


@pytest.mark.asyncio
async def test_cancel_api(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    started = asyncio.Event()

    async def runner(kind, targets, **kw):
        started.set()
        await asyncio.sleep(60)

    manager.runner, manager.names_provider, manager.ranges_provider = runner, _names, _ranges
    manager.after_scan = []
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=AUTH) as c:
        r = await c.post("/api/scans/cancel")
        assert r.status_code == 409 and "no scan" in r.json()["detail"]

        await manager.start("quick")
        await asyncio.wait_for(started.wait(), 5)
        assert (await c.get("/api/scans/current")).json()["cancellable"] is True

        r = await c.post("/api/scans/cancel")
        assert r.status_code == 200 and r.json() == {"cancelled": True}
        assert (await c.get("/api/scans/current")).json() == {"running": False, "scan": None, "progress": None}
        assert (await c.get("/api/scans?limit=1")).json()[0]["status"] == "cancelled"
        assert (await c.post("/api/scans/cancel", headers={"Authorization": "Bearer no"})).status_code == 401
