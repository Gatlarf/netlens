import asyncio

import httpx
import pytest

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
EMPTY = '<?xml version="1.0"?><nmaprun></nmaprun>'


@pytest.mark.asyncio
async def test_progress_is_visible_while_scanning_and_cleared_afterwards(tmp_path):
    db = tmp_path / "t.db"
    init_db(connect(db))
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    manager = app.state.scan_manager
    reached, release = asyncio.Event(), asyncio.Event()

    async def runner(kind, targets, *, nmap_path="nmap", progress=None):
        progress({"task": "SYN Stealth Scan", "percent": 42.5, "hosts_found": 3})
        reached.set()
        await release.wait()
        return EMPTY

    async def names():
        return {}

    async def ranges():
        return ["192.168.1.0/24"]

    manager.runner, manager.names_provider, manager.ranges_provider = runner, names, ranges
    manager.after_scan = []

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=AUTH) as c:
        assert (await c.get("/api/scans/current")).json() == {"running": False, "scan": None, "progress": None}

        await manager.start("deep")
        await asyncio.wait_for(reached.wait(), 5)
        body = (await c.get("/api/scans/current")).json()
        assert body["running"] is True
        assert body["progress"] == {
            "scan_id": body["scan"]["id"], "kind": "deep", "target": None, "phase": "scanning", "targets": ["192.168.1.0/24"],
            "task": "SYN Stealth Scan", "percent": 42.5, "hosts_found": 3,
        }

        release.set()
        await manager.wait()
        body = (await c.get("/api/scans/current")).json()
        assert body == {"running": False, "scan": None, "progress": None}
        assert manager.progress is None


@pytest.mark.asyncio
async def test_runner_without_progress_support_still_works(tmp_path):
    db = tmp_path / "t.db"
    init_db(connect(db))
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    manager = app.state.scan_manager
    seen_kwargs = {}

    async def old_runner(kind, targets, *, nmap_path="nmap"):  # no progress parameter
        seen_kwargs.update(kind=kind)
        return EMPTY

    async def names():
        return {}

    async def ranges():
        return ["192.168.1.0/24"]

    manager.runner, manager.names_provider, manager.ranges_provider = old_runner, names, ranges
    manager.after_scan = []
    await manager.start("quick")
    await manager.wait()
    assert seen_kwargs == {"kind": "quick"}
    conn = connect(db)
    assert conn.execute("SELECT status FROM scans").fetchone()["status"] == "done"
    conn.close()


@pytest.mark.asyncio
async def test_failed_scan_clears_progress_and_explains_error(tmp_path):
    db = tmp_path / "t.db"
    init_db(connect(db))
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    manager = app.state.scan_manager

    async def runner(kind, targets, **kw):
        raise PermissionError(1, "Operation not permitted")

    async def names():
        return {}

    async def ranges():
        return ["192.168.1.0/24"]

    manager.runner, manager.names_provider, manager.ranges_provider = runner, names, ranges
    manager.after_scan = []
    await manager.start("quick")
    await manager.wait()
    assert manager.progress is None
    conn = connect(db)
    row = conn.execute("SELECT status, error FROM scans").fetchone()
    assert row["status"] == "failed" and "NET_RAW" in row["error"]
    conn.close()
