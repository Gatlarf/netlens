import asyncio

import pytest

from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.scanner.nmap_runner import build_args
from app.scanner.options import ScanOptions
from app.scanner.orchestrator import ScanManager

XML = '<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/><address addr="{ip}" addrtype="ipv4"/><address addr="aa:bb:cc:00:00:{n:02d}" addrtype="mac"/></host></nmaprun>'


def test_gentle_arguments_never_probe_services():
    args = build_args("gentle", ["10.0.0.9"], options=ScanOptions(deep_scripts=True))
    assert "-sV" not in args and "-O" not in args and "--script" not in args and "--traceroute" not in args
    assert "--top-ports" in args and args[-1] == "10.0.0.9"


def test_exclude_is_validated_and_passed():
    args = build_args("deep", ["10.0.0.0/24"], exclude=["10.0.0.9", "10.0.0.10"])
    assert args[args.index("--exclude") + 1] == "10.0.0.9,10.0.0.10"
    with pytest.raises(ValueError):
        build_args("deep", ["10.0.0.0/24"], exclude=["10.0.0.0/8; rm"])


def test_gentle_devices_are_scanned_separately(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    tv = get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
    get_or_create_device(conn, "aa:bb:cc:00:00:10", "10.0.0.10")
    conn.execute("UPDATE devices SET gentle = 1 WHERE id = ?", (tv,))
    conn.commit()
    conn.close()
    calls = []

    async def runner(kind, targets, *, nmap_path="nmap", progress=None, options=None, exclude=None):
        calls.append((kind, list(targets), exclude))
        return XML.format(ip="10.0.0.9", n=9) if kind == "gentle" else XML.format(ip="10.0.0.10", n=10)

    async def none():
        return {}

    async def ranges():
        return ["10.0.0.0/24"]

    async def gateway():
        return None

    manager = ScanManager(str(path), load_settings({"NETLENS_TOKEN": "x"}), runner=runner, names_provider=none, ranges_provider=ranges, gateway_provider=gateway, after_scan=[])

    async def go():
        await manager.start("deep")
        await manager.wait()

    asyncio.run(go())
    assert calls == [("deep", ["10.0.0.0/24"], ["10.0.0.9"]), ("gentle", ["10.0.0.9"], None)]


def test_no_gentle_devices_means_one_ordinary_scan(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    calls = []

    async def runner(kind, targets, *, nmap_path="nmap", progress=None, options=None, exclude=None):
        calls.append((kind, exclude))
        return XML.format(ip="10.0.0.10", n=10)

    async def none():
        return {}

    async def ranges():
        return ["10.0.0.0/24"]

    async def gateway():
        return None

    manager = ScanManager(str(path), load_settings({"NETLENS_TOKEN": "x"}), runner=runner, names_provider=none, ranges_provider=ranges, gateway_provider=gateway, after_scan=[])

    async def go():
        await manager.start("quick")
        await manager.wait()

    asyncio.run(go())
    assert calls == [("quick", None)]


def test_gentle_flag_through_the_api(tmp_path):
    from fastapi.testclient import TestClient

    from app.main import create_app

    path = tmp_path / "a.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(path)
        d = get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
        conn.close()
        assert c.get(f"/api/devices/{d}").json()["gentle"] is False
        assert c.patch(f"/api/devices/{d}", json={"gentle": True}).json()["gentle"] is True
        assert [x["gentle"] for x in c.get("/api/devices").json()] == [True]


def _manager(path, runner, recheck=True):
    async def none():
        return {}

    async def ranges():
        return ["10.0.0.0/24"]

    async def gateway():
        return None

    from app.scanner.options import options_from_dict

    m = ScanManager(str(path), load_settings({"NETLENS_TOKEN": "x"}), runner=runner, names_provider=none, ranges_provider=ranges, gateway_provider=gateway, after_scan=[])
    m.options = options_from_dict({"recheck_missing": recheck})
    return m


def test_a_device_the_sweep_missed_gets_a_second_look(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    slow = get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
    gone = get_or_create_device(conn, "aa:bb:cc:00:00:11", "10.0.0.11")
    conn.commit()
    conn.close()
    calls = []

    async def runner(kind, targets, **kw):
        calls.append((kind, sorted(targets)))
        if kind == "recheck":
            return XML.format(ip="10.0.0.9", n=9)      # answers when asked alone; 10.0.0.11 stays silent
        return XML.format(ip="10.0.0.10", n=10)

    async def go():
        m = _manager(path, runner)
        await m.start("quick")
        await m.wait()

    asyncio.run(go())
    assert calls == [("quick", ["10.0.0.0/24"]), ("recheck", ["10.0.0.11", "10.0.0.9"])]
    conn = connect(path)
    assert conn.execute("SELECT online FROM devices WHERE id = ?", (slow,)).fetchone()[0] == 1
    assert conn.execute("SELECT online FROM devices WHERE id = ?", (gone,)).fetchone()[0] == 0
    assert conn.execute("SELECT up FROM checks WHERE device_id = ?", (slow,)).fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_offline' AND device_id = ?", (slow,)).fetchone()[0] == 0
    conn.close()


def test_the_second_look_can_be_switched_off_and_failures_are_harmless(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
    conn.commit()
    conn.close()
    calls = []

    async def runner(kind, targets, **kw):
        calls.append(kind)
        if kind == "recheck":
            from app.scanner.nmap_runner import ScanError
            raise ScanError("boom")
        return XML.format(ip="10.0.0.10", n=10)

    async def go(flag):
        m = _manager(path, runner, recheck=flag)
        await m.start("quick")
        await m.wait()

    asyncio.run(go(False))
    assert calls == ["quick"]
    conn = connect(path)
    conn.execute("UPDATE devices SET online = 1")   # it was marked offline without a second look; bring it back
    conn.commit()
    conn.close()
    asyncio.run(go(True))
    assert calls == ["quick", "quick", "recheck"]
    conn = connect(path)
    assert conn.execute("SELECT status FROM scans ORDER BY id DESC LIMIT 1").fetchone()[0] == "done"
    conn.close()
