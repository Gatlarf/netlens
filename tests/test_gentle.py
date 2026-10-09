import asyncio

import pytest

from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.scanner.nmap_runner import build_args
from app.scanner.options import ScanOptions
from app.scanner.orchestrator import ScanManager

XML = '<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/><address addr="{ip}" addrtype="ipv4"/></host></nmaprun>'


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
        return XML.format(ip=targets[0] if kind == "gentle" else "10.0.0.10")

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
        return XML.format(ip="10.0.0.10")

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
