import asyncio
import json
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import SCHEMA_VERSION, connect, get_or_create_device, init_db
from app.main import create_app
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.nmap_runner import build_args
from app.scanner.options import ScanOptions, command_preview, options_from_dict
from app.scanner.scans import typical_duration
from app.scanner.store import save_scan_results

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T10:00:00Z"


def _host(ip, mac=None, ports=()):
    addr = f'<address addr="{mac}" addrtype="mac"/>' if mac else ""
    pxml = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="svc{p}"/></port>' for p in ports)
    return (f'<host><status state="up" reason="arp-response"/><address addr="{ip}" addrtype="ipv4"/>{addr}'
            f'{"<ports>" + pxml + "</ports>" if pxml else ""}</host>')


def _xml(*hosts):
    return '<?xml version="1.0"?><nmaprun>' + "".join(hosts) + "</nmaprun>"


def _seed(db):
    """1 gateway, 2 Proxmox host, 3 guest (the one we delete), 4 child of 3 set by hand, 5 unrelated."""
    conn = connect(db)
    init_db(conn)
    for i, ip in [(1, "10.0.0.1"), (2, "10.0.0.5"), (3, "10.0.0.6"), (4, "10.0.0.7"), (5, "10.0.0.50")]:
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, ?)",
                     (i, f"aa:00:00:00:00:0{i}", ip, f"host{i}", NOW, NOW))
    conn.execute("UPDATE devices SET parent_mode='device', parent_device_id=3 WHERE id=4")
    conn.executemany("INSERT INTO ports (device_id, proto, port, state, updated) VALUES (?, 'tcp', ?, 'open', ?)", [(3, 22, NOW), (3, 80, NOW), (5, 443, NOW)])
    conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (3, '10.0.0.6', ?, ?)", (NOW, NOW))
    conn.execute("INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (3, 'web', 'ptr', ?, ?)", (NOW, NOW))
    conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (3, ?, 1)", (NOW,))
    conn.execute("INSERT INTO host_keys (device_id, fingerprint, first_seen) VALUES (3, 'SHA256:x', ?)", (NOW,))
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 3, 'device_new', '10.0.0.6')", (NOW,))
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, device_id, host_device_id, updated) VALUES ('proxmox', '100', 'web', 'lxc', 'pve', 'running', 3, 2, ?)", (NOW,))
    conn.executemany("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, ?, ?, 1.0, 0)",
                     [(3, 2, "host-of", "proxmox"), (3, 1, "gateway", "default-route"), (5, 1, "gateway", "default-route"), (2, 1, "gateway", "default-route")])
    conn.commit()
    conn.close()


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    _seed(db)
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers=AUTH) as c:
        c.db = db
        yield c


def _count(db, sql, *args):
    conn = connect(db)
    try:
        return conn.execute(sql, args).fetchone()[0]
    finally:
        conn.close()


# ------------------------------------------------------------------ delete

def test_delete_removes_the_device_and_everything_attached_to_it(client):
    assert client.delete("/api/devices/3").status_code == 204
    db = client.db
    for table in ("ports", "device_ips", "device_names", "checks", "host_keys"):
        assert _count(db, f"SELECT COUNT(*) FROM {table} WHERE device_id = 3") == 0, table
    assert _count(db, "SELECT COUNT(*) FROM relations WHERE src_id = 3 OR dst_id = 3") == 0
    assert _count(db, "SELECT COUNT(*) FROM devices WHERE id = 3") == 0
    # the history keeps its events, without the link to the deleted device
    assert _count(db, "SELECT COUNT(*) FROM events WHERE kind = 'device_new' AND device_id IS NULL") == 1
    assert _count(db, "SELECT device_id FROM hypervisor_guests WHERE guest_id = '100'") is None
    # other devices are untouched
    assert _count(db, "SELECT COUNT(*) FROM devices") == 4 and _count(db, "SELECT COUNT(*) FROM ports WHERE device_id = 5") == 1


def test_a_device_chosen_as_parent_falls_back_to_automatic_when_deleted(client):
    assert [n["parent_id"] for n in client.get("/api/hierarchy").json()["nodes"] if n["id"] == 4] == [3]
    client.delete("/api/devices/3")
    node = next(n for n in client.get("/api/hierarchy").json()["nodes"] if n["id"] == 4)
    assert node["parent_id"] is None and node["source"] == "none"
    assert client.get("/api/devices/4").json()["parent"]["mode"] == "device"  # the stale choice is harmless


def test_delete_is_recorded_in_the_events(client):
    client.delete("/api/devices/3")
    ev = next(e for e in client.get("/api/events?limit=5").json() if e["kind"] == "device_deleted")
    assert "host3" in ev["detail"] and "deleted" in ev["detail"] and "ignored" not in ev["detail"]
    client.delete("/api/devices/5?ignore=true")
    assert any("and ignored" in e["detail"] for e in client.get("/api/events?limit=5").json() if e["kind"] == "device_deleted")


def test_delete_errors_and_auth(client):
    assert client.delete("/api/devices/999").status_code == 404
    assert client.delete("/api/devices/3", headers={"Authorization": "Bearer no"}).status_code == 401
    assert client.get("/api/devices/3").status_code == 200  # the failed attempts changed nothing
    client.delete("/api/devices/3")
    assert client.delete("/api/devices/3").status_code == 404


# ------------------------------------------------------------------ ignore

def test_ignored_device_is_not_added_back_by_the_next_scan(client):
    client.delete("/api/devices/5?ignore=true")
    ignored = client.get("/api/ignored").json()
    assert len(ignored) == 1 and ignored[0]["mac"] == "aa:00:00:00:00:05" and ignored[0]["ip"] == "10.0.0.50" and ignored[0]["label"] == "host5"

    conn = connect(client.db)
    result = save_scan_results(conn, parse_nmap_xml(_xml(_host("10.0.0.50", "AA:00:00:00:00:05", [443]), _host("10.0.0.99", "aa:00:00:00:00:99"))), "quick", now=NOW)
    assert result["new"] == 1  # only the other host
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE mac = 'aa:00:00:00:00:05'").fetchone()[0] == 0
    # a different device that takes over the IP is a new device and is not ignored
    result = save_scan_results(conn, parse_nmap_xml(_xml(_host("10.0.0.50", "bb:00:00:00:00:50"))), "quick", now=NOW)
    assert result["new"] == 1
    conn.close()


def test_without_ignore_a_device_that_is_still_there_comes_back_as_new(client):
    client.delete("/api/devices/5")
    assert client.get("/api/ignored").json() == []
    conn = connect(client.db)
    result = save_scan_results(conn, parse_nmap_xml(_xml(_host("10.0.0.50", "aa:00:00:00:00:05"))), "quick", now=NOW)
    assert result["new"] == 1
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_new' AND detail LIKE '10.0.0.50%'").fetchone()[0] == 1
    conn.close()


def test_a_device_without_a_mac_is_ignored_by_ip(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    device_id = get_or_create_device(conn, None, "172.17.0.1", NOW)
    conn.close()
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers=AUTH) as c:
        assert c.delete(f"/api/devices/{device_id}?ignore=true").status_code == 204
        row = c.get("/api/ignored").json()[0]
        assert row["mac"] is None and row["ip"] == "172.17.0.1"
    conn = connect(db)
    assert save_scan_results(conn, parse_nmap_xml(_xml(_host("172.17.0.1"), _host("172.18.0.1"))), "quick", now=NOW)["new"] == 1
    conn.close()


def test_stop_ignoring_lets_the_device_back_in(client):
    client.delete("/api/devices/5?ignore=true")
    row_id = client.get("/api/ignored").json()[0]["id"]
    assert client.delete(f"/api/ignored/{row_id}").status_code == 204
    assert client.get("/api/ignored").json() == [] and client.delete(f"/api/ignored/{row_id}").status_code == 404
    conn = connect(client.db)
    assert save_scan_results(conn, parse_nmap_xml(_xml(_host("10.0.0.50", "aa:00:00:00:00:05"))), "quick", now=NOW)["new"] == 1
    new_id = conn.execute("SELECT id FROM devices WHERE mac = 'aa:00:00:00:00:05'").fetchone()[0]
    conn.close()
    # ignoring the same device again updates the single entry instead of failing
    assert client.delete(f"/api/devices/{new_id}?ignore=true").status_code == 204
    assert len(client.get("/api/ignored").json()) == 1
    assert client.get("/api/ignored", headers={"Authorization": "Bearer no"}).status_code == 401


# ------------------------------------------------------------------ full scan

def test_full_scan_command_line():
    assert build_args("full", ["10.0.0.5"]) == ["-T4", "-p-", "-sV", "-O", "--osscan-guess", "--traceroute", "--host-timeout", "1800s", "-oX", "-", "10.0.0.5"]
    # slower or faster timing settings and the DNS preference are respected, but never slower than T4
    assert build_args("full", ["10.0.0.5"], options=options_from_dict({"timing": 2}))[0] == "-T4"
    assert build_args("full", ["10.0.0.5"], options=options_from_dict({"timing": 5, "skip_dns": True}))[0:2] == ["-T5", "-p-"]
    assert "-n" in build_args("full", ["10.0.0.5"], options=options_from_dict({"skip_dns": True}))
    with pytest.raises(ValueError):
        build_args("full", ["8.8.8.8"])  # public targets are still refused
    assert command_preview("full", ScanOptions()) == "nmap -T4 -p- -sV -O --osscan-guess --traceroute --host-timeout 1800s -oX - <host>"


def _app(tmp_path):
    db = tmp_path / "t.db"
    _seed(db)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    app.state.scan_manager.after_scan = []

    async def names():
        return {}

    async def ranges():
        return ["10.0.0.0/24"]

    app.state.scan_manager.names_provider, app.state.scan_manager.ranges_provider = names, ranges
    return app, db


@pytest.mark.asyncio
async def test_full_scan_touches_only_its_host(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    calls = []

    async def runner(kind, targets, **kw):
        calls.append((kind, targets))
        return _xml(_host("10.0.0.6", "aa:00:00:00:00:03", [22, 8080, 49152]))

    manager.runner = runner
    before = _count(db, "SELECT COUNT(*) FROM relations"), _count(db, "SELECT COUNT(*) FROM checks")
    scan_id = await manager.start("full", target="10.0.0.6")
    await manager.wait()

    assert calls == [("full", ["10.0.0.6"])]
    conn = connect(db)
    row = conn.execute("SELECT kind, status, target, hosts_found FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert (row["kind"], row["status"], row["target"], row["hosts_found"]) == ("full", "done", "10.0.0.6", 1)
    # the host's port list is replaced by the full result (80 is gone, the high port is found)
    assert [r["port"] for r in conn.execute("SELECT port FROM ports WHERE device_id = 3 ORDER BY port")] == [22, 8080, 49152]
    # nobody else was touched: still online, ports intact, relations and uptime history unchanged
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE online = 1").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM ports WHERE device_id = 5").fetchone()[0] == 1
    assert (conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0], conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]) == before
    conn.close()


@pytest.mark.asyncio
async def test_full_scan_of_a_host_that_is_down_marks_only_that_host_offline(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager

    async def runner(kind, targets, **kw):
        return _xml()  # nothing answered

    manager.runner = runner
    await manager.start("full", target="10.0.0.6")
    await manager.wait()
    conn = connect(db)
    assert [r["id"] for r in conn.execute("SELECT id FROM devices WHERE online = 0")] == [3]
    conn.close()


@pytest.mark.asyncio
async def test_full_scan_rejects_bad_targets_and_runs_one_scan_at_a_time(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    gate = asyncio.Event()

    async def runner(kind, targets, **kw):
        await gate.wait()
        return _xml()

    manager.runner = runner
    for kind, target in [("full", None), ("full", "8.8.8.8"), ("full", "10.0.0.0/24"), ("quick", "10.0.0.6")]:
        with pytest.raises(ValueError):
            await manager.start(kind, target=target)
    await manager.start("full", target="10.0.0.6")
    for _ in range(50):  # the scan task starts a moment after start() returns
        if manager.progress is not None:
            break
        await asyncio.sleep(0.02)
    assert manager.progress["target"] == "10.0.0.6" and manager.progress["kind"] == "full"
    from app.scanner.orchestrator import ScanBusy
    with pytest.raises(ScanBusy):
        await manager.start("full", target="10.0.0.7")
    gate.set()
    await manager.wait()


@pytest.mark.asyncio
async def test_full_scans_have_their_own_typical_duration(tmp_path):
    app, db = _app(tmp_path)
    conn = connect(db)
    conn.execute("INSERT INTO scans (kind, status, started, finished, target) VALUES ('full', 'done', '2026-03-10T10:00:00Z', '2026-03-10T10:05:00Z', '10.0.0.6')")
    conn.execute("INSERT INTO scans (kind, status, started, finished) VALUES ('deep', 'done', '2026-03-10T10:00:00Z', '2026-03-10T10:20:00Z')")
    conn.commit()
    assert typical_duration(conn, "full") == (300, 1) and typical_duration(conn, "deep") == (1200, 1)
    conn.close()


@pytest.mark.asyncio
async def test_full_scan_api(tmp_path):
    app, db = _app(tmp_path)
    manager = app.state.scan_manager
    gate = asyncio.Event()

    async def runner(kind, targets, **kw):
        await gate.wait()
        return _xml()

    manager.runner = runner
    conn = connect(db)
    conn.execute("INSERT INTO devices (id, mac, first_seen, last_seen) VALUES (9, 'aa:00:00:00:00:09', ?, ?)", (NOW, NOW))  # no IP
    conn.commit()
    conn.close()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=AUTH) as c:
        assert (await c.post("/api/devices/999/scan")).status_code == 404
        r = await c.post("/api/devices/9/scan")
        assert r.status_code == 422 and "no IP" in r.json()["detail"]
        assert (await c.post("/api/devices/3/scan", headers={"Authorization": "Bearer no"})).status_code == 401

        r = await c.post("/api/devices/3/scan")
        assert r.status_code == 202
        cur = (await c.get("/api/scans/current")).json()
        assert cur["running"] and cur["scan"]["kind"] == "full" and cur["scan"]["target"] == "10.0.0.6" and cur["progress"]["target"] == "10.0.0.6"
        assert (await c.post("/api/devices/5/scan")).status_code == 409  # one scan at a time
        gate.set()
        await manager.wait()
        last = (await c.get("/api/scans?limit=1")).json()[0]
        assert (last["kind"], last["target"], last["status"]) == ("full", "10.0.0.6", "done")
        assert (await c.get("/api/scan-options")).json()["preview"]["full"].endswith("-oX - <host>")


# ------------------------------------------------------------------ migration

def test_v3_database_is_migrated_to_v4(tmp_path):
    path = tmp_path / "v3.db"
    conn = connect(path)
    init_db(conn)
    conn.execute("DROP TABLE ignored_devices")
    conn.execute("ALTER TABLE scans DROP COLUMN target")
    conn.execute("UPDATE schema_version SET version = 3")
    conn.commit()
    conn.close()
    conn = connect(path)
    init_db(conn)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION == 13
    conn.execute("INSERT INTO scans (kind, status, started, target) VALUES ('full', 'running', ?, '10.0.0.6')", (NOW,))
    conn.execute("INSERT INTO ignored_devices (mac, label, added) VALUES ('aa:00:00:00:00:01', 'x', ?)", (NOW,))
    with pytest.raises(sqlite3.IntegrityError):  # the MAC is unique
        conn.execute("INSERT INTO ignored_devices (mac, label, added) VALUES ('aa:00:00:00:00:01', 'y', ?)", (NOW,))
    conn.close()
