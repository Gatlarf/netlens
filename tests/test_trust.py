import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T12:00:00Z"


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as c:
        c.db = path
        yield c


def test_new_devices_start_unknown_and_can_be_trusted(client):
    conn = connect(client.db)
    save_scan_results(conn, [host("10.0.0.1", "aa:00:00:00:00:01"), host("10.0.0.2", "aa:00:00:00:00:02")], "quick", NOW)
    conn.close()
    devices = {d["primary_ip"]: d for d in client.get("/api/devices").json()}
    assert devices["10.0.0.1"]["trusted"] is False
    assert [d["primary_ip"] for d in client.get("/api/devices", params={"trusted": "false"}).json()] == ["10.0.0.1", "10.0.0.2"]
    dev_id = devices["10.0.0.1"]["id"]
    assert client.patch(f"/api/devices/{dev_id}", json={"trusted": True}).json()["trusted"] is True
    assert [d["primary_ip"] for d in client.get("/api/devices", params={"trusted": "false"}).json()] == ["10.0.0.2"]
    assert client.get(f"/api/devices/{dev_id}").json()["trusted"] is True


def test_trust_in_bulk(client):
    conn = connect(client.db)
    save_scan_results(conn, [host(f"10.0.0.{i}", f"aa:00:00:00:00:0{i}") for i in (1, 2, 3)], "quick", NOW)
    conn.close()
    ids = [d["id"] for d in client.get("/api/devices").json()]
    assert client.post("/api/devices/trust", json={"ids": ids[:2]}).json() == {"changed": 2}
    assert client.post("/api/devices/trust", json={"ids": ids[:2]}).json() == {"changed": 0}  # nothing left to change
    assert client.post("/api/devices/trust", json={}).json() == {"changed": 1}  # everything
    assert client.post("/api/devices/trust", json={"ids": [ids[0]], "trusted": False}).json() == {"changed": 1}
    assert client.post("/api/devices/trust", json={"ids": []}).json() == {"changed": 0}
    assert client.post("/api/devices/trust", json={}, headers={"Authorization": "Bearer no"}).status_code == 401


def test_upgrade_trusts_everything_that_already_exists(tmp_path):
    path = tmp_path / "old.db"
    conn = connect(path)
    init_db(conn)
    get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.1")
    conn.execute("ALTER TABLE devices DROP COLUMN trusted")  # a database from before the column existed
    conn.commit()
    conn.close()
    conn = connect(path)
    init_db(conn)
    assert conn.execute("SELECT trusted FROM devices").fetchone()[0] == 1  # not "unknown devices" all of a sudden
    save_scan_results(conn, [host("10.0.0.9", "aa:00:00:00:00:09")], "quick", NOW)
    assert conn.execute("SELECT trusted FROM devices WHERE primary_ip = '10.0.0.9'").fetchone()[0] == 0
    init_db(conn)  # running it again changes nothing
    assert conn.execute("SELECT trusted FROM devices WHERE primary_ip = '10.0.0.9'").fetchone()[0] == 0


def test_an_ip_taken_over_by_another_device_is_noted_once(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.5", "aa:00:00:00:00:01")], "quick", NOW)
    save_scan_results(conn, [host("10.0.0.5", "aa:00:00:00:00:02")], "quick", "2026-03-10T12:15:00Z")
    save_scan_results(conn, [host("10.0.0.5", "aa:00:00:00:00:02")], "quick", "2026-03-10T12:30:00Z")
    events = [tuple(r) for r in conn.execute("SELECT kind, detail FROM events WHERE kind = 'ip_reused'")]
    assert len(events) == 1 and "aa:00:00:00:00:02" in events[0][1] and "aa:00:00:00:00:01" in events[0][1]
    # long ago: no event
    save_scan_results(conn, [host("10.0.0.7", "aa:00:00:00:00:03")], "quick", "2026-03-01T12:00:00Z")
    save_scan_results(conn, [host("10.0.0.7", "aa:00:00:00:00:04")], "quick", NOW)
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'ip_reused'").fetchone()[0] == 1
