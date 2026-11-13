import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

AUTH = {"Authorization": "Bearer secret"}


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.1", "aa:00:00:00:00:01"), host("10.0.0.2", "aa:00:00:00:00:02")], "quick", "2026-03-10T12:00:00Z")
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_bulk_edit_changes_only_what_is_sent(client):
    one, two = sorted(client.get("/api/devices").json(), key=lambda d: d["primary_ip"])
    group = client.post("/api/groups", json={"name": "Lab", "color": "#336699"}).json()
    res = client.post("/api/devices/bulk", json={"changes": [
        {"id": one["id"], "custom_name": "Switch", "trusted": True, "always_on": True, "notify_offline": True, "report_exclude": True, "gentle": True, "type_override": "switch", "group_id": group["id"]},
        {"id": two["id"], "trusted": True},
    ]})
    assert res.status_code == 200 and res.json() == {"changed": 2, "errors": []}
    now = {d["id"]: d for d in client.get("/api/devices").json()}
    a, b = now[one["id"]], now[two["id"]]
    assert (a["name"], a["type"], a["group_id"]) == ("Switch", "switch", group["id"])
    assert a["trusted"] and a["always_on"] and a["notify_offline"] and a["report_exclude"] and a["gentle"]
    assert b["trusted"] and not b["always_on"] and not b["report_exclude"] and b["name"] == two["name"] and b["group_id"] is None


def test_bulk_edit_reports_a_bad_row_and_goes_on(client):
    one, two = sorted(client.get("/api/devices").json(), key=lambda d: d["primary_ip"])
    res = client.post("/api/devices/bulk", json={"changes": [
        {"id": one["id"], "type_override": "not-a-type"},
        {"id": 9999, "trusted": True},
        {"id": two["id"], "custom_name": "Printer"},
    ]}).json()
    assert res["changed"] == 1
    assert sorted(e["id"] for e in res["errors"]) == [one["id"], 9999]
    assert {d["id"]: d["name"] for d in client.get("/api/devices").json()}[two["id"]] == "Printer"


def test_bulk_edit_refuses_unknown_fields(client):
    one = client.get("/api/devices").json()[0]
    assert client.post("/api/devices/bulk", json={"changes": [{"id": one["id"], "notes": "x"}]}).status_code == 422
