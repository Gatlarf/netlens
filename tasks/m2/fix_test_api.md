Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
test_type_defaults_unknown is outdated: scans now classify every device. Replace it with a test asserting the types from the fixture: 192.168.1.1 -> 'router', 192.168.1.20 -> 'nas' (hostname pi-nas), 192.168.1.30 -> 'printer', 192.168.1.50 -> 'server'. Look the devices up by primary_ip in the list response (field 'primary_ip'). Also keep a test that a device with type_override set reports that override as 'type'.

CURRENT FILE:
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.config import load_settings
from app.main import create_app
from app.db import connect
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results
from app.scanner.scans import create_scan, finish_scan
from app.db import add_event


@pytest.fixture
def client(tmp_path):
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app) as client:
        yield client


@pytest.fixture
def seeded_client(client, tmp_path):
    conn = connect(tmp_path / "t.db")
    xml_path = Path(__file__).parent / "fixtures" / "deep.xml"
    hosts = parse_nmap_xml(xml_path.read_text(encoding="utf-8"))
    save_scan_results(conn, hosts, "deep")

    scan_id = create_scan(conn, "quick")
    finish_scan(conn, scan_id, "done", hosts_found=4)

    # Find device IDs for seeding events
    devices = conn.execute("SELECT id, primary_ip FROM devices ORDER BY primary_ip").fetchall()
    device_ids = {row["primary_ip"]: row["id"] for row in devices}

    # Add an event for one device
    add_event(conn, "device_new", "x", device_id=device_ids["192.168.1.1"])

    conn.close()
    return client


def test_get_devices_returns_four(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 4
    # Ordered by primary_ip
    ips = [d["primary_ip"] for d in data]
    assert ips == ["192.168.1.1", "192.168.1.20", "192.168.1.30", "192.168.1.50"]


def test_get_devices_no_raw_xml(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    for d in data:
        assert "raw_xml" not in d


def test_get_devices_has_required_fields(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    for d in data:
        assert "name" in d
        assert "type" in d
        assert "open_ports" in d
        assert "tags" in d


def test_name_fallback_primary_ip(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    # .30 has no hostname, so name should be primary_ip
    device_30 = next(d for d in data if d["primary_ip"] == "192.168.1.30")
    assert device_30["name"] == "192.168.1.30"


def test_type_defaults_unknown(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    for d in data:
        assert d["type"] == "unknown"


def test_open_ports_for_first_device(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_1 = next(d for d in data if d["primary_ip"] == "192.168.1.1")
    assert device_1["open_ports"] == 4


def test_query_belkin_returns_only_first(client, seeded_client):
    resp = seeded_client.get("/api/devices", params={"q": "belkin"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["primary_ip"] == "192.168.1.1"


def test_query_case_insensitive(client, seeded_client):
    resp = seeded_client.get("/api/devices", params={"q": "PI-NAS"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["primary_ip"] == "192.168.1.20"


def test_online_false_returns_empty(client, seeded_client):
    resp = seeded_client.get("/api/devices", params={"online": "false"})
    assert resp.status_code == 200
    data = resp.json()
    assert data == []


def test_online_true_returns_four(client, seeded_client):
    resp = seeded_client.get("/api/devices", params={"online": "true"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 4


def test_get_device_by_id(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    resp = seeded_client.get(f"/api/devices/{device_id}")
    assert resp.status_code == 200
    d = resp.json()
    assert "ips" in d
    assert "names" in d
    assert "ports" in d
    assert "events" in d
    assert len(d["ports"]) == 4


def test_get_device_unknown_id_404(client, seeded_client):
    resp = seeded_client.get("/api/devices/9999")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "device not found"


def test_patch_custom_name(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"custom_name": "MyRouter"})
    assert resp.status_code == 200
    d = resp.json()
    assert d["name"] == "MyRouter"


def test_patch_type_override(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"type_override": "router"})
    assert resp.status_code == 200
    d = resp.json()
    assert d["type"] == "router"


def test_patch_tags_stored_cleaned(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"tags": ["a", " b ", "", "c"]})
    assert resp.status_code == 200
    d = resp.json()
    assert d["tags"] == ["a", "b", "c"]


def test_patch_invalid_type_override_422(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"type_override": "toaster"})
    assert resp.status_code == 422


def test_patch_empty_custom_name_clears(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    # First set a custom name
    seeded_client.patch(f"/api/devices/{device_id}", json={"custom_name": "TestName"})
    # Then clear it
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"custom_name": ""})
    assert resp.status_code == 200
    d = resp.json()
    # Should fall back to hostname or primary_ip
    assert d["name"] != "TestName"


def test_patch_notes_leaves_custom_name(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    seeded_client.patch(f"/api/devices/{device_id}", json={"custom_name": "KeepMe"})
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"notes": "some note"})
    assert resp.status_code == 200
    d = resp.json()
    assert d["name"] == "KeepMe"


def test_patch_unknown_device_404(client, seeded_client):
    resp = seeded_client.patch("/api/devices/9999", json={"custom_name": "x"})
    assert resp.status_code == 404


def test_patch_more_than_20_tags_422(client, seeded_client):
    resp = seeded_client.get("/api/devices")
    data = resp.json()
    device_id = data[0]["id"]
    tags = [f"tag{i}" for i in range(21)]
    resp = seeded_client.patch(f"/api/devices/{device_id}", json={"tags": tags})
    assert resp.status_code == 422


def test_get_scans_lists_newest_first(client, seeded_client):
    resp = seeded_client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    # Newest first
    if len(data) > 1:
        assert data[0]["created_at"] >= data[1]["created_at"]


def test_get_scans_honours_limit(client, seeded_client):
    resp = seeded_client.get("/api/scans", params={"limit": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1


def test_get_scans_limit_zero_422(client, seeded_client):
    resp = seeded_client.get("/api/scans", params={"limit": 0})
    assert resp.status_code == 422


def test_get_scans_current_no_running(client, seeded_client):
    resp = seeded_client.get("/api/scans/current")
    assert resp.status_code == 200
    data = resp.json()
    assert data["running"] is False
    assert data["scan"] is None


def test_get_scans_current_running_after_create(client, seeded_client):
    conn = connect(client.app.state.db_path)
    scan_id = create_scan(conn, "test")
    conn.close()
    resp = seeded_client.get("/api/scans/current")
    assert resp.status_code == 200
    data = resp.json()
    assert data["running"] is True
    assert data["scan"] is not None


def test_get_health(client, seeded_client):
    resp = seeded_client.get("/api/health")
    assert resp.status_code == 200