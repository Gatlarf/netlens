import gzip

import pytest

from app.db import connect, get_or_create_device, init_db
from app.scanner import vendor
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import refresh_identification, save_scan_results

T = "2026-10-09T12:00:00Z"


@pytest.fixture(autouse=True)
def reset_vendor():
    vendor.configure(None)
    yield
    vendor.configure(None)


def test_registry_knows_what_nmap_s_older_table_does_not():
    # the five addresses of real devices that nmap could not name (taken from a live network)
    assert vendor.lookup("24:fb:e3:00:00:01") == "HP Inc."
    assert vendor.lookup("34:5a:60:aa:bb:cc").startswith("Micro-Star")
    assert vendor.lookup("98:ba:5f:00:00:01").startswith("TP-Link")
    assert vendor.lookup("BC:24:11:00:00:01").startswith("Proxmox") and vendor.lookup("10:66:6a:37:09:9d") == "Zabbly"
    assert vendor.info()["entries"] > 50000


def test_longer_registrations_win_and_formats_are_accepted():
    assert vendor.lookup("24-FB-E3-00-00-01") == vendor.lookup("24:fb:e3:00:00:01")
    assert vendor.lookup(None) is None and vendor.lookup("not a mac") is None and vendor.lookup("") is None


@pytest.mark.parametrize("mac,kind", [
    ("24:fb:e3:00:00:01", "universal"), ("2a:4f:23:00:00:01", "randomized"), ("0e:01:06:e8:59:17", "randomized"), ("52:54:00:12:34:56", "virtual"),
    ("02:42:ac:11:00:02", "virtual"), ("10:66:6a:37:09:9d", "virtual"), ("bc:24:11:00:00:01", "virtual"), ("66:25:24:aa:bb:cc", "randomized"), (None, None), ("zz", None),
])
def test_mac_kind(mac, kind):
    assert vendor.mac_kind(mac) == kind


def test_a_locally_administered_address_has_no_manufacturer_but_a_virtual_prefix_has_a_label():
    assert vendor.lookup("2a:4f:23:00:00:01") is None and vendor.resolve("2a:4f:23:00:00:01") is None  # a phone's private address
    assert vendor.resolve("52:54:00:12:34:56") == "QEMU/KVM (virtual)" and vendor.resolve("02:42:ac:11:00:02") == "Docker (virtual)"


def test_resolve_prefers_what_nmap_found():
    assert vendor.resolve("24:fb:e3:00:00:01", "Hewlett-Packard") == "Hewlett-Packard"
    assert vendor.resolve("24:fb:e3:00:00:01", None) == "HP Inc."


def test_refresh_downloads_a_newer_copy_and_it_wins_over_the_bundled_one(tmp_path):
    csv = "Registry,Assignment,Organization Name,Organization Address\nMA-L,00AABB,Brand New Corp,x\nMA-S,00AABB123,Tiny Maker,y\nMA-L,24FBE3,Renamed HP,z\n"
    count = vendor.refresh(tmp_path, getter=lambda url: csv.encode(), minimum=2)
    assert count == 3 and (tmp_path / "oui.tsv.gz").exists()
    vendor.configure(tmp_path)
    assert vendor.lookup("00:aa:bb:00:00:01") == "Brand New Corp" and vendor.lookup("00:aa:bb:12:30:01") == "Tiny Maker"  # the 36-bit block is more specific
    assert vendor.lookup("24:fb:e3:00:00:01") == "Renamed HP" and vendor.info()["source"].startswith("downloaded")


def test_refresh_refuses_a_bad_answer_and_keeps_the_old_data(tmp_path):
    with pytest.raises(ValueError):
        vendor.refresh(tmp_path, getter=lambda url: b"<html>Request Rejected</html>")
    with pytest.raises(ValueError, match="incomplete"):
        vendor.refresh(tmp_path, getter=lambda url: b"Registry,Assignment,Organization Name,Organization Address\nMA-L,00AABB,One,x\n")
    assert not (tmp_path / "oui.tsv.gz").exists()
    vendor.configure(tmp_path)
    assert vendor.lookup("24:fb:e3:00:00:01") == "HP Inc."  # still the bundled copy


def test_a_broken_override_falls_back_to_the_bundled_copy(tmp_path):
    (tmp_path / "oui.tsv.gz").write_bytes(b"not gzip")
    vendor.configure(tmp_path)
    assert vendor.lookup("24:fb:e3:00:00:01") == "HP Inc."


# ---- during a scan -------------------------------------------------------------------------------------------------
@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def host(ip, mac, vendor_name=None, os_name=None, os_type=None):
    return ScanHost(ip=ip, mac=mac, vendor=vendor_name, hostnames=[], ports=[], os_name=os_name, os_accuracy=90 if os_name else None, os_type=os_type, ttl=64, via="arp")


def row(conn, ip):
    return conn.execute("SELECT * FROM devices WHERE primary_ip = ?", (ip,)).fetchone()


def test_a_scan_fills_in_the_vendor_nmap_did_not_know(conn):
    save_scan_results(conn, [host("10.0.0.1", "24:fb:e3:00:00:01"), host("10.0.0.2", "52:54:00:12:34:56"), host("10.0.0.3", "2a:4f:23:00:00:01"),
                             host("10.0.0.4", "24:fb:e3:00:00:02", vendor_name="Hewlett-Packard")], "quick", now=T)
    assert row(conn, "10.0.0.1")["vendor"] == "HP Inc." and row(conn, "10.0.0.2")["vendor"] == "QEMU/KVM (virtual)"
    assert row(conn, "10.0.0.3")["vendor"] is None  # a private address has no manufacturer
    assert row(conn, "10.0.0.4")["vendor"] == "Hewlett-Packard"  # what nmap found stays


def test_the_device_class_is_kept_between_scans_so_a_quick_scan_classifies_the_same(conn):
    save_scan_results(conn, [host("10.0.0.5", "aa:bb:cc:00:00:05", os_name="Vimtag CP3 PTZ camera", os_type="webcam")], "deep", now=T)
    assert row(conn, "10.0.0.5")["os_type"] == "webcam" and row(conn, "10.0.0.5")["device_type"] == "camera"
    save_scan_results(conn, [host("10.0.0.5", "aa:bb:cc:00:00:05")], "quick", now=T)  # no OS detection this time
    assert row(conn, "10.0.0.5")["os_type"] == "webcam" and row(conn, "10.0.0.5")["device_type"] == "camera"


def test_refresh_identification_fills_vendors_and_reclassifies_everything(conn):
    device = get_or_create_device(conn, "24:fb:e3:00:00:09", "10.0.0.9")
    conn.execute("UPDATE devices SET device_type = 'unknown', vendor = NULL, os_name = 'Vimtag CP3 PTZ camera' WHERE id = ?", (device,))
    other = get_or_create_device(conn, "aa:bb:cc:00:00:08", "10.0.0.8")
    conn.commit()
    result = refresh_identification(conn)
    assert result["vendors_filled"] == 1 and result["types_changed"] >= 1
    assert row(conn, "10.0.0.9")["vendor"] == "HP Inc." and row(conn, "10.0.0.9")["device_type"] == "camera"  # the OS name says so
    assert refresh_identification(conn) == {"vendors_filled": 0, "types_changed": 0}  # nothing left to change


# ---- API, startup and the monthly refresh -----------------------------------------------------------------------------
from fastapi.testclient import TestClient  # noqa: E402

from app.api import vendor_db as vendor_db_api  # noqa: E402
from app.config import load_settings  # noqa: E402
from app.db import get_setting, set_setting  # noqa: E402
from app.main import create_app  # noqa: E402

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    d = get_or_create_device(c, "24:fb:e3:00:00:09", "10.0.0.9")
    c.execute("UPDATE devices SET device_type = 'unknown', vendor = NULL, os_name = 'Silicondust HDHomeRun set top box' WHERE id = ?", (d,))
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app, headers=ADMIN) as cl:
        cl.app_ = app
        cl.path = path
        yield cl


def test_starting_applies_the_vendor_table_and_the_current_rules_to_known_devices(client):
    device = client.get("/api/devices").json()[0]
    assert device["vendor"] == "HP Inc." and device["type"] == "tv" and device["mac_kind"] == "universal"


def test_device_and_map_report_the_kind_of_mac_address(client):
    conn = connect(client.path)
    get_or_create_device(conn, "2a:4f:23:00:00:01", "10.0.0.10")
    conn.close()
    kinds = {d["primary_ip"]: d["mac_kind"] for d in client.get("/api/devices").json()}
    assert kinds == {"10.0.0.9": "universal", "10.0.0.10": "randomized"}
    assert {n["ip"]: n["mac_kind"] for n in client.get("/api/map").json()["nodes"]} == kinds


def test_new_device_types_can_be_chosen_by_hand_and_unknown_ones_are_refused(client):
    d = client.get("/api/devices").json()[0]["id"]
    assert client.patch(f"/api/devices/{d}", json={"type_override": "tablet"}).json()["type"] == "tablet"
    assert client.patch(f"/api/devices/{d}", json={"type_override": "toaster"}).status_code == 422


def test_vendor_db_api_and_manual_refresh(client, monkeypatch):
    info = client.get("/api/vendor-db").json()
    assert info["entries"] > 50000 and info["source"] == "bundled copy" and info["refreshed"] is None
    monkeypatch.setattr(vendor, "_http_get", lambda url: ("Registry,Assignment,Organization Name,Organization Address\n" + "".join(f"MA-L,{i:06X},Maker {i},x\n" for i in range(1, 40001))).encode())
    r = client.post("/api/vendor-db/refresh")
    assert r.status_code == 200 and r.json()["entries"] == 40000 and r.json()["source"].startswith("downloaded") and r.json()["refreshed"]
    assert "vendors_filled" in r.json()["result"]


def test_a_failing_download_is_a_clean_error_and_is_remembered(client, monkeypatch):
    def boom(url):
        raise OSError("no route")

    monkeypatch.setattr(vendor, "_http_get", boom)
    r = client.post("/api/vendor-db/refresh")
    assert r.status_code == 502 and "no route" in r.json()["detail"]
    assert "no route" in client.get("/api/vendor-db").json()["error"]


def test_the_refresh_is_due_monthly_and_a_failure_is_retried_after_a_day(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    assert vendor_db_api.due(conn, "2026-10-09T12:00:00Z")  # never refreshed
    set_setting(conn, vendor_db_api.REFRESHED_KEY, "2026-10-01T12:00:00Z")
    assert not vendor_db_api.due(conn, "2026-10-20T12:00:00Z") and vendor_db_api.due(conn, "2026-10-31T12:00:00Z")
    set_setting(conn, vendor_db_api.ERROR_KEY, "2026-10-20T12:00:00Z boom")
    assert not vendor_db_api.due(conn, "2026-10-20T20:00:00Z") and vendor_db_api.due(conn, "2026-10-21T12:00:00Z")


def test_only_administrators_may_trigger_the_download(client):
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    vera = TestClient(client.app_)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.post("/api/vendor-db/refresh").status_code == 403 and vera.get("/api/vendor-db").status_code == 403
