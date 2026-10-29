"""Networks (app/networks.py): ranges that go quiet are noticed, and nothing else is."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import networks
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

T0 = datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc)
LAN, IOT, SINGLE = "192.168.1.0/24", "10.0.20.0/24", "192.168.1.50"


def at(i):
    return (T0 + timedelta(minutes=15 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    yield conn
    conn.close()


def ips(prefix, n):
    return [f"{prefix}.{i}" for i in range(1, n + 1)]


def kinds(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events WHERE kind IN ('network_quiet', 'network_back') ORDER BY id")]


def scan(db, i, lan=10, iot=10):
    return networks.record_scan(db, [LAN, IOT, SINGLE], ips("192.168.1", lan) + ips("10.0.20", iot), now=at(i))


def test_a_range_that_goes_silent_is_reported_after_two_scans_and_again_when_it_is_back(db):
    for i in range(5):
        assert scan(db, i) == []
    assert scan(db, 5, iot=0) == []                                  # one bad scan is not enough
    assert scan(db, 6, iot=0) == ["network_quiet"]
    assert scan(db, 7, iot=0) == []                                  # said once
    assert "no host answers" in kinds(db)[0][1] and kinds(db)[0][1].startswith(IOT)
    listing = {n["cidr"]: n for n in networks.listing(db)}
    assert listing[IOT]["status"] == "quiet" and listing[LAN]["status"] == "ok" and listing[IOT]["usual_hosts"] == 10
    assert scan(db, 8, iot=3) == []                                  # a few hosts are not back yet: 3 of the usual 10
    assert scan(db, 9, iot=9) == ["network_back"]
    assert [k for k, _ in kinds(db)] == ["network_quiet", "network_back"]
    assert {n["cidr"]: n for n in networks.listing(db)}[IOT]["status"] == "ok"


def test_far_fewer_hosts_is_reported_too(db):
    for i in range(5):
        scan(db, i, iot=40)
    scan(db, 5, iot=4)
    assert scan(db, 6, iot=4) == ["network_quiet"]
    assert "only 4 of the usual 40" in kinds(db)[0][1]


def test_normal_ups_and_downs_say_nothing(db):
    for i, n in enumerate([10, 8, 12, 9, 10, 7, 11, 10, 9, 8, 10, 6, 10, 9]):
        assert scan(db, i, iot=n) == []
    assert kinds(db) == []


def test_a_small_or_new_range_has_nothing_to_lose(db):
    assert networks.record_scan(db, [LAN], [], now=at(0)) == []                # a range that never had a host
    for i in range(1, 5):
        assert networks.record_scan(db, [LAN], [], now=at(i)) == []
    assert networks.listing(db)[0]["status"] == "empty"
    networks.record_scan(db, ["10.9.9.0/24"], ["10.9.9.1"], now=at(5))           # one host: a router, not a network that can go quiet
    for i in range(6, 10):
        assert networks.record_scan(db, ["10.9.9.0/24"], [], now=at(i)) == []


def test_single_addresses_are_not_networks_and_a_network_can_be_switched_off(db):
    scan(db, 0)
    rows = {n["cidr"]: n for n in networks.listing(db)}
    assert set(rows) == {LAN, IOT} and all(r["scan"] for r in rows.values())        # the single address is not tracked as a network
    networks.set_scan(db, rows[IOT]["id"], False)
    assert networks.scan_targets(db) == [LAN]
    assert {n["cidr"]: n for n in networks.listing(db)}[IOT]["status"] == "off"      # still listed, with its devices and its history
    networks.record_scan(db, [LAN], ips("192.168.1", 10), now=at(1))                 # a scan without it says nothing about it
    assert kinds(db) == []
    networks.set_scan(db, rows[IOT]["id"], True)
    scan(db, 2)
    assert {n["cidr"]: n for n in networks.listing(db)}[IOT]["status"] == "ok"


def test_most_specific_range_wins_and_devices_are_counted_per_network(db):
    host = lambda ip, mac: ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")  # noqa: E731
    save_scan_results(db, [host("192.168.1.5", "aa:00:00:00:00:01"), host("10.0.20.7", None), host("10.0.20.8", None)], "quick", now=at(0))
    networks.record_scan(db, ["192.168.0.0/20", LAN, IOT], ["192.168.1.5", "10.0.20.7", "10.0.20.8"], now=at(0))
    listing = {n["cidr"]: n for n in networks.listing(db)}
    assert listing[LAN]["devices"] == 1 and listing["192.168.0.0/20"]["devices"] == 0
    assert (listing[IOT]["devices"], listing[IOT]["no_mac"]) == (2, 2)
    devices = [{"primary_ip": "192.168.1.5"}, {"primary_ip": "10.0.20.7"}, {"primary_ip": "8.8.8.8"}, {"primary_ip": None}]
    networks.assign(db, devices)
    assert [d["network"] and d["network"]["label"] for d in devices] == [LAN, IOT, None, None]
    networks.rename(db, listing[IOT]["id"], "  IoT   VLAN ")
    assert [n["label"] for n in networks.listing(db) if n["cidr"] == IOT] == ["IoT VLAN"]
    with pytest.raises(ValueError):
        networks.rename(db, 1, "x" * 61)


def test_api_and_summary(tmp_path):
    path = tmp_path / "api.db"
    conn = connect(path)
    init_db(conn)
    for i in range(5):
        scan(conn, i)
    scan(conn, 5, iot=0)
    scan(conn, 6, iot=0)
    assert networks.summary(conn) == {"tracked": 2, "quiet": 1, "quiet_names": [IOT]}
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path)

    async def no_cards():
        return []
    app.state.scan_manager.ranges_provider = no_cards
    with TestClient(app, headers={"Authorization": "Bearer t"}) as client:
        rows = client.get("/api/networks").json()["networks"]
        assert [r["status"] for r in rows] == ["quiet", "ok"]            # in order of address
        nid = rows[0]["id"]
        assert client.patch(f"/api/networks/{nid}", json={"name": "IoT"}).json()["networks"][0]["label"] == "IoT"
        assert client.patch("/api/networks/999", json={"name": "x"}).status_code == 404
        assert client.patch(f"/api/networks/{nid}", json={"name": "y" * 61}).status_code == 422
        from app import dashboard
        text = [p["text"] for p in dashboard.current_problems(connect(path))]
        assert any("stopped answering" in t and "IoT" in t for t in text)
        from app import ask_more
        answer = ask_more.r_networks(ask_more.t_networks(connect(path), {}))
        assert "IoT" in answer and "QUIET" in answer
