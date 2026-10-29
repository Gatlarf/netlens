"""Network cards: a host with two MAC addresses is two devices; the owner links them (devices.same_host_id)."""

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.dns.plan import DnsDevice, DnsSettings, build_plan, parse_networks
from app.main import create_app
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

NOW = "2026-10-10T12:00:00Z"
ZONE = "home.example.com"


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "n.db"
    conn = connect(path)
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.20", "aa:00:00:00:00:02"), host("10.0.0.21", "aa:00:00:00:00:03"), host("10.0.0.22", "aa:00:00:00:00:04")], "quick", now=NOW)
    conn.close()
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path), headers={"Authorization": "Bearer t"}) as c:
        yield c


def detail(client, i):
    return client.get(f"/api/devices/{i}").json()


def test_linking_a_card_shows_on_both_devices(client):
    assert client.patch("/api/devices/2", json={"nic_of": 1}).status_code == 200
    host_page, card_page = detail(client, 1), detail(client, 2)
    assert [(n["id"], n["mac"], n["ip"]) for n in host_page["nics"]] == [(2, "aa:00:00:00:00:03", "10.0.0.21")] and host_page["nic_of"] is None
    assert card_page["nic_of"]["id"] == 1 and card_page["nics"] == []
    assert detail(client, 3)["nics"] == [] and detail(client, 3)["nic_of"] is None
    assert client.patch("/api/devices/2", json={"nic_of": None}).status_code == 200
    assert detail(client, 1)["nics"] == [] and detail(client, 2)["nic_of"] is None


def test_what_cannot_be_linked(client):
    assert client.patch("/api/devices/1", json={"nic_of": 1}).status_code == 422             # itself
    assert client.patch("/api/devices/1", json={"nic_of": 99}).status_code == 422            # nothing there
    client.patch("/api/devices/2", json={"nic_of": 1})
    assert client.patch("/api/devices/1", json={"nic_of": 2}).status_code == 422             # the host cannot become a card of its own card


def test_a_card_of_a_card_is_a_card_of_the_main_host(client):
    client.patch("/api/devices/2", json={"nic_of": 1})
    client.patch("/api/devices/3", json={"nic_of": 2})
    assert detail(client, 3)["nic_of"]["id"] == 1
    assert sorted(n["id"] for n in detail(client, 1)["nics"]) == [2, 3]


def test_a_host_that_becomes_a_card_takes_its_cards_along(client):
    client.patch("/api/devices/2", json={"nic_of": 1})
    client.patch("/api/devices/1", json={"nic_of": 3})
    assert detail(client, 2)["nic_of"]["id"] == 3 and detail(client, 1)["nic_of"]["id"] == 3
    assert sorted(n["id"] for n in detail(client, 3)["nics"]) == [1, 2]


def test_deleting_the_host_frees_its_cards(client, tmp_path):
    client.patch("/api/devices/2", json={"nic_of": 1})
    assert client.delete("/api/devices/1").status_code in (200, 204)
    assert detail(client, 2)["nic_of"] is None


def test_dns_registers_the_hosts_own_name_only():
    st = DnsSettings(networks=parse_networks(f"10.0.0.0/24 = {ZONE}"), grace_hours=0)
    snapshot = {"zones": [{"name": ZONE, "kind": "forward", "writable": True}], "records": [], "server": "dns1"}

    def items(*devices):
        result = build_plan(list(devices), snapshot, st, NOW)
        return {i["device_id"]: i for i in result["items"]}

    main = DnsDevice(id=1, ip="10.0.0.20", hostname=f"nas.{ZONE}")
    card = DnsDevice(id=2, ip="10.0.0.21", hostname=f"nas.{ZONE}", nic_of=1)
    got = items(main, card)
    assert got[1]["state"] == "add" and got[2]["state"] == "skip" and "network card" in got[2]["reason"]
    own = DnsDevice(id=2, ip="10.0.0.21", hostname=f"nas.{ZONE}", nic_of=1, dns_name="nas-storage")
    assert items(main, own)[2]["state"] == "add"                                               # a name of its own is honoured
    always = DnsDevice(id=2, ip="10.0.0.21", hostname=f"nas2.{ZONE}", nic_of=1, dns_mode="always")
    assert items(main, always)[2]["state"] == "add"
