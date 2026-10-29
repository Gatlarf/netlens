"""Why does a network not answer (app/netdiag.py): the route, the gateway and the devices that used to live there."""

import asyncio

import pytest

from app import netdiag, networks
from app.db import connect, init_db
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

NOW = "2026-10-29T09:00:00Z"


def up_xml(*ips):
    hosts = "".join(f'<host><status state="up" reason="echo-reply"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips)
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{hosts}</nmaprun>'


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=60, via="icmp")


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    save_scan_results(conn, [host("10.0.20.1", "aa:00:00:00:00:01"), host("10.0.20.5", "aa:00:00:00:00:05"), host("10.0.20.6", "aa:00:00:00:00:06"), host("192.168.0.9", "aa:00:00:00:00:09")], "quick", now=NOW)
    conn.execute("UPDATE devices SET device_type = 'router', always_on = 1 WHERE primary_ip = '10.0.20.1'")
    conn.commit()
    networks.record_scan(conn, ["10.0.20.0/24", "192.168.0.0/24"], ["10.0.20.1", "10.0.20.5", "10.0.20.6", "192.168.0.9"], now=NOW)
    yield conn
    conn.close()


def net_id(db, cidr):
    return db.execute("SELECT id FROM networks WHERE cidr = ?", (cidr,)).fetchone()["id"]


def run(db, cidr, answering, route):
    async def nmap(args):
        asked = [a for a in args if a.count(".") == 3 and a[0].isdigit()]
        return up_xml(*[ip for ip in asked if ip in answering])

    async def ip(args):
        return route

    return asyncio.run(netdiag.diagnose(db, net_id(db, cidr), nmap, ip))


def titles(result, level=None):
    return [f["title"] for f in result["findings"] if level is None or f["level"] == level]


def test_the_route_is_read_from_ip():
    assert netdiag.parse_route("10.0.20.5 via 192.168.0.1 dev eth0 src 192.168.0.189 uid 1000\n    cache") == {"found": True, "gateway": "192.168.0.1", "dev": "eth0"}
    assert netdiag.parse_route("192.168.0.9 dev eth0 src 192.168.0.189") == {"found": True, "gateway": None, "dev": "eth0"}
    assert netdiag.parse_route("") == {"found": False, "gateway": None, "dev": None}


def test_the_most_useful_devices_are_asked_first(db):
    from ipaddress import ip_network

    picked = netdiag._pick(db, ip_network("10.0.20.0/24"))
    assert [p["primary_ip"] for p in picked][0] == "10.0.20.1" and {p["primary_ip"] for p in picked} == {"10.0.20.1", "10.0.20.5", "10.0.20.6"}


def test_no_route(db):
    r = run(db, "10.0.20.0/24", set(), "")
    assert titles(r, "bad") == ["There is no route to this network"]


def test_the_gateway_is_down(db):
    r = run(db, "10.0.20.0/24", set(), "10.0.20.1 via 192.168.0.1 dev eth0 src 192.168.0.189")
    assert "The gateway 192.168.0.1 does not answer" in titles(r, "bad")
    assert r["route"]["gateway"] == "192.168.0.1" and r["route"]["gateway_answers"] is False


def test_a_route_and_a_gateway_but_nothing_answers_is_a_filter_problem(db):
    r = run(db, "10.0.20.0/24", {"192.168.0.1"}, "10.0.20.1 via 192.168.0.1 dev eth0 src 192.168.0.189")
    assert titles(r, "bad") == ["A route exists, the gateway answers, but none of the known devices does"]
    assert "firewall" in r["findings"][-1]["text"]
    assert [p["answered"] for p in r["probes"]] == [False, False, False]


def test_a_reachable_network(db):
    r = run(db, "10.0.20.0/24", {"192.168.0.1", "10.0.20.1", "10.0.20.5"}, "10.0.20.1 via 192.168.0.1 dev eth0 src 192.168.0.189")
    assert titles(r, "ok") == ["2 of 3 known devices answer now"] and not titles(r, "bad")
    assert {p["ip"]: p["answered"] for p in r["probes"]} == {"10.0.20.1": True, "10.0.20.5": True, "10.0.20.6": False}


def test_a_directly_connected_network_that_is_silent_points_at_the_vlan(db):
    r = run(db, "192.168.0.0/24", set(), "192.168.0.9 dev eth0 src 192.168.0.189")
    assert titles(r, "bad") == ["Nothing answers on a directly connected network"] and "trunk" in r["findings"][-1]["text"]
    assert "This network is directly connected" in titles(r, "info")


def test_a_network_without_known_devices_says_so(db):
    networks.add(db, "10.9.9.0/24")

    async def nmap(args):
        return up_xml()

    r = asyncio.run(netdiag.diagnose(db, net_id(db, "10.9.9.0/24"), nmap, lambda a: asyncio.sleep(0, "10.9.9.1 dev eth0")))
    assert "No device of this network is known yet" in titles(r)


def test_the_api_and_a_failing_nmap(db, tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    path = db.file if hasattr(db, "file") and db.file else None
    if not path:
        pytest.skip("needs the database file")
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path)

    async def nmap(args):
        raise netdiag.actions.ActionError("nmap is not available")

    app.state.action_runner = nmap
    with TestClient(app, headers={"Authorization": "Bearer t"}) as c:
        r = c.post(f"/api/networks/{net_id(db, '10.0.20.0/24')}/test")
        assert r.status_code == 200 and r.json()["network"]["cidr"] == "10.0.20.0/24" and r.json()["probes"]
        assert c.post("/api/networks/999/test").status_code == 404
