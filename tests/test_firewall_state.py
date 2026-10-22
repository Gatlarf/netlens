"""What a firewall plugin reports besides its clients: stored, shown, and the events when it changes."""

import copy
import sqlite3

import pytest

from app.db import init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_firewall, record_switch_ports

NODE = {"mac": "aa:00:00:00:00:01", "ip": "10.0.0.1", "name": "fw", "role": "gateway", "ports": [{"port": 1, "name": "wan1", "up": True, "enabled": True}],
        "firewall": {"version": "v7.2.5", "serial": "FGT123", "model": "FortiGate 60F",
                     "ha": {"mode": "a-p", "state": "primary", "peer_state": "secondary", "in_sync": True},
                     "tunnels": [{"name": "to-hq", "remote": "203.0.113.5", "up": True}, {"name": "to-lab", "up": False}],
                     "licences": [{"name": "Support", "expires": "2027-06-30"}, {"name": "IPS", "expires": "2026-11-01"}]}}


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.1', 'fw', 1, 'x', 'x')")
    c.commit()
    return c


def out(node):
    return validate_output("topology", {"nodes": [node], "clients": []})


def events(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events ORDER BY id")]


def test_the_contract_keeps_the_firewall_part_and_rejects_nonsense():
    fw = out(NODE)["nodes"][0]["firewall"]
    assert fw["ha"]["state"] == "primary" and [t["up"] for t in fw["tunnels"]] == [True, False] and fw["licences"][0]["expires"] == "2027-06-30"
    bad = copy.deepcopy(NODE)
    bad["firewall"]["licences"][0]["expires"] = "June 2027"
    with pytest.raises(ContractError):
        out(bad)
    assert out({k: v for k, v in NODE.items() if k != "firewall"})["nodes"][0]["firewall"] is None


def test_a_node_without_a_mac_gets_a_placeholder_from_its_address():
    node = out({"ip": "10.0.0.7", "name": "gw", "role": "gateway"})["nodes"][0]
    assert node["mac"] == "02:00:0a:00:00:07"
    with pytest.raises(ContractError):
        out({"name": "gw", "role": "gateway"})


def test_first_sync_stores_and_warns_once_about_a_licence_that_ends_soon(conn):
    assert record_firewall(conn, "fortigate", out(NODE), now="2026-10-20T10:00:00Z") == 1
    assert events(conn) == [("firewall_licence", "fw: IPS ends in 12 day(s)")]
    record_firewall(conn, "fortigate", out(NODE), now="2026-10-21T10:00:00Z")
    assert len(events(conn)) == 1                                   # not again for the same end date


def test_failover_and_tunnel_changes_raise_events(conn):
    record_firewall(conn, "fortigate", out(NODE), now="2026-10-20T10:00:00Z")
    changed = copy.deepcopy(NODE)
    changed["firewall"]["ha"].update(state="secondary", peer_state="primary")
    changed["firewall"]["tunnels"] = [{"name": "to-hq", "up": False}, {"name": "to-lab", "up": True}]
    record_firewall(conn, "fortigate", out(changed), now="2026-10-20T10:05:00Z")
    kinds = [e for e in events(conn) if e[0] != "firewall_licence"]
    assert ("firewall_ha", "fw: high availability primary -> secondary") in kinds
    assert ("vpn_down", "fw: tunnel to-hq") in kinds and ("vpn_up", "fw: tunnel to-lab") in kinds


def test_interfaces_come_through_the_ports_of_the_node(conn):
    record_switch_ports(conn, "fortigate", out(NODE))
    assert conn.execute("SELECT name, up FROM switch_ports").fetchone()["name"] == "wan1"
