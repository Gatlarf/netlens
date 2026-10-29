"""MAC addresses for hosts behind a router (app/arpcache.py, the ARP table read over SNMP)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app import arpcache
from app.db import connect, init_db
from app.hostmetrics import service as hm, snmp
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

T0 = datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc)
ROUTER_MAC = "aa:00:00:00:00:01"


def at(minutes):
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def host(ip, mac=None):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=60, via="icmp")


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.1", ROUTER_MAC)], "quick", now=at(0))
    yield conn
    conn.close()


class FakeAgent:
    """Answers walks of the two ARP tables from fixed rows: {base oid: [(suffix, value)]}."""

    def __init__(self, tables):
        self.tables = tables

    def walk(self, base):
        return list(self.tables.get(tuple(base), []))


def mac(n):
    return bytes([0x02, 0, 0, 0, 0, n])


def test_the_arp_table_is_read_from_both_mibs_and_bad_entries_are_dropped():
    media = {snmp.IP_NET_TO_MEDIA_PHYS: [((7, 10, 0, 20, 5), mac(5)), ((7, 10, 0, 20, 6), mac(6)), ((7, 10, 0, 20, 7), b"\x00\x01"), ((7, 10, 0, 20, 8), mac(8))],
             snmp.IP_NET_TO_MEDIA_TYPE: [((7, 10, 0, 20, 6), 2), ((7, 10, 0, 20, 5), 3)]}                     # .6 is marked invalid; .7 is not a MAC
    got = snmp.read_arp(FakeAgent(media))
    assert got == [("10.0.20.5", "02:00:00:00:00:05", 7), ("10.0.20.8", "02:00:00:00:00:08", 7)]
    newer = {snmp.IP_NET_TO_PHYS_PHYS: [((3, 1, 4, 10, 0, 30, 9), mac(9)), ((3, 2, 16) + (0,) * 16, mac(1)), ((3, 1, 4, 10, 0, 30, 10), mac(10))],
             snmp.IP_NET_TO_PHYS_STATE: [((3, 1, 4, 10, 0, 30, 10), 7)]}                                       # IPv6 row and an incomplete entry are skipped
    assert snmp.read_arp(FakeAgent(newer)) == [("10.0.30.9", "02:00:00:00:00:09", 3)]
    assert snmp.read_arp(FakeAgent({})) == []


def test_only_station_addresses_are_kept(db):
    entries = [("10.0.20.1", "00:00:00:00:00:00", 1), ("10.0.20.2", "ff:ff:ff:ff:ff:ff", 1), ("10.0.20.3", "01:00:5e:00:00:01", 1), ("10.0.20.4", "zz", 1), ("10.0.20.5", "02:00:00:00:00:05", 1)]
    assert arpcache.learn(db, 1, entries, at(1)) == 1
    assert arpcache.fresh(db, at(1)) == {"10.0.20.5": "02:00:00:00:00:05"}


def test_a_host_behind_a_router_gets_its_mac_and_keeps_its_history(db):
    save_scan_results(db, [host("10.0.20.5")], "quick", now=at(2))                    # found by address alone: no MAC
    first = db.execute("SELECT id, mac FROM devices WHERE primary_ip = '10.0.20.5'").fetchone()
    assert first["mac"] is None
    arpcache.learn(db, 1, [("10.0.20.5", "02:00:00:00:00:05", 7)], at(3))
    save_scan_results(db, [host("10.0.20.5")], "quick", now=at(4))
    rows = db.execute("SELECT id, mac, primary_ip FROM devices WHERE primary_ip = '10.0.20.5'").fetchall()
    assert [(r["id"], r["mac"]) for r in rows] == [(first["id"], "02:00:00:00:00:05")]       # the same device took the MAC over: no duplicate
    # the lease moves: the same MAC on another address is the same device, and that is an address change
    arpcache.learn(db, 1, [("10.0.20.9", "02:00:00:00:00:05", 7)], at(5))
    save_scan_results(db, [host("10.0.20.9")], "quick", now=at(6))
    moved = db.execute("SELECT id, primary_ip FROM devices WHERE mac = '02:00:00:00:00:05'").fetchall()
    assert [(r["id"], r["primary_ip"]) for r in moved] == [(first["id"], "10.0.20.9")]
    assert [r["detail"] for r in db.execute("SELECT detail FROM events WHERE kind = 'ip_changed'")] == ["10.0.20.5 -> 10.0.20.9"]


def test_what_the_scan_saw_is_never_replaced(db):
    arpcache.learn(db, 1, [("10.0.0.50", "02:00:00:00:00:50", 1)], at(1))
    save_scan_results(db, [host("10.0.0.50", "02:00:00:00:00:99")], "quick", now=at(2))
    assert db.execute("SELECT mac FROM devices WHERE primary_ip = '10.0.0.50'").fetchone()["mac"] == "02:00:00:00:00:99"


def test_an_old_entry_is_not_used(db):
    arpcache.learn(db, 1, [("10.0.20.5", "02:00:00:00:00:05", 7)], at(1))
    assert arpcache.fresh(db, at(59)) == {"10.0.20.5": "02:00:00:00:00:05"}
    assert arpcache.fresh(db, at(65)) == {}
    save_scan_results(db, [host("10.0.20.5")], "quick", now=at(70))
    assert db.execute("SELECT mac FROM devices WHERE primary_ip = '10.0.20.5'").fetchone()["mac"] is None


def test_one_mac_for_many_addresses_is_a_router_not_a_host(db):
    entries = [(f"10.0.30.{i}", "02:00:00:00:00:77", 1) for i in range(1, arpcache.MAX_IPS_PER_MAC + 2)] + [("10.0.30.200", "02:00:00:00:00:88", 1)]
    arpcache.learn(db, 1, entries, at(1))
    known = arpcache.fresh(db, at(1))
    assert known == {"10.0.30.200": "02:00:00:00:00:88"}                                    # a proxy-ARP router would otherwise merge all of them into one device
    save_scan_results(db, [host("10.0.30.1"), host("10.0.30.2")], "quick", now=at(2))
    assert db.execute("SELECT COUNT(*) FROM devices WHERE mac IS NULL AND primary_ip LIKE '10.0.30.%'").fetchone()[0] == 2


def test_a_router_or_switch_reads_its_arp_table_by_itself(db):
    db.execute("UPDATE devices SET device_type = 'router' WHERE id = 1")
    db.execute("INSERT INTO host_monitors (device_id, method, address, port, interval_s, created) VALUES (1, 'snmp', '10.0.0.1', 161, 60, ?)", (at(0),))
    row = db.execute("SELECT * FROM host_monitors").fetchone()
    assert hm.reads_arp(db, row) is True
    db.execute("UPDATE devices SET device_type = 'pc' WHERE id = 1")
    assert hm.reads_arp(db, row) is False                                                   # a PC is not asked
    db.execute("UPDATE host_monitors SET arp_mode = 'on'")
    assert hm.reads_arp(db, db.execute("SELECT * FROM host_monitors").fetchone()) is True
    db.execute("UPDATE devices SET device_type = 'router' WHERE id = 1")
    db.execute("UPDATE host_monitors SET arp_mode = 'off'")
    assert hm.reads_arp(db, db.execute("SELECT * FROM host_monitors").fetchone()) is False


def test_the_monitor_reads_the_table_every_five_minutes(db, monkeypatch):
    db.execute("UPDATE devices SET device_type = 'router' WHERE id = 1")
    db.execute("INSERT INTO host_monitors (device_id, method, address, port, interval_s, created) VALUES (1, 'snmp', '10.0.0.1', 161, 60, ?)", (at(0),))
    row = db.execute("SELECT * FROM host_monitors").fetchone()
    reads = []
    monkeypatch.setattr(hm, "make_agent", lambda *a, **k: "agent")
    monkeypatch.setattr(snmp, "read_arp", lambda agent: reads.append(agent) or [("10.0.20.5", "02:00:00:00:00:05", 7)])
    state = {}
    asyncio.run(hm._learn_arp(db, row, {"community": "x"}, state, 1000.0, at(1)))
    asyncio.run(hm._learn_arp(db, row, {"community": "x"}, state, 1060.0, at(2)))          # a minute later: not again
    assert len(reads) == 1 and arpcache.entries_of(db, 1) == 1
    asyncio.run(hm._learn_arp(db, row, {"community": "x"}, state, 1000.0 + hm.ARP_EVERY, at(6)))
    assert len(reads) == 2

    def fail(agent):
        raise snmp.SnmpError("no answer")

    monkeypatch.setattr(snmp, "read_arp", fail)
    asyncio.run(hm._learn_arp(db, row, {"community": "x"}, state, 5000.0, at(90)))        # a failure is not the monitor's failure
    assert arpcache.entries_of(db, 1) == 1


def test_the_setting_is_validated_and_kept():
    ok = hm.validate({"method": "snmp", "address": "10.0.0.1", "community": "c", "arp_mode": "on"})
    assert ok["arp_mode"] == "on"
    assert hm.validate({"method": "snmp", "address": "10.0.0.1", "community": "c"})["arp_mode"] == "auto"
    assert hm.validate({"method": "ssh", "address": "10.0.0.1", "username": "u", "password": "p", "arp_mode": "on"})["arp_mode"] == "auto"      # only SNMP has it
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "snmp", "address": "10.0.0.1", "community": "c", "arp_mode": "sometimes"})


# ------------------------------------------------------------------ the client list of a router or DHCP plugin
def test_dhcp_leases_and_router_clients_give_hosts_their_mac(db):
    from app.plugins.enrich import record_client_macs

    data = {"clients": [{"mac": "02:00:00:00:00:31", "ip": "10.0.30.31", "name": "printer"}, {"mac": "02:00:00:00:00:32", "ip": None}, {"mac": "bad", "ip": "10.0.30.33"}]}
    assert record_client_macs(db, "kea", data, at(1)) == 1
    assert arpcache.fresh(db, at(1)) == {"10.0.30.31": "02:00:00:00:00:31"}
    assert db.execute("SELECT source, device_id FROM arp_cache").fetchone()["source"] == "plugin:kea"
    save_scan_results(db, [host("10.0.30.31")], "quick", now=at(2))
    assert db.execute("SELECT mac FROM devices WHERE primary_ip = '10.0.30.31'").fetchone()["mac"] == "02:00:00:00:00:31"
    assert record_client_macs(db, "kea", {"clients": []}, at(3)) == 0


def test_clients_the_scan_did_not_find_are_listed_not_added(db):
    import json

    from app import networks
    from app.db import set_setting

    save_scan_results(db, [host("10.0.40.5", "02:00:00:00:00:05")], "quick", now=at(1))
    networks.add(db, "10.0.40.0/24")
    clients = [{"mac": "02:00:00:00:00:05", "ip": "10.0.40.5", "name": "known"},            # found by the scan
               {"mac": "02:00:00:00:00:41", "ip": "10.0.40.41", "name": "asleep phone", "medium": "wifi"},
               {"mac": "02:00:00:00:00:42", "ip": "10.0.40.7", "name": "known by address only"},
               {"mac": "02:00:00:00:00:43", "ip": "172.20.0.9", "name": "outside the scanned networks"}]
    set_setting(db, "plugin.kea.data", json.dumps({"nodes": [], "clients": clients}))
    set_setting(db, "plugin.kea", json.dumps({"enabled": True}))
    db.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (2, '10.0.40.7', ?, ?)", (at(0), at(0)))
    save_scan_results(db, [host("10.0.40.7", "02:00:00:00:00:99")], "quick", now=at(2))
    got = networks.unseen_clients(db)
    assert got["count"] == 1 and got["clients"][0]["ip"] == "10.0.40.41" and got["clients"][0]["source"] == "kea" and got["clients"][0]["medium"] == "wifi"
    assert db.execute("SELECT COUNT(*) FROM devices WHERE primary_ip = '10.0.40.41'").fetchone()[0] == 0          # listed only
    set_setting(db, "plugin.kea", json.dumps({"enabled": False}))
    assert networks.unseen_clients(db)["count"] == 0                                                              # a plugin that is off says nothing
