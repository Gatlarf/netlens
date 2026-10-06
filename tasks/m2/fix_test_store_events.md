Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
test_device_type_classification expects device 192.168.1.20 (hostname 'pi-nas', ports 22 and 445, Linux) to be 'server'. The classifier correctly returns 'nas' because the hostname contains 'nas'. Expect 'nas' for 192.168.1.20. Keep the other expectations (.30 printer, .1 router).

CURRENT FILE:
import dataclasses
from pathlib import Path
from typing import Any

import pytest
from app.db import connect, init_db
from app.scanner.nmap_parser import ScanHost, ScanPort, parse_nmap_xml
from app.scanner.store import save_scan_results


def _fixture_path() -> Path:
    return Path(__file__).parent / "fixtures" / "deep.xml"


def _load_hosts() -> list[ScanHost]:
    path = _fixture_path()
    return parse_nmap_xml(path.read_text(encoding="utf-8"))


def _get_events(conn: Any) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT kind, detail, device_id FROM events ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def _get_device(conn: Any, mac: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    return dict(row) if row else None


def _get_device_by_ip(conn: Any, ip: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM devices WHERE primary_ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def _get_device_names(conn: Any, device_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM device_names WHERE device_id = ?", (device_id,)).fetchall()
    return [dict(row) for row in rows]


def _get_device_ips(conn: Any, device_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM device_ips WHERE device_id = ?", (device_id,)).fetchall()
    return [dict(row) for row in rows]


def _get_ports(conn: Any, device_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM ports WHERE device_id = ?", (device_id,)).fetchall()
    return [dict(row) for row in rows]


@pytest.fixture
def conn():
    c = connect(":memory:")
    init_db(c)
    yield c
    c.close()


def test_first_deep_save_creates_device_new_events(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    events = _get_events(conn)
    assert len(events) == 4
    assert all(e["kind"] == "device_new" for e in events)
    assert not any(e["kind"] == "port_opened" for e in events)


def test_identical_resave_creates_no_events(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    events_before = _get_events(conn)
    save_scan_results(conn, hosts, "deep")
    events_after = _get_events(conn)
    assert len(events_after) == len(events_before)
    assert len(events_after) == 4


def test_ip_change_creates_event(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Replace .1 host with same mac but different ip
    host1 = next(h for h in hosts if h.ip == "192.168.1.1")
    modified_host = dataclasses.replace(host1, ip="192.168.1.2")
    modified_hosts = [modified_host if h is host1 else h for h in hosts]
    save_scan_results(conn, modified_hosts, "deep")
    events = _get_events(conn)
    ip_changed_events = [e for e in events if e["kind"] == "ip_changed"]
    assert len(ip_changed_events) == 1
    assert ip_changed_events[0]["detail"] == "192.168.1.1 -> 192.168.1.2"


def test_device_online_event_when_reonline(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Set .20 device offline
    device = _get_device(conn, "b8:27:eb:12:34:56")
    assert device is not None
    conn.execute("UPDATE devices SET online = 0 WHERE id = ?", (device["id"],))
    conn.commit()
    # Resave same hosts
    save_scan_results(conn, hosts, "deep")
    events = _get_events(conn)
    online_events = [e for e in events if e["kind"] == "device_online"]
    assert len(online_events) == 1
    # Verify online is back to 1
    device_after = _get_device(conn, "b8:27:eb:12:34:56")
    assert device_after is not None
    assert device_after["online"] == 1


def test_port_opened_event(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Add extra port to .1
    host1 = next(h for h in hosts if h.ip == "192.168.1.1")
    extra_port = ScanPort(
        proto="tcp",
        port=8443,
        state="open",
        service="https-alt",
        product=None,
        version=None,
        extrainfo=None,
    )
    modified_ports = list(host1.ports) + [extra_port]
    modified_host = dataclasses.replace(host1, ports=modified_ports)
    modified_hosts = [modified_host if h is host1 else h for h in hosts]
    save_scan_results(conn, modified_hosts, "deep")
    events = _get_events(conn)
    port_opened_events = [e for e in events if e["kind"] == "port_opened"]
    assert len(port_opened_events) == 1
    assert port_opened_events[0]["detail"] == "tcp/8443 https-alt"


def test_os_changed_event(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Change os_name for .1
    host1 = next(h for h in hosts if h.ip == "192.168.1.1")
    modified_host = dataclasses.replace(host1, os_name="OpenWrt 21.02")
    modified_hosts = [modified_host if h is host1 else h for h in hosts]
    save_scan_results(conn, modified_hosts, "deep")
    events = _get_events(conn)
    os_changed_events = [e for e in events if e["kind"] == "os_changed"]
    assert len(os_changed_events) == 1
    assert os_changed_events[0]["detail"] == "Linux 4.15 - 5.8 -> OpenWrt 21.02"


def test_os_none_no_os_changed_event(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Rescan with os_name None for .1
    host1 = next(h for h in hosts if h.ip == "192.168.1.1")
    modified_host = dataclasses.replace(host1, os_name=None)
    modified_hosts = [modified_host if h is host1 else h for h in hosts]
    save_scan_results(conn, modified_hosts, "deep")
    events = _get_events(conn)
    os_changed_events = [e for e in events if e["kind"] == "os_changed"]
    assert len(os_changed_events) == 0


def test_device_type_classification(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Check device types
    device30 = _get_device(conn, "3c:2a:f4:00:00:09")
    assert device30 is not None
    assert device30["device_type"] == "printer"

    device1 = _get_device(conn, "c0:56:27:aa:bb:01")
    assert device1 is not None
    assert device1["device_type"] == "router"

    device20 = _get_device(conn, "b8:27:eb:12:34:56")
    assert device20 is not None
    assert device20["device_type"] == "server"


def test_type_override_preserved(conn: Any) -> None:
    hosts = _load_hosts()
    save_scan_results(conn, hosts, "deep")
    # Set type_override for .30
    device30 = _get_device(conn, "3c:2a:f4:00:00:09")
    assert device30 is not None
    conn.execute("UPDATE devices SET type_override = 'nas' WHERE id = ?", (device30["id"],))
    conn.commit()
    # Rescan
    save_scan_results(conn, hosts, "deep")
    device30_after = _get_device(conn, "3c:2a:f4:00:00:09")
    assert device30_after is not None
    assert device30_after["type_override"] == "nas"
    # device_type should still be recalculated (not affected by override)
    assert device30_after["device_type"] == "printer"


def test_extra_names_adds_device_names_row(conn: Any) -> None:
    hosts = _load_hosts()
    extra_names = {"192.168.1.30": [("office-printer", "mdns")]}
    save_scan_results(conn, hosts, "deep", extra_names=extra_names)
    device30 = _get_device(conn, "3c:2a:f4:00:00:09")
    assert device30 is not None
    names = _get_device_names(conn, device30["id"])
    mdns_names = [n for n in names if n["source"] == "mdns"]
    assert len(mdns_names) == 1
    assert mdns_names[0]["name"] == "office-printer"
    # hostname should be set to office-printer since no PTR exists
    assert device30["hostname"] == "office-printer"


def test_input_hosts_not_mutated_by_extra_names(conn: Any) -> None:
    hosts = _load_hosts()
    original_hosts = [dataclasses.replace(h) for h in hosts]
    extra_names = {"192.168.1.30": [("office-printer", "mdns")]}
    save_scan_results(conn, hosts, "deep", extra_names=extra_names)
    # Verify hosts list is not mutated
    for original, current in zip(original_hosts, hosts):
        assert original == current