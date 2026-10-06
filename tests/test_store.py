from pathlib import Path
from datetime import datetime
from dataclasses import replace

import pytest

from app.db import connect, init_db
from app.scanner.nmap_parser import parse_nmap_xml, ScanHost, ScanPort
from app.scanner.store import save_scan_results


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "deep.xml"


@pytest.fixture
def conn():
    conn = connect(":memory:")
    init_db(conn)
    yield conn
    conn.close()


@pytest.fixture
def hosts():
    return parse_nmap_xml(FIXTURE_PATH.read_text(encoding='utf-8'))


def test_first_save_new_counts(conn, hosts):
    result = save_scan_results(conn, hosts, kind="deep")
    assert result["new"] == 4
    assert result["updated"] == 0
    assert len(result["device_ids"]) == 4


def test_devices_table_has_four_rows(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 4


def test_second_identical_save_updates(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    result = save_scan_results(conn, hosts, kind="deep")
    assert result["new"] == 0
    assert result["updated"] == 4
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 4


def test_hostname_ptr_preferred_for_scanbox(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    row = conn.execute(
        "SELECT hostname FROM devices WHERE primary_ip = '192.168.1.50'"
    ).fetchone()
    assert row[0] == "scanbox.lan"


def test_hostname_none_for_no_names(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    row = conn.execute(
        "SELECT hostname FROM devices WHERE primary_ip = '192.168.1.30'"
    ).fetchone()
    assert row[0] is None


def test_vendor_and_os_stored_for_first_host(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    row = conn.execute(
        "SELECT vendor, os_name, os_confidence FROM devices WHERE primary_ip = '192.168.1.1'"
    ).fetchone()
    assert row[0] == "Belkin International"
    assert row[1] == "Linux 4.15 - 5.8"
    assert row[2] == 96


def test_ports_rows_count(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    count = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
    assert count == 9


def test_device_names_two_rows_for_scanbox(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    device_id = conn.execute(
        "SELECT id FROM devices WHERE primary_ip = '192.168.1.50'"
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT source FROM device_names WHERE device_id = ?",
        (device_id,),
    ).fetchall()
    sources = {r[0] for r in rows}
    assert sources == {"user", "ptr"}
    assert len(rows) == 2


def test_quick_save_does_not_delete_existing_ports(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    device_id = conn.execute(
        "SELECT id FROM devices WHERE primary_ip = '192.168.1.1'"
    ).fetchone()[0]

    original_host = next(h for h in hosts if h.ip == "192.168.1.1")
    reduced_host = replace(
        original_host,
        ports=[
            ScanPort(proto='tcp', port=22, state='open', service=None, product=None, version=None, extrainfo=None),
            ScanPort(proto='tcp', port=80, state='open', service=None, product=None, version=None, extrainfo=None),
        ]
    )
    save_scan_results(conn, [reduced_host], kind="quick")

    ports = conn.execute(
        "SELECT port FROM ports WHERE device_id = ? ORDER BY port",
        (device_id,),
    ).fetchall()
    assert {p[0] for p in ports} == {22, 53, 80, 443}


def test_deep_save_deletes_missing_ports(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    device_id = conn.execute(
        "SELECT id FROM devices WHERE primary_ip = '192.168.1.1'"
    ).fetchone()[0]

    original_host = next(h for h in hosts if h.ip == "192.168.1.1")
    reduced_host = replace(
        original_host,
        ports=[
            ScanPort(proto='tcp', port=22, state='open', service=None, product=None, version=None, extrainfo=None),
            ScanPort(proto='tcp', port=80, state='open', service=None, product=None, version=None, extrainfo=None),
        ]
    )
    save_scan_results(conn, [reduced_host], kind="deep")

    ports = conn.execute(
        "SELECT port FROM ports WHERE device_id = ? ORDER BY port",
        (device_id,),
    ).fetchall()
    assert {p[0] for p in ports} == {22, 80}


def test_no_os_info_does_not_erase_stored_os(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    device_id = conn.execute(
        "SELECT id FROM devices WHERE primary_ip = '192.168.1.1'"
    ).fetchone()[0]

    original_host = next(h for h in hosts if h.ip == "192.168.1.1")
    reduced_host = replace(
        original_host,
        ports=[]
    )
    save_scan_results(conn, [reduced_host], kind="quick")

    row = conn.execute(
        "SELECT os_name FROM devices WHERE id = ?",
        (device_id,),
    ).fetchone()
    assert row[0] == "Linux 4.15 - 5.8"


def test_invalid_kind_raises_value_error(conn, hosts):
    with pytest.raises(ValueError):
        save_scan_results(conn, hosts, kind="invalid")


def test_custom_name_survives_rescan(conn, hosts):
    save_scan_results(conn, hosts, kind="deep")
    device_id = conn.execute(
        "SELECT id FROM devices WHERE primary_ip = '192.168.1.1'"
    ).fetchone()[0]
    conn.execute(
        "UPDATE devices SET custom_name = 'My Router' WHERE id = ?",
        (device_id,),
    )
    conn.commit()

    save_scan_results(conn, hosts, kind="deep")

    row = conn.execute(
        "SELECT custom_name FROM devices WHERE id = ?",
        (device_id,),
    ).fetchone()
    assert row[0] == "My Router"