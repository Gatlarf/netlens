import re
import sqlite3
import pytest
from app.db import connect, init_db, utcnow, get_or_create_device, add_event, list_devices, SCHEMA_VERSION


def test_init_db_creates_tables():
    conn = connect(":memory:")
    init_db(conn)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = {row[0] for row in cursor.fetchall()}
    expected = {"devices", "device_ips", "device_names", "ports", "scans", "events", "relations", "settings", "host_keys", "schema_version", "checks", "hypervisor_guests", "ignored_devices", "stats_daily", "wifi_samples", "service_checks", "service_results", "port_baselines"}
    assert expected == tables


def test_init_db_idempotent():
    conn = connect(":memory:")
    init_db(conn)
    init_db(conn)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = {row[0] for row in cursor.fetchall()}
    expected = {"devices", "device_ips", "device_names", "ports", "scans", "events", "relations", "settings", "host_keys", "schema_version", "checks", "hypervisor_guests", "ignored_devices", "stats_daily", "wifi_samples", "service_checks", "service_results", "port_baselines"}
    assert expected == tables


def test_schema_version():
    conn = connect(":memory:")
    init_db(conn)
    cursor = conn.execute("SELECT version FROM schema_version")
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == SCHEMA_VERSION


def test_get_or_create_device_mac_normalization():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    id1 = get_or_create_device(conn, "AA-BB-CC-DD-EE-FF", "192.168.1.1", now)
    id2 = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    assert id1 == id2


def test_get_or_create_device_same_mac_new_ip():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    id1 = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    id2 = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.2", now)
    assert id1 == id2
    cursor = conn.execute("SELECT primary_ip FROM devices WHERE id=?", (id1,))
    row = cursor.fetchone()
    assert row[0] == "192.168.1.2"
    cursor = conn.execute("SELECT ip FROM device_ips WHERE device_id=? ORDER BY ip", (id1,))
    ips = [row[0] for row in cursor.fetchall()]
    assert len(ips) == 2
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips


def test_get_or_create_device_no_mac_same_ip():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    id1 = get_or_create_device(conn, None, "192.168.1.1", now)
    id2 = get_or_create_device(conn, None, "192.168.1.1", now)
    assert id1 == id2


def test_get_or_create_device_no_mac_different_ip():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    id1 = get_or_create_device(conn, None, "192.168.1.1", now)
    id2 = get_or_create_device(conn, None, "192.168.1.2", now)
    assert id1 != id2


def test_get_or_create_device_no_mac_vs_mac_same_ip():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    id1 = get_or_create_device(conn, None, "192.168.1.1", now)
    id2 = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    assert id1 != id2


def test_get_or_create_device_online_and_last_seen():
    conn = connect(":memory:")
    init_db(conn)
    now1 = utcnow()
    id1 = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now1)
    cursor = conn.execute("SELECT online, last_seen, first_seen FROM devices WHERE id=?", (id1,))
    row = cursor.fetchone()
    assert row[0] == 1
    assert row[1] == now1
    assert row[2] == now1

    now2 = "2024-01-01T00:00:00Z"
    get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now2)
    cursor = conn.execute("SELECT online, last_seen, first_seen FROM devices WHERE id=?", (id1,))
    row = cursor.fetchone()
    assert row[0] == 1
    assert row[1] == now2
    assert row[2] == now1


def test_add_event():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    event_id = add_event(conn, "scan", "found device", device_id)
    assert event_id is not None
    cursor = conn.execute("SELECT kind, detail, device_id FROM events WHERE id=?", (event_id,))
    row = cursor.fetchone()
    assert row[0] == "scan"
    assert row[1] == "found device"
    assert row[2] == device_id


def test_delete_device_nulls_events():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    event_id = add_event(conn, "scan", "found device", device_id)
    conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
    conn.commit()
    cursor = conn.execute("SELECT device_id FROM events WHERE id=?", (event_id,))
    row = cursor.fetchone()
    assert row[0] is None


def test_delete_device_cascades_device_ips():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)", (device_id, "192.168.1.2", now, now))
    conn.commit()
    conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
    conn.commit()
    cursor = conn.execute("SELECT COUNT(*) FROM device_ips WHERE device_id=?", (device_id,))
    count = cursor.fetchone()[0]
    assert count == 0


def test_utcnow_format():
    ts = utcnow()
    pattern = r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"
    assert re.match(pattern, ts)


def test_list_devices_returns_dicts():
    conn = connect(":memory:")
    init_db(conn)
    now = utcnow()
    get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.1", now)
    devices = list_devices(conn)
    assert isinstance(devices, list)
    assert len(devices) >= 1
    assert isinstance(devices[0], dict)


def test_foreign_key_enforcement():
    conn = connect(":memory:")
    init_db(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO ports (device_id, port) VALUES (?, ?)", (9999, 80))