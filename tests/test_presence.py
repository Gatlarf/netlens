import ipaddress
import sqlite3
from typing import Any

import pytest

from app.db import connect, init_db, get_or_create_device
from app.scanner.presence import mark_offline


def _create_device(conn: sqlite3.Connection, mac: str, ip: str, online: int = 1) -> int:
    device_id = get_or_create_device(conn, mac, ip)
    if device_id is None:
        raise ValueError("Device creation failed")
    conn.execute("UPDATE devices SET online = ? WHERE id = ?", (online, device_id))
    conn.commit()
    return device_id


def _get_device(conn: sqlite3.Connection, device_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise ValueError(f"Device {device_id} not found")
    return dict(row)


def _get_events(conn: sqlite3.Connection, device_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM events WHERE device_id = ? ORDER BY id",
        (device_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def test_unseen_device_inside_range_marked_offline():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24"])
    assert offline_ids == [device_id]
    device = _get_device(conn, device_id)
    assert device["online"] == 0
    events = _get_events(conn, device_id)
    assert len(events) == 1
    assert events[0]["kind"] == "device_offline"
    assert events[0]["detail"] == "192.168.1.10"
    assert events[0]["device_id"] == device_id
    conn.close()


def test_seen_device_stays_online():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    offline_ids = mark_offline(conn, {device_id}, ["192.168.1.0/24"])
    assert offline_ids == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    events = _get_events(conn, device_id)
    assert len(events) == 0
    conn.close()


def test_unseen_device_outside_every_range_stays_online():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "10.0.0.10")
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24"])
    assert offline_ids == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    events = _get_events(conn, device_id)
    assert len(events) == 0
    conn.close()


def test_already_offline_device_not_touched():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10", online=0)
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24"])
    assert offline_ids == []
    device = _get_device(conn, device_id)
    assert device["online"] == 0
    events = _get_events(conn, device_id)
    assert len(events) == 0
    conn.close()


def test_several_ranges_cover_devices_in_both():
    conn = connect(":memory:")
    init_db(conn)
    device1 = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    device2 = _create_device(conn, "aa:bb:cc:dd:ee:02", "10.0.0.10")
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24", "10.0.0.0/24"])
    assert offline_ids == [device1, device2]
    device1_row = _get_device(conn, device1)
    device2_row = _get_device(conn, device2)
    assert device1_row["online"] == 0
    assert device2_row["online"] == 0
    events1 = _get_events(conn, device1)
    events2 = _get_events(conn, device2)
    assert len(events1) == 1
    assert len(events2) == 1
    assert events1[0]["detail"] == "192.168.1.10"
    assert events2[0]["detail"] == "10.0.0.10"
    conn.close()


def test_returns_ascending_ids():
    conn = connect(":memory:")
    init_db(conn)
    device1 = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    device2 = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.20")
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24"])
    assert offline_ids == [device1, device2]
    assert offline_ids == sorted(offline_ids)
    conn.close()


def test_empty_ranges_returns_empty_and_changes_nothing():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    offline_ids = mark_offline(conn, set(), [])
    assert offline_ids == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    events = _get_events(conn, device_id)
    assert len(events) == 0
    conn.close()


def test_seen_ids_can_be_set_or_list():
    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    offline_ids_set = mark_offline(conn, {device_id}, ["192.168.1.0/24"])
    assert offline_ids_set == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    conn.close()

    conn = connect(":memory:")
    init_db(conn)
    device_id = _create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    offline_ids_list = mark_offline(conn, [device_id], ["192.168.1.0/24"])
    assert offline_ids_list == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    conn.close()


def test_device_with_null_primary_ip_is_skipped():
    conn = connect(":memory:")
    init_db(conn)
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:ff", "192.168.1.10")
    assert device_id is not None
    conn.execute("UPDATE devices SET primary_ip = NULL WHERE id = ?", (device_id,))
    conn.commit()
    offline_ids = mark_offline(conn, set(), ["192.168.1.0/24"])
    assert offline_ids == []
    device = _get_device(conn, device_id)
    assert device["online"] == 1
    events = _get_events(conn, device_id)
    assert len(events) == 0
    conn.close()