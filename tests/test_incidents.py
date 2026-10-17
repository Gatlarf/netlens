from datetime import datetime, timezone

import pytest

from app import incidents, insights, licence
from app.db import add_event, connect, init_db

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    c = connect(tmp_path / "i.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    for i, (name, ip) in enumerate([("sw-garden", "192.168.1.2"), ("cam1", "192.168.1.31"), ("cam2", "192.168.1.32"), ("nas", "192.168.1.20")], 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')", (i, f"aa:bb:cc:dd:ee:0{i}", ip, name))
    c.commit()
    yield c
    c.close()


def ev(conn, kind, minute, device_id, detail="x"):
    return add_event(conn, kind, detail, device_id=device_id, now=f"2026-11-01T10:{minute:02d}:00Z")


def test_events_that_follow_each_other_are_one_incident_and_a_recovery_closes_it(conn):
    ev(conn, "device_offline", 0, 1)
    ev(conn, "device_offline", 1, 2)
    ev(conn, "device_offline", 2, 3)
    ev(conn, "device_online", 40, 1)               # the recovery comes much later and still belongs to the incident
    ev(conn, "device_online", 41, 2)
    ev(conn, "device_online", 41, 3)
    ev(conn, "service_down", 55, 4)                # an hour later, another device: another incident
    found = incidents.incidents(conn, 7, NOW)
    assert len(found) == 2
    later, first = found
    assert first["device_count"] == 3 and first["resolved"] is True and "lasted 41 minutes" in first["summary"]
    assert later["resolved"] is False and later["ongoing"] is True and "may still be going on" in later["summary"]


def test_the_device_above_the_others_is_the_probable_cause(conn, monkeypatch):
    from app import hierarchy

    ev(conn, "device_offline", 0, 1)
    ev(conn, "device_offline", 1, 2)
    devices, _ = hierarchy.load_hierarchy(conn)
    monkeypatch.setattr(incidents, "load_hierarchy", lambda c: (devices, {2: hierarchy.Parent(1, "manual", "test")}))
    found = incidents.incidents(conn, 7, NOW)
    assert found[0]["cause"]["name"] == "sw-garden" and "Probable cause: sw-garden" in found[0]["summary"]


def test_maintenance_and_old_events_are_left_out(conn):
    ev(conn, "device_offline", 0, 1)
    assert incidents.incidents(conn, 0, NOW) == []


def test_the_model_only_rewords_and_a_failure_keeps_the_plain_text(conn):
    ev(conn, "device_offline", 0, 4, "nas offline")
    item = incidents.incidents(conn, 7, NOW)[0]
    text = incidents.narrate(conn, item, ask=lambda m: "The nas dropped off the network.")
    assert text == "The nas dropped off the network."
    assert "192.168" not in str(incidents.narrate.__doc__)

    def broken(messages):
        raise RuntimeError("down")

    assert incidents.narrate(conn, item, ask=broken) is None
