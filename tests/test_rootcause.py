import pytest

from app import rootcause
from app.db import connect, init_db

NOW = "2026-03-10T12:00:00Z"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    # router(1) <- switch(2) <- nas(3), cam(4); router(1) <- ap(5)
    for i, (name, online) in enumerate([("router", 1), ("sw-garden", 0), ("nas", 0), ("cam", 0), ("ap", 0)], start=1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (i, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}", name, online, NOW, NOW))
    for src, dst in [(2, 1), (3, 2), (4, 2), (5, 1)]:
        c.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?,?,?,?,?,0)", (src, dst, "uplink", "plugin:snmp", 1.0))
    c.commit()
    return c


def event(i, kind, device):
    return {"id": i, "ts": NOW, "kind": kind, "device_id": device, "detail": None, "maintenance": None, "name": f"d{device}", "ip": None, "mac": None, "vendor": None, "trusted": 1, "notify_offline": 1}


def test_devices_behind_an_offline_switch_are_grouped(conn):
    events = [event(1, "device_offline", 2), event(2, "device_offline", 3), event(3, "device_offline", 4), event(4, "device_offline", 5)]
    out = rootcause.collapse(conn, events)
    kinds = [(e["kind"], e["device_id"]) for e in out]
    assert ("device_offline", 2) in kinds and ("device_offline", 5) in kinds        # the switch and the access point are causes themselves
    assert ("device_offline", 3) not in kinds and ("device_offline", 4) not in kinds
    summary = next(e for e in out if e["kind"] == "unreachable")
    assert summary["device_id"] == 2 and "sw-garden is offline" in summary["text"] and "2 devices" in summary["text"] and "cam" in summary["text"]


def test_a_device_with_an_online_parent_is_its_own_cause(conn):
    conn.execute("UPDATE devices SET online = 1 WHERE id = 2")
    conn.commit()
    out = rootcause.collapse(conn, [event(1, "device_offline", 3)])
    assert [e["kind"] for e in out] == ["device_offline"]


def test_other_events_pass_through(conn):
    events = [event(1, "device_new", 3), event(2, "service_down", 3)]
    out = rootcause.collapse(conn, events)
    assert [e["kind"] for e in out] == ["device_new", "unreachable"]


def test_topmost_offline_device_is_the_cause(conn):
    conn.execute("UPDATE devices SET online = 0 WHERE id = 1")      # the router is down as well
    conn.commit()
    out = rootcause.collapse(conn, [event(1, "device_offline", 1), event(2, "device_offline", 2), event(3, "device_offline", 3)])
    assert [(e["kind"], e["device_id"]) for e in out] == [("device_offline", 1), ("unreachable", 1)]
    assert "2 devices" in out[1]["text"]


async def test_channels_send_one_message(tmp_path):
    import json

    from app.notify import channels as ch

    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    for i, (name, online) in enumerate([("router", 1), ("sw-garden", 0), ("nas", 0)], start=1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                  (i, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}", name, online, NOW, NOW))
    for src, dst in [(2, 1), (3, 2)]:
        c.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?,?,?,?,?,0)", (src, dst, "uplink", "plugin:snmp", 1.0))
    c.commit()
    channel = {"id": "c1", "type": "webhook", "name": "hook", "enabled": True, "events": ["device_offline"], "settings": {"url": "http://example.invalid/h"}, "last_event_id": 0}
    ch.save_channels(c, [channel])
    from app.db import add_event

    add_event(c, "device_offline", None, device_id=2, now=NOW)
    add_event(c, "device_offline", None, device_id=3, now=NOW)
    c.close()
    sent = []

    def poster(url, data, headers, timeout=15.0):
        sent.append(json.loads(data))
        return 200, "ok"

    result = await ch.process_channels(str(path), poster=poster)
    assert result["sent"] == 1 and len(sent) == 1
    assert "behind it" in sent[0]["message"] and sent[0]["message"].count("\n") == 1
