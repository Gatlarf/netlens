"""Beats: a quick ping of every device between two scans."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app import beats, checkstats
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

RANGES = ["10.0.0.0/24"]
T0 = "2026-10-24T12:00:00Z"


def stamp(minute):
    return f"2026-10-24T12:{minute:02d}:00Z"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "b.db")
    init_db(c)
    for ip, online in (("10.0.0.5", 1), ("10.0.0.6", 1), ("192.168.9.9", 1)):          # the last one is outside the scanned range
        c.execute("INSERT INTO devices (primary_ip, mac, online, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)", (ip, f"aa:bb:cc:00:00:{ip[-1]}{ip[-1]}", online, T0, T0))
    c.execute("UPDATE devices SET always_on = 1")
    c.commit()
    return c


def online(conn, ip):
    return conn.execute("SELECT online FROM devices WHERE primary_ip = ?", (ip,)).fetchone()[0]


def test_only_always_on_devices_in_the_scanned_ranges_are_asked_unless_all_is_chosen(conn):
    assert [r["primary_ip"] for r in beats.targets(conn, T0, RANGES)] == ["10.0.0.5", "10.0.0.6"]
    assert beats.targets(conn, T0, []) == []
    conn.execute("UPDATE devices SET always_on = 0 WHERE primary_ip = '10.0.0.6'")
    assert [r["primary_ip"] for r in beats.targets(conn, T0, RANGES)] == ["10.0.0.5"]            # a phone that sleeps is left to the scans
    beats.save_settings(conn, which="all")
    assert [r["primary_ip"] for r in beats.targets(conn, T0, RANGES)] == ["10.0.0.5", "10.0.0.6"]


def test_a_device_is_offline_after_three_missed_beats_and_back_at_the_first_answer(conn):
    beats._misses.clear()
    answers = {"10.0.0.6": 1.5}
    for minute in (1, 2):
        beats.record(conn, answers, RANGES, stamp(minute))
        assert online(conn, "10.0.0.5") == 1                                   # one or two lost answers are not an outage
    result = beats.record(conn, answers, RANGES, stamp(3))
    assert online(conn, "10.0.0.5") == 0 and len(result["offline"]) == 1
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_offline'").fetchone()[0] == 1
    beats.record(conn, {"10.0.0.5": 2.0, "10.0.0.6": 1.5}, RANGES, stamp(4))
    assert online(conn, "10.0.0.5") == 1
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_online'").fetchone()[0] == 1


def test_beats_are_recorded_as_checks_and_counted_in_the_roll_up(conn):
    beats._misses.clear()
    beats.record(conn, {"10.0.0.5": 2.5}, RANGES, stamp(1))
    rows = conn.execute("SELECT device_id, up, rtt_ms, beat FROM checks ORDER BY device_id").fetchall()
    assert [(r["up"], r["beat"]) for r in rows] == [(1, 1), (0, 1)] and rows[0]["rtt_ms"] == 2.5
    totals = checkstats.totals(conn, "2026-10-24T00:00:00Z")
    assert sorted((u, n) for u, n, _a, _b in totals.values()) == [(0, 1), (1, 1)]


def test_the_rows_of_beats_are_pruned_but_their_count_stays(conn):
    beats._misses.clear()
    beats.record(conn, {"10.0.0.5": 1.0, "10.0.0.6": 1.0}, RANGES, stamp(1))
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms, beat) VALUES (1, '2026-10-20T00:00:00Z', 1, 1, 0)")      # a scan row is never pruned here
    assert beats.prune(conn, "2026-10-30T00:00:00Z") == 2
    assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 1
    assert sum(n for _u, n, _a, _b in checkstats.totals(conn, "2026-10-24T00:00:00Z").values()) == 2


def test_run_once_uses_nmap_and_skips_when_nothing_answers(tmp_path):
    db = tmp_path / "r.db"
    c = connect(db)
    init_db(c)
    c.execute("INSERT INTO devices (primary_ip, mac, online, always_on, first_seen, last_seen) VALUES ('10.0.0.5', 'aa:bb:cc:00:00:05', 1, 1, ?, ?)", (T0, T0))
    c.execute("INSERT INTO devices (primary_ip, mac, online, always_on, first_seen, last_seen) VALUES ('10.0.0.6', 'aa:bb:cc:00:00:06', 1, 1, ?, ?)", (T0, T0))
    c.commit()
    c.close()
    xml = '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><times srtt="1500"/></host></nmaprun>'

    async def answers(args):
        return xml

    async def silence(args):
        return '<nmaprun></nmaprun>'

    beats._misses.clear()
    result = asyncio.run(beats.run_once(str(db), RANGES, runner=answers, now=T0))
    assert result["checked"] == 2 and result["answered"] == 1
    assert asyncio.run(beats.run_once(str(db), RANGES, runner=silence, now=T0)) is None           # nobody answered: the beat is dropped, not "all down"


def test_settings_roundtrip_through_the_api(tmp_path):
    db = tmp_path / "s.db"
    c = connect(db)
    init_db(c)
    c.close()
    client = TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers={"Authorization": "Bearer secret"})
    cfg = client.get("/api/config").json()
    assert cfg["presence_interval"] == 60 and cfg["presence_misses"] == 3 and cfg["presence_scope"] == "core"
    assert client.put("/api/config/general", json={"presence_interval": 30, "presence_misses": 2}).json()["presence_interval"] == 30
    assert client.put("/api/config/general", json={"presence_interval": 0}).json()["presence_interval"] == 0
    assert client.put("/api/config/general", json={"presence_interval": 5}).status_code == 422
    assert client.put("/api/config/general", json={"presence_misses": 99}).status_code == 422


def test_service_bars_are_slices_with_the_number_of_failed_checks(tmp_path):
    from datetime import datetime, timedelta, timezone

    from app.api import services as api

    db = tmp_path / "v.db"
    c = connect(db)
    init_db(c)
    c.execute("INSERT INTO service_checks (name, kind, host, port, interval_s, timeout_s, enabled, created) VALUES ('web', 'tcp', 'h', 80, 60, 5, 1, ?)", (T0,))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(30):                                               # 30 checks in the last 30 minutes: 3 of them failed
        ts = (now - timedelta(minutes=i + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c.execute("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (1, ?, ?, 5, '')", (ts, 0 if i in (3, 4, 20) else 1))
    c.commit()
    items = api.slices(c, 1, 1, 2)                                    # the last hour in two bars of 30 minutes
    assert sum(i.get("n", 1) for i in items) == 30 and sum(i.get("down", 0) for i in items) == 3
    assert all(not i["up"] for i in items if i.get("down"))


def _row(conn, did, minute, up, beat):
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms, beat) VALUES (?, ?, ?, NULL, ?)", (did, stamp(minute), up, beat))


def test_a_single_lost_quick_check_is_no_outage_but_three_in_a_row_are(conn):
    from app import flapping

    for m, up in enumerate([1, 0, 1, 1, 0, 0, 0, 1, 1]):                # one lost answer, then three in a row
        _row(conn, 1, m, up, 1)
    rows = conn.execute("SELECT ts, up, beat FROM checks WHERE device_id = 1 ORDER BY ts").fetchall()
    runs = flapping.outages(rows, 3)
    assert len(runs) == 1 and runs[0]["start"] == stamp(4) and runs[0]["checks"] == 3 and runs[0]["seconds"] == 180
    assert len(flapping.outages(rows, 1)) == 2                           # without the debounce both count


def test_a_missed_scan_counts_at_once(conn):
    from app import flapping

    _row(conn, 1, 0, 1, 0)
    _row(conn, 1, 15, 0, 0)
    _row(conn, 1, 30, 1, 0)
    rows = conn.execute("SELECT ts, up, beat FROM checks WHERE device_id = 1 ORDER BY ts").fetchall()
    assert len(flapping.outages(rows, 3)) == 1


def test_flapping_counts_outages_not_lost_packets_for_devices_with_quick_checks(conn):
    from app import stats

    for m in range(40):                                                  # device 1: a lost answer every 5 minutes, never three in a row
        _row(conn, 1, m, 0 if m % 5 == 4 else 1, 1)
    for m in range(40):                                                  # device 2: down for 3 minutes, up, three times
        _row(conn, 2, m, 0 if m % 10 in (3, 4, 5) else 1, 1)
    conn.commit()
    flaps = stats._flaps(conn, "2026-10-24T11:00:00Z")
    assert 1 not in flaps and flaps[2] == 8                              # 4 outages (minutes 3-5, 13-15, 23-25, 33-35), each down and up again


def test_events_carry_the_importance_and_critical_problems_lead_the_attention_list(conn):
    from app import dashboard
    from app.db import add_event

    conn.execute("UPDATE devices SET tier = 'critical' WHERE primary_ip = '10.0.0.5'")
    conn.execute("UPDATE devices SET tier = 'low' WHERE primary_ip = '10.0.0.6'")
    conn.commit()
    ids = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices")}
    add_event(conn, "device_offline", "x", device_id=ids["10.0.0.5"], now=T0)
    add_event(conn, "device_offline", "y", device_id=ids["10.0.0.6"], now=T0)
    assert [r[0] for r in conn.execute("SELECT tier FROM events ORDER BY id")] == ["critical", "low"]
    tiers = dashboard._tiers(conn)
    assert tiers == {f"device:{ids['10.0.0.5']}": "critical", f"device:{ids['10.0.0.6']}": "low"}


def test_reliability_pairs_outages_and_reports_recovery_time_and_alert_quality(conn):
    from app import reliability
    from app.db import add_event

    did = conn.execute("SELECT id FROM devices WHERE primary_ip = '10.0.0.5'").fetchone()[0]
    for kind, minute in (("device_offline", 1), ("device_online", 3), ("device_offline", 10), ("device_online", 40)):    # 2 min and 30 min
        add_event(conn, kind, "x", device_id=did, now=stamp(minute))
    add_event(conn, "device_offline", "x", device_id=did, now=stamp(50))                                               # still down
    doc = reliability.build(conn, 7, now="2026-10-24T13:00:00Z")
    d = doc["devices"]
    assert d["outages"] == 3 and d["ongoing"] == 1 and d["longest_seconds"] == 1800
    assert doc["mttr_seconds"] == (120 + 1800) // 2 and doc["alerts"]["cleared_within_5_min"] == 1
    assert doc["alerts"]["problems"] == 3 and doc["watching"]["devices"] == 3 and doc["meets_target"] in (True, False)
    assert reliability.set_target(conn, 99.9) == 99.9 and reliability.target(conn) == 99.9
