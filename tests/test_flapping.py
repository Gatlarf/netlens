import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import actions, flapping
from app.config import load_settings
from app.db import init_db
from app.main import create_app

NOW = datetime(2026, 10, 9, 20, 0, 0, tzinfo=timezone.utc)


def stamp(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    for i, ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"), start=1):
        c.execute("INSERT INTO devices (id, primary_ip, mac, device_type, first_seen, last_seen, online) VALUES (?, ?, ?, ?, 'x', 'x', 1)", (i, ip, f"02:00:00:00:00:0{i}", "switch" if i == 1 else "pc"))
    c.commit()
    return c


def history(conn, device_id, pattern, step=10, rtt=2.0):
    """pattern: a string of U (up) and D (down), oldest first, one check every `step` minutes."""
    n = len(pattern)
    for i, ch in enumerate(pattern):
        up = ch == "U"
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", (device_id, stamp((n - i) * step), 1 if up else 0, rtt if up else None))
    conn.commit()


FLAP = "UUDUUUDDUUUDUUUUDUUUUUDDDUUUUUUDUUUUUDUU"


def behind(conn, child=2, parent=1):
    conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'uplink', 'plugin:x', 1.0, 0)", (child, parent))
    conn.commit()


def titles(report):
    return [f["title"] for f in report["findings"]]


def test_not_enough_history(conn):
    history(conn, 1, "UUDU")
    assert titles(flapping.analyze(conn, 1, now=stamp(0))) == ["Not enough history yet"]


def test_a_stable_device_is_not_flapping(conn):
    history(conn, 1, "U" * 40)
    r = flapping.analyze(conn, 1, now=stamp(0))
    assert titles(r) == ["Not flapping"] and r["outages"] == 0


def test_devices_behind_stayed_up_means_it_just_does_not_answer(conn):
    history(conn, 1, FLAP)
    history(conn, 2, "U" * len(FLAP))
    behind(conn)
    r = flapping.analyze(conn, 1, now=stamp(0))
    assert "It is probably running; it just does not answer Netlens" in titles(r)
    assert r["behind_stayed_up_percent"] == 100 and r["devices_behind"] == 1
    assert "Common with managed switches and access points" in titles(r)


def test_devices_behind_going_down_together_is_a_real_outage(conn):
    history(conn, 1, FLAP)
    history(conn, 2, FLAP)
    behind(conn)
    assert "The devices behind it go down with it" in titles(flapping.analyze(conn, 1, now=stamp(0)))


def test_without_known_children_it_says_how_to_find_out(conn):
    history(conn, 1, FLAP)
    assert "Netlens does not know what is behind it" in titles(flapping.analyze(conn, 1, now=stamp(0)))


def test_everything_missed_at_once_is_a_scan_problem(conn):
    for d in range(1, 7):
        history(conn, d, FLAP)
    r = flapping.analyze(conn, 1, now=stamp(0))
    assert "Other devices were missed at the same moments" in titles(r) and r["network_wide_percent"] == 100


def test_only_this_device_affected(conn):
    history(conn, 1, FLAP)
    for d in range(2, 7):
        history(conn, d, "U" * len(FLAP))
    assert "Only this device is affected" in titles(flapping.analyze(conn, 1, now=stamp(0)))


def test_single_scan_gaps_and_periodicity(conn):
    pattern = ("U" * 5 + "D") * 8   # a gap every 6 checks = 60 minutes
    history(conn, 1, pattern)
    r = flapping.analyze(conn, 1, now=stamp(0))
    assert "Most gaps last a single scan" in titles(r)
    assert r["period_seconds"] == 3600 and any(t.startswith("It drops about every") for t in titles(r))


def test_gaps_in_one_time_window(conn):
    # checks every 60 minutes for 5 days; down only between 02:00 and 05:00 UTC
    rows = []
    start = NOW - timedelta(days=5)
    t = start
    while t < NOW:
        down = 2 <= t.hour < 5
        rows.append((1, t.strftime("%Y-%m-%dT%H:%M:%SZ"), 0 if down else 1, None if down else 2.0))
        t += timedelta(hours=1)
    conn.executemany("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", rows)
    conn.commit()
    r = flapping.analyze(conn, 1, now=stamp(0))
    assert any(t.startswith("Mostly between 02:00 and 06:00") or t.startswith("Mostly between 01:00") for t in titles(r)), titles(r)
    shifted = flapping.analyze(conn, 1, now=stamp(0), tz_minutes=120)
    assert any("04:00" in t or "03:00" in t for t in titles(shifted)), titles(shifted)


def test_slow_before_it_drops(conn):
    rows = []
    for i in range(60):
        down = i % 6 == 5
        pre = i % 6 == 4
        rows.append((1, stamp((60 - i) * 10), 0 if down else 1, None if down else (60.0 if pre else 2.0)))
    conn.executemany("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", rows)
    conn.commit()
    assert "It slows down before it drops" in titles(flapping.analyze(conn, 1, now=stamp(0)))


def test_outage_durations(conn):
    history(conn, 1, "UUDDDUUUUUUU", step=10)
    runs = flapping.outages(conn.execute("SELECT ts, up FROM checks ORDER BY ts").fetchall())
    assert runs[0]["checks"] == 3 and runs[0]["seconds"] == 1800


XML_UP = '<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/><address addr="10.0.0.1" addrtype="ipv4"/><times srtt="2000"/></host></nmaprun>'
XML_DOWN = '<?xml version="1.0"?><nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>'


def test_probe_counts_answers_per_method():
    calls = {"n": 0}

    async def runner(args):
        if "-PR" in args:
            calls["n"] += 1
            return XML_UP if calls["n"] % 2 else XML_DOWN     # ARP answered every other time
        return XML_DOWN

    result = asyncio.run(flapping.probe("10.0.0.1", rounds=6, pause=0, runner=runner))
    assert result["scan"] == {"up": False, "seconds": result["scan"]["seconds"]}
    arp = next(m for m in result["methods"] if m["method"] == "ARP")
    assert arp["answered"] == 3 and arp["asked"] == 6 and arp["rtt_ms"] == 2.0
    assert any(f["title"].startswith("ARP: answered 3 of 6") and f["level"] == "warn" for f in result["findings"])


def test_probe_says_when_a_scan_of_just_this_device_sees_it():
    async def runner(args):
        return XML_UP if "-PR" in args or "--top-ports" in args else XML_DOWN

    result = asyncio.run(flapping.probe("10.0.0.1", rounds=3, pause=0, runner=runner))
    assert result["scan"]["up"] is True
    assert any(f["title"].startswith("A scan aimed only at this device sees it") for f in result["findings"])


def test_probe_with_no_answer_and_bad_input():
    async def silent(args):
        return XML_DOWN

    result = asyncio.run(flapping.probe("10.0.0.1", rounds=3, pause=0, runner=silent))
    assert result["findings"][0]["title"] == "It did not answer at all now"
    for bad in (None, "", "fe80::1", "not-an-ip"):
        with pytest.raises(actions.ActionError):
            asyncio.run(flapping.probe(bad))


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "a.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer t"}) as c:
        c.path = path
        c.app_ = app
        yield c


def test_api(client):
    c = sqlite3.connect(client.path)
    c.row_factory = sqlite3.Row
    c.execute("INSERT INTO devices (id, primary_ip, mac, first_seen, last_seen, online) VALUES (7, '10.0.0.7', '02:00:00:00:00:07', 'x', 'x', 1)")
    c.commit()
    c.close()
    assert client.get("/api/devices/7/flapping").json()["findings"][0]["title"] == "Not enough history yet"
    assert client.get("/api/devices/999/flapping").status_code == 404

    async def runner(args):
        return XML_UP

    client.app_.state.action_runner = runner
    client.app_.state.flapping_pause = 0
    r = client.post("/api/devices/7/flapping/probe")
    assert r.status_code == 200 and r.json()["methods"][0]["answered"] == 8
    assert client.post("/api/devices/999/flapping/probe").status_code == 404
