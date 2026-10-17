import json
import random

import pytest

from app import anomaly, insights, licence, tsdb
from app.db import connect, init_db

NOW = 1_800_000_000 - (1_800_000_000 % 86400) + 3 * 86400 + 14 * 3600      # a weekday-ish afternoon, exactly on the hour
HOUR = 3600


def normal_day_points(base_by_hour, days=14, noise=2.0, seed=1):
    rnd = random.Random(seed)
    pts = []
    t = NOW - days * 86400
    while t < NOW - HOUR:
        pts.append([t, base_by_hour(anomaly._hour_class(t)[0]) + rnd.uniform(-noise, noise), None, None])
        t += 2100
    return pts


def test_a_reading_far_outside_the_usual_for_that_hour_is_unusual():
    pts = normal_day_points(lambda h: 60.0 if 9 <= h < 18 else 10.0)
    assert anomaly.judge(pts, 12.0, NOW, 25.0)["unusual"] is False             # the working-hours level is 60: 12 is low, not high
    assert anomaly.judge(pts, 62.0, NOW, 25.0)["unusual"] is False
    night = NOW + 10 * HOUR                                                    # 00:00: normally about 10
    assert anomaly.judge(pts, 70.0, night, 25.0)["unusual"] is True
    assert anomaly.judge(pts, 18.0, night, 25.0)["unusual"] is False           # a small change is not an anomaly however still the device is


def test_too_little_history_says_nothing():
    pts = normal_day_points(lambda h: 10.0, days=3)
    assert anomaly.judge(pts, 99.0, NOW, 25.0) is None


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "a.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def feed(conn, level_now):
    store = tsdb.for_conn(conn)
    rnd = random.Random(3)
    t = NOW - 14 * 86400
    while t <= NOW - 1500:
        store.record([("device", 1, "cpu_pct", 8.0 + rnd.uniform(-2, 2), "", "%")], ts=int(t))
        t += 1800
    for k in range(5):
        store.record([("device", 1, "cpu_pct", level_now, "", "%")], ts=int(NOW - 1200 + k * 240))


def test_a_busy_night_is_announced_after_two_rounds_and_only_once(conn):
    feed(conn, 85.0)
    found = anomaly.scan(conn, NOW)
    assert found and found[0]["metric"] == "cpu_pct" and found[0]["name"] == "nas" and "unusual for this time of day" in anomaly.describe(found[0])
    assert anomaly.check(conn, NOW) == []                                      # the first round only notes it
    assert len(anomaly.check(conn, NOW + 900)) == 1                            # the second announces it
    assert anomaly.check(conn, NOW + 1800) == []                               # and then it keeps quiet for six hours
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM events")]
    assert kinds == ["anomaly"]


def test_a_normal_reading_raises_nothing(conn):
    feed(conn, 9.0)
    assert anomaly.scan(conn, NOW) == [] and anomaly.check(conn, NOW) == [] and anomaly.check(conn, NOW + 900) == []
