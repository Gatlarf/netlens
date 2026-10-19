import random
from datetime import datetime, timedelta, timezone

import pytest

from app import checkstats, reports, stats, tsdb, uptime
from app.db import connect, init_db

NOW = datetime(2026, 10, 15, 12, 20, 30, tzinfo=timezone.utc)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_totals(conn, since):
    return {r[0]: (r[1], r[2], r[3], r[4]) for r in conn.execute(
        "SELECT device_id, SUM(up), COUNT(*), COALESCE(SUM(rtt_ms), 0), COUNT(rtt_ms) FROM checks WHERE ts >= ? GROUP BY device_id", (since,))}


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    rnd = random.Random(3)
    for d in range(1, 9):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
                  (d, f"aa:00:00:00:00:{d:02x}", f"10.0.0.{d}", f"dev{d}", d % 2, stamp(NOW - timedelta(days=60)), stamp(NOW)))
    # a check every 7 minutes for 40 days; device 1 never fails, 2 is down for a few days, 3 flaps, the rest fail now and then; some checks have no response time
    t = NOW - timedelta(days=40)
    while t <= NOW:
        for d in range(1, 9):
            if d == 1:
                up = 1
            elif d == 2:
                up = 0 if NOW - timedelta(days=9) <= t < NOW - timedelta(days=6, hours=5) else 1
            elif d == 3:
                up = 1 if (int(t.timestamp()) // 420) % 3 else 0
            else:
                up = 0 if rnd.random() < 0.01 * d else 1
            c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", (d, stamp(t), up, rnd.random() * 9 if up and rnd.random() < 0.9 else None))
        t += timedelta(minutes=7, seconds=rnd.randint(0, 40))
    c.commit()
    yield c
    c.close()


@pytest.mark.parametrize("since", ["2026-10-15T12:00:00Z", "2026-10-15T07:13:44Z", "2026-10-08T12:20:30Z", "2026-09-15T12:20:30Z", "2026-09-01T00:00:00Z"])
@pytest.mark.parametrize("core", [None, True, False])
def test_totals_equal_the_raw_rows(conn, since, core):
    got = checkstats.totals(conn, since, core)
    want = raw_totals(conn, since)
    if core is not None:
        keep = {r[0] for r in conn.execute("SELECT id FROM devices WHERE always_on = ?", (1 if core else 0,))}
        want = {d: v for d, v in want.items() if d in keep}
    assert got.keys() == want.keys()
    for d in want:
        assert got[d][:2] == want[d][:2] and got[d][2] == pytest.approx(want[d][2]) and got[d][3] == want[d][3]


def test_rolling_up_is_incremental_and_follows_late_rows(conn):
    assert checkstats.current(conn)
    before = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, 0, 2.0)", (stamp(NOW - timedelta(days=20)),))     # written out of order
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, 1, 3.0)", (stamp(NOW + timedelta(minutes=5)),))
    conn.commit()
    assert checkstats.fold(conn) == 2
    since = stamp(NOW - timedelta(days=25))
    assert checkstats.totals(conn, since)[1][:2] == raw_totals(conn, since)[1][:2]
    assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == before + 2
    assert checkstats.fold(conn) == 0


def test_a_big_gap_falls_back_to_the_raw_rows_and_backfill_catches_up(conn, monkeypatch):
    conn.execute("DELETE FROM checks_hourly")
    conn.execute("DELETE FROM settings WHERE key = ?", (checkstats.KEY,))
    conn.commit()
    monkeypatch.setattr(checkstats, "INLINE_LIMIT", 10)
    since = stamp(NOW - timedelta(days=5))
    assert checkstats.current(conn) is False
    assert checkstats.totals(conn, since)[2][:2] == raw_totals(conn, since)[2][:2]          # still right, the slow way
    monkeypatch.setattr(checkstats, "CHUNK", 20000)
    assert checkstats.backfill(conn) > 0 and checkstats.current(conn) is True
    assert conn.execute("SELECT SUM(n) FROM checks_hourly").fetchone()[0] == conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]


def test_a_table_that_was_emptied_starts_over(conn):
    conn.execute("DELETE FROM checks")
    conn.commit()
    assert checkstats.current(conn) is True
    assert conn.execute("SELECT COUNT(*) FROM checks_hourly").fetchone()[0] == 0


def test_deleting_a_device_removes_its_roll_up(conn):
    conn.execute("DELETE FROM devices WHERE id = 3")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM checks_hourly WHERE device_id = 3").fetchone()[0] == 0


def test_uptime_overview_and_statistics_match_the_raw_numbers(conn):
    now = stamp(NOW)
    rows = {r["id"]: r for r in uptime.uptime_overview(conn, now=now)}
    for d, days in ((1, 1), (2, 7), (3, 30)):
        since = stamp(NOW - timedelta(days=days))
        u, n = raw_totals(conn, since)[d][:2]
        key = {1: "up_24h", 2: "up_7d", 3: "up_30d"}[d]
        assert rows[d][key] == round(u / n * 100, 2)
    s = stats._availability(conn, now)
    u, n = conn.execute("SELECT SUM(up), COUNT(*) FROM checks WHERE ts >= ?", (stamp(NOW - timedelta(days=7)),)).fetchone()
    assert s["uptime_7d"] == pytest.approx(u / n * 100, abs=0.01)
    assert [r["id"] for r in s["least_reliable"]][0] in (2, 3)                       # the device that was down for days or flaps
    assert s["flapping_total"] >= 1 and s["flapping"][0]["id"] == 3


def test_the_monthly_report_is_the_same_with_and_without_the_roll_up(conn, monkeypatch):
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    end = datetime(2026, 10, 1, tzinfo=timezone.utc)
    fast = reports.availability(conn, start, end, with_services=False)
    monkeypatch.setattr(checkstats, "range_totals", lambda *a, **k: None)
    slow = reports.availability(conn, start, end, with_services=False)
    assert fast["devices"] == slow["devices"] and fast["devices"]
    assert any(d["outages"] for d in fast["devices"]) and any(d["outages"] == 0 for d in fast["devices"])


def test_a_slightly_old_answer_is_served_at_once_and_refreshed_in_the_background(monkeypatch):
    import threading
    import types

    from app.api import stats as api_stats

    clock = [1000.0]
    monkeypatch.setattr(api_stats.time, "monotonic", lambda: clock[0])
    request = types.SimpleNamespace(app=types.SimpleNamespace(state=types.SimpleNamespace()))
    calls = []
    done = threading.Event()

    def build():
        calls.append(1)
        done.set()
        return f"answer {len(calls)}"

    assert api_stats._cached(request, ("k",), build) == "answer 1"
    clock[0] += 10
    assert api_stats._cached(request, ("k",), build) == "answer 1" and len(calls) == 1            # fresh: from the cache
    clock[0] += 60                                                                              # 70 s: stale but usable
    done.clear()
    assert api_stats._cached(request, ("k",), build) == "answer 1"                              # shown at once ...
    assert done.wait(3)
    for _ in range(100):
        if request.app.state.stats_cache[("k",)][1] == "answer 2":
            break
        threading.Event().wait(0.02)
    assert request.app.state.stats_cache[("k",)][1] == "answer 2"                               # ... and refreshed behind it
    clock[0] += 500                                                                             # too old: computed now
    assert api_stats._cached(request, ("k",), build) == "answer 3"
