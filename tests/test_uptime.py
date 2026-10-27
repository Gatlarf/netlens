import pytest
from app.db import connect, init_db, get_or_create_device
from app.uptime import record_checks, uptime_percent, recent_checks, device_uptime, uptime_overview

NOW = "2026-03-10T12:00:00Z"


@pytest.fixture
def conn():
    c = connect(":memory:")
    init_db(c)
    yield c
    c.close()


def test_record_checks_basic(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11")
    c = get_or_create_device(conn, "aa:bb:cc:dd:ee:03", "10.9.9.9")

    inserted = record_checks(conn, {a}, ["192.168.1.0/24"], now=NOW)
    assert inserted == 2

    row_a = conn.execute("SELECT up FROM checks WHERE device_id = ?", (a,)).fetchone()
    row_b = conn.execute("SELECT up FROM checks WHERE device_id = ?", (b,)).fetchone()
    row_c = conn.execute("SELECT up FROM checks WHERE device_id = ?", (c,)).fetchone()

    assert row_a["up"] == 1
    assert row_b["up"] == 0
    assert row_c is None


def test_record_checks_empty_ranges(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    inserted = record_checks(conn, {a}, [], now=NOW)
    assert inserted == 1


def test_record_checks_rtt(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11")

    record_checks(conn, {a, b}, [], now=NOW, rtts={a: 1.5})

    row_a = conn.execute("SELECT rtt_ms FROM checks WHERE device_id = ?", (a,)).fetchone()
    row_b = conn.execute("SELECT rtt_ms FROM checks WHERE device_id = ?", (b,)).fetchone()

    assert row_a["rtt_ms"] == 1.5
    assert row_b["rtt_ms"] is None

    # Down device keeps rtt_ms None even if present in rtts
    record_checks(conn, {b}, [], now=NOW, rtts={b: 3.0})
    row_b2 = conn.execute("SELECT rtt_ms FROM checks WHERE device_id = ?", (b,)).fetchone()
    assert row_b2["rtt_ms"] is None


def test_record_checks_retention(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)", (a, "2025-01-01T00:00:00Z"))
    conn.commit()

    record_checks(conn, {a}, [], now=NOW, keep_days=90)

    count = conn.execute("SELECT COUNT(*) FROM checks WHERE ts < '2026-01-01'").fetchone()[0]
    assert count == 0


def test_uptime_percent(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11")

    for ts in ["2026-03-10T10:00:00Z", "2026-03-10T10:15:00Z", "2026-03-10T10:30:00Z"]:
        conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)", (a, ts))
    conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 0)", (a, "2026-03-10T10:45:00Z"))
    conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 0)", (a, "2026-03-01T00:00:00Z"))
    conn.commit()

    assert uptime_percent(conn, a, 1, now=NOW) == 75.0
    assert uptime_percent(conn, a, 30, now=NOW) == 60.0
    assert uptime_percent(conn, b, 1, now=NOW) is None


def test_recent_checks(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    for ts in ["2026-03-10T10:00:00Z", "2026-03-10T10:10:00Z", "2026-03-10T10:20:00Z",
               "2026-03-10T10:30:00Z", "2026-03-10T10:40:00Z"]:
        conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)", (a, ts))
    conn.commit()

    result = recent_checks(conn, a, limit=3)
    assert len(result) == 3
    assert result[0]["ts"] == "2026-03-10T10:20:00Z"
    assert result[1]["ts"] == "2026-03-10T10:30:00Z"
    assert result[2]["ts"] == "2026-03-10T10:40:00Z"
    assert all(isinstance(r["up"], bool) for r in result)


def test_device_uptime(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    checks = [
        ("2026-03-10T11:00:00Z", 1, 2.0),
        ("2026-03-10T11:10:00Z", 1, 2.0),
        ("2026-03-10T11:20:00Z", 0, None),
        ("2026-03-10T11:30:00Z", 0, None),
        ("2026-03-10T11:40:00Z", 0, None),
    ]
    for ts, up, rtt in checks:
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", (a, ts, up, rtt))
    conn.commit()

    result = device_uptime(conn, a, now=NOW)
    assert result["up_24h"] == 40.0
    assert result["status_for_seconds"] == 2400
    assert result["avg_rtt_ms"] == 2.0
    assert result["since"] == "2026-03-10T11:00:00Z"
    assert len(result["checks"]) == 5

    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11")
    result_b = device_uptime(conn, b, now=NOW)
    assert result_b["up_24h"] is None
    assert result_b["status_for_seconds"] is None
    assert result_b["checks"] == []


def test_uptime_overview(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11")
    c = get_or_create_device(conn, "aa:bb:cc:dd:ee:03", "192.168.1.12")

    conn.execute("UPDATE devices SET custom_name = 'Zebra' WHERE id = ?", (a,))
    conn.execute("UPDATE devices SET custom_name = 'Alpha' WHERE id = ?", (b,))
    conn.execute("UPDATE devices SET custom_name = 'Zzz' WHERE id = ?", (c,))
    conn.commit()

    for ts in ["2026-03-10T11:00:00Z", "2026-03-10T11:10:00Z", "2026-03-10T11:20:00Z"]:
        conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)", (a, ts))
    for ts in ["2026-03-10T11:00:00Z", "2026-03-10T11:10:00Z", "2026-03-10T11:20:00Z"]:
        conn.execute("INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)", (b, ts))
    conn.commit()

    result = uptime_overview(conn, bars=2, now=NOW)
    assert len(result) == 3
    assert result[0]["name"] == "Alpha"
    assert result[1]["name"] == "Zebra"
    assert result[2]["name"] == "Zzz"

    assert result[0]["bars"] == [1, 1]
    assert result[1]["bars"] == [1, 1]
    assert result[2]["bars"] == []
    assert result[2]["last_ts"] is None
    assert isinstance(result[0]["online"], bool)

def _history(conn, device, hours, step_minutes=60, down_at=()):
    from app.uptime import _format_ts, _parse_ts
    end = _parse_ts(NOW)
    n = int(hours * 60 / step_minutes)
    for i in range(n + 1):
        ts = _format_ts(end - __import__("datetime").timedelta(minutes=i * step_minutes))
        up = 0 if i in down_at else 1
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", (device, ts, up, None if not up else 10.0 + i))
    conn.commit()


def test_overview_with_a_range_gives_slices_with_time_and_response(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    _history(conn, a, 24, 60, down_at={5})
    row = uptime_overview(conn, bars=24, now=NOW, days=1)[0]
    bars = row["bars"]
    assert len(bars) == 24 and all("ts" in b for b in bars)             # the newest check lands in the last slice, not in a 25th
    assert sum(1 for b in bars if not b["up"]) == 1
    assert [b for b in bars if b["up"]][0]["rtt_ms"] is not None
    assert row["up_30d"] is not None and row["up_24h"] is not None


def test_a_slice_with_several_checks_says_how_many_and_how_many_failed(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    _history(conn, a, 24, 30, down_at={3})
    bars = uptime_overview(conn, bars=6, now=NOW, days=1)[0]["bars"]
    assert len(bars) == 6
    bad = [b for b in bars if not b["up"]]
    assert len(bad) == 1 and bad[0]["down"] == 1 and bad[0]["n"] == 9 and bad[0]["end"] > bad[0]["ts"]
    assert all(b["n"] == 8 for b in bars[1:5])      # the check made exactly now belongs to the newest slice


def test_device_uptime_over_30_days(conn):
    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    _history(conn, a, 24 * 30, 360)
    result = device_uptime(conn, a, now=NOW, limit=30, days=30)
    assert len(result["checks"]) == 30 and result["up_30d"] == 100.0 and result["avg_rtt_ms"] is not None
    assert device_uptime(conn, a, now=NOW, limit=5)["checks"][0]["up"] in (True, False)      # the original form is unchanged


def test_uptime_endpoint_ranges(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        assert c.get("/api/uptime?range=7d&bars=30").status_code == 200
        assert c.get("/api/uptime?range=6h&bars=30").status_code == 200            # 6 hours: a quarter of a day, still whole slices
        assert c.get("/api/uptime?range=1y").status_code == 422
        assert c.get("/api/uptime").status_code == 200


# ---- always-on (core) devices ----
def test_core_numbers_and_suggestions(conn):
    from app.stats import core_numbers
    from app.uptime import core_choices, set_core

    router = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    phone = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")
    conn.execute("UPDATE devices SET device_type = 'router' WHERE id = ?", (router,))
    conn.execute("UPDATE devices SET device_type = 'phone' WHERE id = ?", (phone,))
    _history(conn, router, 24 * 3, 60)
    _history(conn, phone, 24 * 3, 60, down_at=set(range(0, 40)))
    assert core_numbers(conn, NOW)["devices"] == 0 and core_numbers(conn, NOW)["uptime"]["24h"] is None
    choices = {c["id"]: c for c in core_choices(conn, NOW)}
    assert choices[router]["suggested"] is True and choices[phone]["suggested"] is False         # up all the time and a router
    assert set_core(conn, [router]) == 1
    core = core_numbers(conn, NOW)
    assert core["devices"] == 1 and core["uptime"]["24h"] == 100.0 and core["uptime"]["30d"] == 100.0     # the phone's gaps do not count
    assert uptime_overview(conn, now=NOW)[0]["always_on"] is True
    assert set_core(conn, []) == 0


def test_flapping_can_be_split_into_core_and_others(conn):
    from app.stats import flapping_devices

    a = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    b = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")
    for dev in (a, b):
        _history(conn, dev, 12, 30, down_at={1, 3, 5, 7, 9, 11, 13})
    conn.execute("UPDATE devices SET always_on = 1 WHERE id = ?", (a,))
    assert flapping_devices(conn, NOW) == 2 and flapping_devices(conn, NOW, True) == 1 and flapping_devices(conn, NOW, False) == 1


def test_core_api_and_viewer_rights(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import load_settings
    from app.main import create_app
    from tests.test_users import make, sign_in

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(tmp_path / "t.db")
        dev = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
        conn.commit()
        make(c, "vera", "viewer")
        vera = sign_in(app, "vera")
        assert vera.get("/api/uptime/core").status_code == 200
        assert vera.put("/api/uptime/core", json={"device_ids": [dev]}).status_code == 403
        assert c.put("/api/uptime/core", json={"device_ids": [dev]}).json() == {"count": 1}
        assert c.get("/api/uptime?range=24h").json()[0]["always_on"] is True
        assert c.get("/api/stats/summary").json()["core"]["devices"] == 1
        assert c.patch(f"/api/devices/{dev}", json={"always_on": False}).json()["always_on"] is False
        assert c.get("/api/uptime?range=24h").json()[0]["always_on"] is False
        assert c.patch(f"/api/devices/{dev}", json={"always_on": True}).json()["always_on"] is True


def test_latest_response_times_for_the_radar(tmp_path):
    from datetime import datetime, timedelta, timezone

    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect, init_db
    from app.main import create_app

    db = tmp_path / "l.db"
    conn = connect(db)
    init_db(conn)
    now = datetime.now(timezone.utc)
    stamp = lambda minutes: (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for i, ip in ((1, "10.0.0.1"), (2, "10.0.0.2"), (3, "10.0.0.3")):
        conn.execute("INSERT INTO devices (id, primary_ip, mac, online, first_seen, last_seen) VALUES (?, ?, ?, 1, ?, ?)", (i, ip, f"aa:00:00:00:00:0{i}", stamp(900), stamp(1)))
    for minutes, rtt in ((5, 10.0), (3, 20.0), (1, 30.0)):                      # device 1: answers, the last three average 20 ms
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, 1, ?)", (stamp(minutes), rtt))
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (2, ?, 1, 5.0)", (stamp(4),))
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (2, ?, 0, NULL)", (stamp(1),))     # device 2: its latest check failed
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (3, ?, 1, 9.0)", (stamp(120),))    # device 3: nothing recent
    conn.commit()
    conn.close()
    client = TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers={"Authorization": "Bearer secret"})
    got = {d["id"]: d for d in client.get("/api/uptime/latest").json()}
    assert set(got) == {1, 2} and got[1]["rtt_ms"] == 20.0 and got[1]["up"] is True
    assert got[2]["up"] is False and got[2]["rtt_ms"] is None


def test_six_hour_range_has_its_own_percentage_and_slices(tmp_path):
    from app.db import connect, init_db

    conn = connect(tmp_path / "t.db")
    init_db(conn)
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.1', 'a', 1, 'x', 'x')")
    conn.commit()
    rows = overview_for_six_hours(conn)
    assert rows[0]["up_6h"] is None or 0 <= rows[0]["up_6h"] <= 100
    assert "up_24h" in rows[0] and isinstance(rows[0]["bars"], list)


def overview_for_six_hours(conn):
    from app.uptime import RANGES, uptime_overview

    assert RANGES["6h"] == 0.25
    return uptime_overview(conn, bars=12, days=RANGES["6h"])
