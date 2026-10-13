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
        assert c.get("/api/uptime?range=1y").status_code == 422
        assert c.get("/api/uptime").status_code == 200
