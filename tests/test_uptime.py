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