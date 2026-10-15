import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import reports, tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 1, ?, ?)",
              (stamp(NOW - timedelta(days=40)), stamp(NOW)))
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (2, 'aa:00:00:00:00:02', '10.0.0.6', 'phone', 0, ?, ?)",
              (stamp(NOW - timedelta(days=2)), stamp(NOW)))
    # nas: checked every hour for ten days, down for 3 hours
    t = NOW - timedelta(days=10)
    while t <= NOW:
        down = NOW - timedelta(days=3, hours=3) <= t < NOW - timedelta(days=3)
        c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, ?, 1.0)", (stamp(t), 0 if down else 1))
        t += timedelta(hours=1)
    c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (2, ?, 1, 1.0)", (stamp(NOW - timedelta(hours=1)),))
    c.execute("INSERT INTO service_checks (id, name, kind, host, port, interval_s, timeout_s, enabled, created) VALUES (1, 'Website', 'http', 'example.org', 443, 60, 5, 1, 'x')")
    for i, up in enumerate([1, 1, 0, 0, 1, 1, 1, 1]):
        c.execute("INSERT INTO service_results (check_id, ts, up, ms) VALUES (1, ?, ?, 20.0)", (stamp(NOW - timedelta(hours=8 - i)), up))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def test_month_bounds():
    s, e = reports.month_bounds("2026-12")
    assert (s.year, s.month, e.year, e.month) == (2026, 12, 2027, 1)
    for bad in ("2026-13", "26-01", "2026/01", "abcd-ef", ""):
        with pytest.raises(ValueError):
            reports.month_bounds(bad)


def test_duration_text():
    assert reports.duration(30) == "30 s"
    assert reports.duration(3 * 3600) == "3 h"
    assert reports.duration(95 * 60) == "1 h 35 min"
    assert reports.duration(3 * 86400) == "3.0 days"


def test_availability_counts_outages(conn):
    r = reports.availability(conn, NOW - timedelta(days=10, hours=1), NOW + timedelta(hours=1))
    nas = next(d for d in r["devices"] if d["id"] == 1)
    assert nas["outages"] == 1 and nas["down_seconds"] == 3 * 3600
    assert 98 < nas["availability"] < 99 and nas["always_on"] is True
    assert r["summary"]["core_devices"] == 1 and r["summary"]["with_outages"] == 2
    web = r["services"][0]
    assert web["outages"] == 1 and web["availability"] == 75.0 and web["avg_ms"] == 20.0


def test_csv_neutralises_formulas(conn):
    conn.execute("UPDATE devices SET custom_name = '=HYPERLINK(\"x\")' WHERE id = 2")
    conn.commit()
    r = reports.availability(conn, NOW - timedelta(days=10), NOW + timedelta(hours=1))
    text = reports.availability_csv(r)
    assert "'=HYPERLINK" in text and text.count("\r\n") == 1 + len(r["devices"]) + len(r["services"])


def test_weekly_text(conn):
    w = reports.weekly(conn, NOW)
    title, text = reports.weekly_text(w)
    assert "Netlens weekly report" in title
    assert "1 of 2 devices are online" in text
    assert "phone" in text            # first seen two days ago
    assert "Website (service)" in text


def test_schedule(conn):
    assert reports.due(conn, NOW) is False                      # off by default
    reports.save_settings(conn, {"enabled": True, "day": NOW.astimezone().weekday(), "hour": 0})
    assert reports.due(conn, NOW) is True
    reports.mark_sent(conn, NOW)
    assert reports.due(conn, NOW + timedelta(hours=1)) is False
    assert reports.due(conn, NOW + timedelta(days=7, hours=1)) is True
    with pytest.raises(ValueError):
        reports.save_settings(conn, {"hour": 25})


def test_send_goes_only_to_subscribed_channels(conn):
    from app.notify import channels as ch

    sent = []

    def poster(url, data, headers, timeout=15.0):
        sent.append((url, data))
        return 200, "ok"

    chans = [
        {"id": "a", "type": "ntfy", "name": "A", "enabled": True, "events": ["report_weekly"], "settings": {"server": "https://ntfy.example", "topic": "t"}, "last_event_id": 1},
        {"id": "b", "type": "ntfy", "name": "B", "enabled": True, "events": ["device_offline"], "settings": {"server": "https://ntfy.example", "topic": "u"}, "last_event_id": 1},
    ]
    ch.save_channels(conn, chans)
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    result = asyncio.run(reports.send_weekly(path, force=True, poster=poster))
    assert result["sent"] == 1 and result["failed"] == 0 and len(sent) == 1 and sent[0][0].endswith("/t")


def test_api(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        r = tc.get("/api/reports/availability?month=2026-09")
        assert r.status_code == 200 and r.json()["month"] == "2026-09" and r.json()["devices"] == []
        assert tc.get("/api/reports/availability?month=nope").status_code == 422
        assert tc.get("/api/reports/availability.csv").headers["content-type"].startswith("text/csv")
        w = tc.get("/api/reports/weekly").json()
        assert w["settings"]["enabled"] is False and "text" in w
        assert tc.put("/api/reports/weekly/settings", json={"enabled": True, "day": 2, "hour": 7}).json()["settings"] == {"enabled": True, "day": 2, "hour": 7}
        assert tc.put("/api/reports/weekly/settings", json={"hour": 30}).status_code == 422
        assert tc.post("/api/reports/weekly/send").status_code == 409
    tsdb.forget_all()
