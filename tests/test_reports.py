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
        assert tc.put("/api/reports/weekly/settings", json={"enabled": True, "day": 2, "hour": 7}).json()["settings"] == {**reports.DEFAULTS, "enabled": True, "day": 2, "hour": 7}
        assert tc.put("/api/reports/weekly/settings", json={"hour": 30}).status_code == 422
        assert tc.post("/api/reports/weekly/send").status_code == 409
    tsdb.forget_all()


# ------------------------------------------------------------------ what the reports cover
SPAN = (NOW - timedelta(days=10, hours=1), NOW + timedelta(hours=1))


def test_the_report_can_be_limited_to_the_always_on_devices(conn):
    everything = reports.availability(conn, *SPAN)
    core = reports.availability(conn, *SPAN, scope="core")
    assert {d["id"] for d in everything["devices"]} == {1, 2} and {d["id"] for d in core["devices"]} == {1}
    assert core["summary"]["devices"] == 1 and core["summary"]["scope"] == "core" and core["services"] == everything["services"]


def test_services_can_be_left_out(conn):
    r = reports.availability(conn, *SPAN, with_services=False)
    assert r["services"] == [] and r["summary"]["services"] == 0 and r["summary"]["services_availability"] is None and len(r["devices"]) == 2


def test_one_group_only(conn):
    conn.execute("INSERT INTO device_groups (id, name, color) VALUES (1, 'Servers', '#fff')")
    conn.execute("UPDATE devices SET group_id = 1 WHERE id = 2")
    conn.commit()
    assert [d["id"] for d in reports.availability(conn, *SPAN, group_id=1)["devices"]] == [2]


def test_only_what_had_an_outage_and_a_target(conn):
    r = reports.availability(conn, *SPAN, only_outages=True, target=99.5)
    assert [d["id"] for d in r["devices"]] == [1] and [s["name"] for s in r["services"]] == ["Website"]
    assert r["summary"]["devices"] == 2                          # the summary still counts what was selected, not what is listed
    assert r["summary"]["with_outages"] == 2 and r["summary"]["target"] == 99.5
    full = reports.availability(conn, *SPAN, target=99.5)
    flags = {("d", d["id"]): d["below_target"] for d in full["devices"]} | {("s", s["id"]): s["below_target"] for s in full["services"]}
    assert flags == {("d", 1): True, ("d", 2): False, ("s", 1): True} and full["summary"]["below_target"] == 2
    assert "Below target" in reports.availability_csv(full).splitlines()[0] and "Below target" not in reports.availability_csv(reports.availability(conn, *SPAN)).splitlines()[0]


def test_weekly_settings_scope_and_sections(conn):
    assert reports.get_settings(conn)["scope"] == "all" and all(reports.get_settings(conn)[k] for k in reports.SECTIONS)
    out = reports.save_settings(conn, {"scope": "core", "services": False, "new_devices": False})
    assert out["scope"] == "core" and out["services"] is False and out["new_devices"] is False and out["health"] is True
    for bad in ({"scope": "nope"}, {"services": "yes"}):
        with pytest.raises(ValueError):
            reports.save_settings(conn, bad)
    assert reports.get_settings(conn)["scope"] == "core"


def test_the_weekly_report_follows_its_settings(conn):
    everything = reports.weekly(conn, NOW, {"scope": "all"})
    core = reports.weekly(conn, NOW, {"scope": "core", "services": False, "new_devices": False})
    assert everything["devices"]["total"] == 2 and core["devices"]["total"] == 1 and core["devices"]["online"] == 1
    assert everything["devices"]["new_count"] == 1 and core["devices"]["new_count"] == 0
    assert core["worst_services"] == [] and everything["worst_services"] != []
    title, text = reports.weekly_text(core)
    assert "1 of 1 always-on devices are online now." in text and "new device" not in text and "(service)" not in text and "Service checks" not in text
    _, full_text = reports.weekly_text(everything)
    assert "1 of 2 devices are online now." in full_text and "1 new device(s) appeared" in full_text and "(service)" in full_text


def test_always_on_scope_limits_health_and_disks_too(conn):
    from app.hostmetrics import service as hm

    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (1, 1, 'ssh', 'a', 22, 'x'), (2, 2, 'ssh', 'b', 22, 'x')")
    for mon in (1, 2):
        conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value, pending, pending_n) VALUES (?, 'cpu_pct', '', 'warning', 'x', 95, NULL, 0)", (mon,))
    conn.commit()
    assert {p["device"] for p in reports.weekly(conn, NOW, {"scope": "all"})["problems"]} == {"nas", "phone"}
    assert {p["device"] for p in reports.weekly(conn, NOW, {"scope": "core"})["problems"]} == {"nas"}
    assert reports.weekly(conn, NOW, {"health": False})["problems"] == []


def test_api_filters_and_weekly_options(tmp_path, conn):
    path = tmp_path / "t.db"
    conn.commit()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=conn.execute("PRAGMA database_list").fetchone()[2])
    with TestClient(app, headers=AUTH) as tc:
        month = NOW.strftime("%Y-%m")
        full = tc.get(f"/api/reports/availability?month={month}").json()
        core = tc.get(f"/api/reports/availability?month={month}&scope=core&services=false&target=99").json()
        assert len(full["devices"]) == 2 and len(core["devices"]) == 1 and core["services"] == [] and core["summary"]["target"] == 99 and "groups" in core
        assert tc.get(f"/api/reports/availability?month={month}&scope=weird").status_code == 422
        assert tc.get(f"/api/reports/availability?month={month}&target=500").status_code == 422
        csv = tc.get(f"/api/reports/availability.csv?month={month}&scope=core&services=false")
        assert csv.status_code == 200 and "Service" not in csv.text.replace("Type", "")
        saved = tc.put("/api/reports/weekly/settings", json={"scope": "core", "health": False}).json()["settings"]
        assert saved["scope"] == "core" and saved["health"] is False
        assert tc.put("/api/reports/weekly/settings", json={"scope": "x"}).status_code == 422
        assert tc.get("/api/reports/weekly").json()["data"]["options"]["scope"] == "core"


# ------------------------------------------------------------------ left out, business hours, maintenance, item count, monthly mail
@pytest.fixture
def utc(monkeypatch):
    import time

    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def test_a_device_can_be_left_out_of_the_reports(conn):
    conn.execute("UPDATE devices SET report_exclude = 1 WHERE id = 2")
    conn.commit()
    assert [d["id"] for d in reports.availability(conn, *SPAN)["devices"]] == [1]
    week = reports.weekly(conn, NOW, {})
    assert week["devices"]["total"] == 1 and week["devices"]["new_count"] == 0                      # phone (id 2) is neither counted nor named as new


def test_the_device_form_can_set_the_flag(tmp_path, conn):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=conn.execute("PRAGMA database_list").fetchone()[2])
    with TestClient(app, headers=AUTH) as tc:
        assert tc.get("/api/devices/2").json()["report_exclude"] is False
        assert tc.patch("/api/devices/2", json={"report_exclude": True}).json()["report_exclude"] is True
        month = NOW.strftime("%Y-%m")
        assert [d["id"] for d in tc.get(f"/api/reports/availability?month={month}").json()["devices"]] == [1]


def test_business_hours_count_only_those_hours(conn, utc):
    business = {"business_days": [0, 1, 2, 3, 4], "business_start": 8, "business_end": 18}
    during = reports.availability(conn, *SPAN, hours="business", business=business)
    nas = next(d for d in during["devices"] if d["id"] == 1)
    assert nas["outages"] == 1 and nas["checks"] < 240 and during["summary"]["hours"] == "business"        # the outage was Monday 09:00-12:00
    evenings = reports.availability(conn, *SPAN, hours="business", business={**business, "business_start": 13, "business_end": 18})
    assert next(d for d in evenings["devices"] if d["id"] == 1)["outages"] == 0
    weekend = reports.availability(conn, *SPAN, hours="business", business={**business, "business_days": [5, 6]})
    assert next(d for d in weekend["devices"] if d["id"] == 1)["outages"] == 0
    assert next(d for d in reports.availability(conn, *SPAN)["devices"] if d["id"] == 1)["outages"] == 1


def test_business_spans_follow_the_servers_clock(utc):
    spans = reports.business_spans(datetime(2026, 10, 12, 0, 0, tzinfo=timezone.utc), datetime(2026, 10, 14, 0, 0, tzinfo=timezone.utc), reports.DEFAULTS)
    assert spans.contains("2026-10-12T09:00:00Z") and not spans.contains("2026-10-12T07:59:59Z") and not spans.contains("2026-10-12T18:00:00Z") and spans.contains("2026-10-13T17:59:59Z")
    assert not spans.contains("2026-10-17T10:00:00Z")                                                         # a Saturday


def test_planned_maintenance_can_be_left_out(conn):
    from app import maintenance

    window = maintenance.clean_window({"name": "Updates", "scope": {"all": True}, "schedule": {"type": "once", "start": "2026-10-12T08:30:00Z", "end": "2026-10-12T12:30:00Z"}})
    maintenance.save_windows(conn, [window])
    normal = next(d for d in reports.availability(conn, *SPAN)["devices"] if d["id"] == 1)
    quiet = reports.availability(conn, *SPAN, ignore_maintenance=True)
    nas = next(d for d in quiet["devices"] if d["id"] == 1)
    assert normal["outages"] == 1 and nas["outages"] == 0 and nas["availability"] == 100.0 and nas["checks"] < normal["checks"] and quiet["summary"]["ignore_maintenance"] is True
    weekly = maintenance.clean_window({"name": "Nights", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [0], "start": "08:30", "end": "12:30"}, "tz": "UTC"})
    maintenance.save_windows(conn, [weekly])
    assert next(d for d in reports.availability(conn, *SPAN, ignore_maintenance=True)["devices"] if d["id"] == 1)["outages"] == 0        # every Monday 08:30-12:30


def test_the_number_of_listed_items_is_a_setting(conn):
    for i in range(3, 9):
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, 'x', 'x')", (i, f"aa:00:00:00:00:{i:02x}", f"10.0.1.{i}", f"d{i}"))
        for k, up in enumerate([1, 0, 1]):
            conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, 1.0)", (i, stamp(NOW - timedelta(hours=5 - k)), up))
    conn.commit()
    assert len(reports.weekly(conn, NOW, {"max_items": 3})["worst_devices"]) == 3
    assert len(reports.weekly(conn, NOW, {"max_items": 10})["worst_devices"]) == 7
    reports.save_settings(conn, {"max_items": 4})
    assert len(reports.weekly(conn, NOW)["worst_devices"]) == 4
    for bad in (0, 31, "5", True):
        with pytest.raises(ValueError):
            reports.save_settings(conn, {"max_items": bad})


def test_settings_for_hours_and_the_monthly_report_are_checked(conn):
    out = reports.save_settings(conn, {"hours": "business", "business_days": [4, 0, 0], "business_start": 9, "business_end": 17, "monthly": True, "monthly_day": 3, "monthly_target": 99.9})
    assert out["business_days"] == [0, 4] and out["monthly"] and out["monthly_target"] == 99.9
    assert reports.save_settings(conn, {"monthly_target": None})["monthly_target"] is None
    for bad in ({"hours": "night"}, {"business_days": []}, {"business_days": [7]}, {"business_end": 25}, {"monthly_day": 29}, {"monthly_target": 120}, {"nope": 1}, {"business_start": 18}):
        with pytest.raises(ValueError):
            reports.save_settings(conn, bad)
    assert reports.get_settings(conn)["business_start"] == 9


def test_the_monthly_report_text_and_schedule(conn, utc):
    reports.save_settings(conn, {"monthly": True, "monthly_day": 2, "monthly_hour": 8, "monthly_target": 99.5, "ignore_maintenance": True})
    data = reports.monthly(conn, "2026-10", now=NOW)
    title, text = reports.monthly_text(data)
    assert title == "Netlens availability report for October 2026" and "were reachable" in text and "Target 99.5%" in text and "time in planned maintenance windows is left out" in text
    assert "nas" in text and "Below the 99.5% target" in text
    assert reports.previous_month(NOW) == "2026-09"
    assert reports.monthly(conn, now=NOW)["month"] == "2026-09"
    assert not reports.monthly_due(conn, datetime(2026, 11, 1, 23, 0, tzinfo=timezone.utc))               # not yet the 2nd
    assert reports.monthly_due(conn, datetime(2026, 11, 2, 8, 0, tzinfo=timezone.utc))
    from app.db import set_setting

    set_setting(conn, reports.MONTHLY_KEY, "2026-10")
    assert not reports.monthly_due(conn, datetime(2026, 11, 5, 8, 0, tzinfo=timezone.utc)) and reports.monthly_due(conn, datetime(2026, 12, 2, 9, 0, tzinfo=timezone.utc))
    reports.save_settings(conn, {"monthly": False})
    assert not reports.monthly_due(conn, datetime(2026, 12, 20, 9, 0, tzinfo=timezone.utc))


def test_the_monthly_report_is_sent_to_the_channels_that_ask_for_it(conn, tmp_path):
    from app.notify import channels as ch

    sent = []
    channel = {"id": "a", "name": "ntfy", "type": "ntfy", "enabled": True, "events": ["report_monthly"], "topic": "t"}
    other = {"id": "b", "name": "other", "type": "ntfy", "enabled": True, "events": ["report_weekly"], "topic": "t"}
    orig_load, orig_send = ch.load_channels, ch.send_channel
    ch.load_channels = lambda c: [channel, other]
    ch.send_channel = lambda c, title, body, attachments=(), **kw: sent.append((c["name"], title, body))
    try:
        result = asyncio.run(reports.send_monthly(conn.execute("PRAGMA database_list").fetchone()[2], force=True))
    finally:
        ch.load_channels, ch.send_channel = orig_load, orig_send
    assert result["sent"] == 1 and result["channels"] == 1 and [s[0] for s in sent] == ["ntfy"] and "availability report" in sent[0][1]
    assert "report_monthly" in ch.EVENT_LABELS


def test_api_monthly_and_new_report_settings(tmp_path, conn):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=conn.execute("PRAGMA database_list").fetchone()[2])
    with TestClient(app, headers=AUTH) as tc:
        month = NOW.strftime("%Y-%m")
        saved = tc.put("/api/reports/weekly/settings", json={"hours": "business", "business_days": [0, 1], "monthly": True, "monthly_target": 99}).json()["settings"]
        assert saved["hours"] == "business" and saved["business_days"] == [0, 1] and saved["monthly"] is True
        assert tc.put("/api/reports/weekly/settings", json={"max_items": 99}).status_code == 422
        rep = tc.get(f"/api/reports/availability?month={month}").json()
        assert rep["summary"]["hours"] == "business" and rep["business"]["business_days"] == [0, 1]       # the saved choice is the default
        assert tc.get(f"/api/reports/availability?month={month}&hours=all&ignore_maintenance=true").json()["summary"]["hours"] == "all"
        assert tc.get(f"/api/reports/availability?month={month}&hours=night").status_code == 422
        body = tc.get("/api/reports/monthly").json()
        assert body["title"].startswith("Netlens availability report for") and body["settings"]["monthly"] is True
        assert tc.post("/api/reports/monthly/send").status_code == 409                                      # no channel asks for it yet
