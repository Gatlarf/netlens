import time

import pytest
from fastapi.testclient import TestClient

from app import forecast, tsdb
from app.backup import create_backup, restore_backup
from app.config import load_settings
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
NOW = 1_800_000_000
DAY = 86400


def points(start_value, per_day, days, now=NOW, step=3600):
    n = days * 86400 // step
    return [[now - (n - i) * step, start_value + per_day * (i * step / 86400), None, None] for i in range(n + 1)]


def test_a_rising_disk_gets_a_date():
    pts = points(50, 1.0, 20)
    out = forecast.estimate(pts, pts[-1][1], NOW)
    assert out["trend"] == "growing"
    assert 29 < out["days_to_full"] < 31                      # 70% now, 1 point per day
    assert out["full_on"]


def test_a_steady_disk_gets_none():
    pts = points(40, 0.0, 20)
    out = forecast.estimate(pts, 40, NOW)
    assert out["trend"] == "steady" and out["days_to_full"] is None


def test_a_shrinking_disk():
    pts = points(80, -1.0, 10)
    assert forecast.estimate(pts, 70, NOW)["trend"] == "shrinking"


def test_too_little_history_gives_no_estimate():
    pts = points(50, 5.0, 1)
    out = forecast.estimate(pts, 55, NOW)
    assert out["trend"] == "unknown" and out["days_to_full"] is None


def test_one_big_file_does_not_make_a_trend():
    pts = points(40, 0.0, 20)
    for p in pts[-3:]:
        p[1] += 20                                            # the last three hours: a large download
    out = forecast.estimate(pts, pts[-1][1], NOW)
    assert out["days_to_full"] is None or out["days_to_full"] > 90


def test_a_year_away_is_not_reported():
    pts = points(40, 0.05, 20)
    assert forecast.estimate(pts, 41, NOW)["days_to_full"] is None


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (1,'snmp','10.0.0.5',161,'',60,'[]',1,1,'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def feed(conn, per_day, days=10, start=70.0, now=None):
    now = now or int(time.time())
    store = tsdb.for_conn(conn)
    rows = [("device", 1, "disk_pct", start + per_day * ((t - (now - days * DAY)) / DAY), "/data", "%") for t in range(now - days * DAY, now + 1, 3600)]
    for r, t in zip(rows, range(now - days * DAY, now + 1, 3600)):
        store.record([r], ts=t)
    store.rollup(now)
    return now


def test_check_raises_once_and_forgets_when_it_recovers(conn):
    now = feed(conn, per_day=1.5, days=10, start=60)          # 75% now, full in about 17 days: outside the 14
    assert forecast.check(conn, now) == []
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('forecast.alert_days', '30')")
    assert forecast.check(conn, now) == ["capacity_warning"]
    assert forecast.check(conn, now) == []                    # not again
    ev = conn.execute("SELECT kind, detail FROM events WHERE kind LIKE 'capacity_%'").fetchall()
    assert len(ev) == 1 and "/data" in ev[0]["detail"] and "nas" in ev[0]["detail"]


def test_critical_when_days_are_few(conn):
    now = feed(conn, per_day=3.0, days=10, start=62)          # 92% now: full in under 3 days
    assert forecast.check(conn, now) == ["capacity_critical"]


def test_a_disk_already_critical_is_left_to_its_own_alert(conn):
    now = feed(conn, per_day=0.5, days=10, start=92)          # 97%: past the critical limit of 95
    assert forecast.check(conn, now) == []


def test_device_limits_override_and_reset(conn):
    assert hm.rules(conn, 1)["disk_pct"]["warn"] == 85
    out = hm.save_device_limits(conn, 1, {"disk_pct": {"warn": 92, "crit": 98}})
    assert out["disk_pct"]["warn"] == 92 and hm.rules(conn)["disk_pct"]["warn"] == 85
    assert hm.device_overrides(conn, 1)["disk_pct"]["crit"] == 98
    with pytest.raises(hm.MonitorError):
        hm.save_device_limits(conn, 1, {"disk_pct": {"warn": 99, "crit": 90}})
    with pytest.raises(hm.MonitorError):
        hm.save_device_limits(conn, 1, {"nonsense": {"warn": 1}})
    assert hm.save_device_limits(conn, 1, {})["disk_pct"]["warn"] == 85
    assert hm.device_overrides(conn, 1) == {}


def test_a_device_limit_decides_the_level(conn):
    hm.save_device_limits(conn, 1, {"disk_pct": {"warn": 92, "crit": 98}})
    raised = hm.evaluate(conn, 1, 1, "nas", [("disk_pct", "/", 88.0, "%")], "2026-03-10T12:00:00Z")
    assert raised == []                                       # 88% is fine for this device
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (2, 'aa:00:00:00:00:02', '10.0.0.6', 'other', 1, 'x', 'x')")
    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (2,2,'snmp','10.0.0.6',161,'',60,'[]',1,1,'x')")
    other = hm.evaluate(conn, 2, 2, "other", [("disk_pct", "/", 88.0, "%")], "2026-03-10T12:00:00Z")
    assert other == ["metric_warning"]                        # the general limit (85) still applies to the others


def test_the_history_travels_in_the_backup(tmp_path):
    tsdb.forget_all()
    src = tmp_path / "a" / "netlens.db"
    src.parent.mkdir()
    c = connect(src)
    init_db(c)
    store = tsdb.for_conn(c)
    now = int(time.time())
    store.record([("device", 1, "cpu_pct", 42.0, "", "%")], ts=now - 100)
    c.close()
    backup = tmp_path / "b.db"
    create_backup(src, backup)
    tsdb.forget_all()
    dst = tmp_path / "b" / "netlens.db"
    dst.parent.mkdir()
    result = restore_backup(dst, backup)
    assert result["metrics"] is True
    c2 = connect(dst)
    got = tsdb.for_conn(c2).query("device", 1, "cpu_pct", span=3600, end=now)
    c2.close()
    assert [p[1] for p in got["points"]] == [42.0]
    tsdb.forget_all()


def test_the_api(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        assert tc.get("/api/forecast").json() == {"items": [], "alert_days": 14}
        r = tc.put("/api/devices/1/limits", json={"rules": {"disk_pct": {"warn": 90, "crit": 97}}})
        assert r.status_code == 200 and r.json()["overrides"]["disk_pct"]["warn"] == 90 and r.json()["general"]["disk_pct"]["warn"] == 85
        assert tc.put("/api/devices/1/limits", json={"rules": {"disk_pct": {"warn": 99, "crit": 50}}}).status_code == 422
        assert tc.get("/api/devices/9/limits").status_code == 404
    tsdb.forget_all()


def test_the_summary_for_home_assistant_has_health_and_remote_sites(conn):
    from app.stats import summary

    now = feed(conn, per_day=1.0, days=10, start=70)
    conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (1, 'disk_pct', '/data', 'warning', 'x', 80)")
    conn.execute("UPDATE host_monitors SET last_ok = 1 WHERE id = 1")
    conn.commit()
    s = summary(conn)
    assert s["health"]["monitored"] == 1 and s["health"]["warning"] == 1 and s["health"]["critical"] == 0
    assert s["health"]["days_to_full"] is not None
    nas = next(d for d in s["device_list"] if d["id"] == 1)
    assert nas["health"]["level"] == "warning" and nas["health"]["disk"] is not None
    assert s["remote_sites"] == {"total": 0, "silent": 0, "problems": 0, "devices_down": 0, "services_down": 0}


def test_a_rising_memory_is_listed_but_never_announced_as_a_disk(conn):
    now = int(time.time())
    store = tsdb.for_conn(conn)
    for t in range(now - 10 * DAY, now + 1, 3600):
        store.record([("device", 1, "mem_pct", 50 + 2.0 * ((t - (now - 10 * DAY)) / DAY), "", "%")], ts=t)
    store.rollup(now)
    leaks = forecast.memory_trends(conn, now)
    assert len(leaks) == 1 and leaks[0]["device"] == "nas" and 10 < leaks[0]["days_to_full"] < 20
    assert forecast.forecasts(conn, now) == [] and forecast.check(conn, now) == []
