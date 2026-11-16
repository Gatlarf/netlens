from datetime import datetime, timedelta, timezone

import pytest

from app import healthscore as hs
from app.db import connect, init_db

NOW = "2026-11-16T12:00:00Z"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "n.db")
    init_db(c)
    return c


def _device(conn, name, kind, always_on=1, tier="normal", online=1):
    cur = conn.execute("INSERT INTO devices (hostname, device_type, always_on, tier, online, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                       (name, kind, always_on, tier, online, NOW, NOW))
    return cur.lastrowid


def _checks(conn, dev, up_pattern, ms=None, start=None):
    t = datetime(2026, 11, 16, 11, 0, tzinfo=timezone.utc)
    for i, up in enumerate(up_pattern):
        ts = (t - timedelta(minutes=5 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?,?,?,?)", (dev, ts, up, ms if up else None))
    conn.commit()


def _listing(conn):
    return [{"id": r["id"], "name": r["hostname"], "type": r["device_type"], "online": bool(r["online"])} for r in conn.execute("SELECT * FROM devices")]


def test_parts_score_what_they_measure():
    assert hs.latency_score(10) == 100 and hs.latency_score(30) == 100 and hs.latency_score(300) == 0 and 40 < hs.latency_score(190) < 60
    assert hs.temperature_score(50) == 100 and hs.temperature_score(80) == 50 and hs.temperature_score(90) == 20 and hs.temperature_score(120) == 0


def test_only_always_on_or_critical_devices_count_and_cameras_stand_apart():
    assert hs.group_of("router", "normal", True) == "gear" and hs.group_of("switch", "critical", False) == "gear"
    assert hs.group_of("vm", "normal", True) == "hosts" and hs.group_of("iot", "critical", True) == "hosts"
    assert hs.group_of("iot", "normal", True) is None and hs.group_of("phone", "normal", False) is None and hs.group_of("pc", "normal", True) is None
    assert hs.group_of("camera", "normal", True) == "cameras" and hs.group_of("camera", "normal", False) is None


def test_a_missing_part_is_left_out_and_an_offline_device_is_capped():
    score, worst = hs.device_score({"uptime": 100, "loss": 100, "latency": None, "temperature": None}, True)
    assert score == 100 and worst is None
    assert hs.device_score({"uptime": 100, "loss": 100, "latency": 100, "temperature": 100}, False)[0] == hs.OFFLINE_CAP
    assert hs.device_score({"uptime": None, "loss": None, "latency": None, "temperature": None}, True) == (None, None)
    score, worst = hs.device_score({"uptime": 100, "loss": 100, "latency": 100, "temperature": 50}, True)
    assert score == 90 and worst == "temperature"


def test_a_healthy_network_scores_100_and_a_hot_critical_router_pulls_it_down_with_a_reason(conn):
    sw = _device(conn, "sw", "switch")
    ap = _device(conn, "attic", "router", tier="critical")
    for d in (sw, ap):
        _checks(conn, d, [1] * 12, ms=5.0)
    out = hs.compute(conn, NOW, _listing(conn), {sw: {"temp": 40}, ap: {"temp": 40}}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert out["score"] == 100 and out["costs"] == [] and out["why"] is None and out["label"] == "good"
    hot = hs.compute(conn, NOW, _listing(conn), {sw: {"temp": 40}, ap: {"temp": 90}}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert hot["score"] < 100 and hot["costs"][0]["name"] == "attic" and "hot (90" in hot["costs"][0]["reason"] and "attic" in hot["why"]
    assert hot["devices"][ap] < hot["devices"][sw] == 100


def test_the_importance_changes_the_weight_and_low_devices_never_count(conn):
    a = _device(conn, "a", "switch", tier="low")
    b = _device(conn, "b", "switch", tier="normal")
    _checks(conn, a, [0] * 12)
    _checks(conn, b, [1] * 12, ms=5.0)
    out = hs.compute(conn, NOW, _listing(conn), {}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert out["score"] == 100 and a not in {c["device_id"] for c in out["costs"]}


def test_an_offline_device_and_containers_cost_points_but_containers_less_than_a_vm(conn):
    vm = _device(conn, "vm1", "vm", online=0)
    router = _device(conn, "r", "router")
    _checks(conn, router, [1] * 12, ms=5.0)
    _checks(conn, vm, [1] * 12, ms=5.0)
    one = hs.compute(conn, NOW, _listing(conn), {}, {"running": 4, "unhealthy": 0, "restarting": 0, "problems": []})
    assert one["devices"][vm] == hs.OFFLINE_CAP and one["costs"][0]["name"] == "vm1" and one["costs"][0]["reason"] == "is not answering"
    conn.execute("UPDATE devices SET online = 1")
    both = hs.compute(conn, NOW, _listing(conn), {}, {"running": 4, "unhealthy": 4, "restarting": 0, "problems": [{"host_device_id": router}]})
    assert both["parts"]["containers"] == 0 and 0 < 100 - both["score"] < one["costs"][0]["points"]
    assert both["costs"][0]["name"] == "Containers" and both["costs"][0]["href"] == f"#/device/{router}/network/virtualization"


def test_cameras_have_a_score_of_their_own(conn):
    router = _device(conn, "r", "router")
    cam = _device(conn, "cam", "camera", online=0)
    cam2 = _device(conn, "cam2", "camera")
    _checks(conn, router, [1] * 12, ms=5.0)
    _checks(conn, cam, [1, 0, 0, 0, 0, 0], ms=5.0)
    _checks(conn, cam2, [1] * 12, ms=5.0)
    out = hs.compute(conn, NOW, _listing(conn), {}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert out["score"] == 100                                           # a dead camera does not lower the network score
    assert out["cameras"]["total"] == 2 and out["cameras"]["online"] == 1 and out["cameras"]["score"] < 100 and out["cameras"]["weakest"][0]["name"] == "cam"


def test_nothing_to_score_gives_no_score(conn):
    _device(conn, "phone", "phone", always_on=0)
    out = hs.compute(conn, NOW, _listing(conn), {}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert out["score"] is None and out["label"] is None and out["cameras"]["score"] is None


def test_the_summary_carries_the_score(conn):
    from app import stats

    _device(conn, "sw", "switch")
    conn.commit()
    s = stats.summary(conn, now=NOW)
    assert set(s["score"]) >= {"score", "label", "why", "costs", "parts", "cameras", "devices", "counted"}


def test_a_camera_that_is_all_but_perfect_is_not_listed_as_weak(conn):
    _device(conn, "r", "router")
    cam = _device(conn, "cam", "camera")
    _checks(conn, cam, [1] * 400, ms=5.0)
    conn.execute("UPDATE checks SET up = 0 WHERE id = (SELECT MIN(id) FROM checks)")
    conn.commit()
    out = hs.compute(conn, NOW, _listing(conn), {}, {"running": 0, "unhealthy": 0, "restarting": 0, "problems": []})
    assert out["cameras"]["score"] == 100 and out["cameras"]["weakest"] == []


def test_the_score_of_each_day_is_kept_and_the_trend_compares_with_the_last_day(tmp_path):
    from app import healthscore
    from app.db import connect, init_db

    conn = connect(tmp_path / "n.db")
    init_db(conn)
    block = lambda score, cams=100: {"score": score, "cameras": {"score": cams}}
    healthscore.remember(conn, "2026-11-15T10:00:00Z", block(90))
    healthscore.remember(conn, "2026-11-16T10:00:00Z", block(93))
    healthscore.remember(conn, "2026-11-16T22:00:00Z", block(91, 95))                    # the newest reading of the day replaces the earlier one
    healthscore.remember(conn, "2026-11-16T22:05:00Z", block(91, 95))                    # nothing changed: nothing written
    healthscore.remember(conn, "2026-11-17T08:00:00Z", {"score": None})                  # no score: nothing kept
    assert healthscore.history(conn, "2026-11-01") == [{"day": "2026-11-15", "score": 90, "cameras": 100}, {"day": "2026-11-16", "score": 91, "cameras": 95}]
    assert healthscore.history(conn, "2026-11-16", "2026-11-16") == [{"day": "2026-11-16", "score": 91, "cameras": 95}]
    assert healthscore.trend(conn, "2026-11-17T08:00:00Z", 95) == {"delta": 4, "since": "2026-11-16", "was": 91}
    assert healthscore.trend(conn, "2026-11-15T08:00:00Z", 95) is None and healthscore.trend(conn, "2026-11-17T08:00:00Z", None) is None
    healthscore.remember(conn, "2028-06-01T08:00:00Z", block(80))                       # a new day far later: what is older than 400 days goes
    assert [r["day"] for r in healthscore.history(conn, "2026-01-01")] == ["2028-06-01"]
    conn.close()


def test_the_summary_carries_the_trend(tmp_path):
    from fastapi.testclient import TestClient

    from app import tsdb
    from app.config import load_settings
    from app.main import create_app

    tsdb.forget_all()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        got = c.get("/api/stats/summary").json()
        assert "trend" in got["score"]                                                       # None until there is an earlier day
    tsdb.forget_all()
