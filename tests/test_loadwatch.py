"""Expected busy periods: a known heavy job, or a busy time that comes back at the same hour, day or interval, raises no processor warning."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import tsdb
from app.db import connect, init_db
from app.hostmetrics import loadwatch as lw
from app.hostmetrics import service as hm
from app.hostmetrics import ssh

T0 = datetime(2026, 3, 10, 3, 0).astimezone()           # 03:00 local time


def stamp(t):
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'gpwindows', 1, 'x', 'x')")
    c.commit()
    hm.save_monitor(c, 1, {"method": "snmp", "address": "10.0.0.5", "community": "x"})
    yield c
    c.close()
    tsdb.forget_all()


def mid(conn):
    return hm.get_monitor(conn, 1)["id"]


def run(conn, start, minutes, value=99, top=None, step=5):
    """Readings every `step` minutes from `start`; returns the events that were raised."""
    raised = []
    for m in range(0, minutes + 1, step):
        raised += hm.evaluate(conn, mid(conn), 1, "gpwindows", [("cpu_pct", "", value, "%")], stamp(start + timedelta(minutes=m)), top)
    return raised


def kinds(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events ORDER BY id")]


DEFENDER = [("MsMpEng", 95.0)]


# ------------------------------------------------------------------------------------------------ the knowledge
def test_known_processes_are_recognised_by_name_only():
    assert lw.known("MsMpEng.exe")[0].startswith("Windows Defender")
    assert lw.known("msmpeng#2")[0].startswith("Windows Defender")
    assert lw.known("md0_resync")[0] == "a RAID check or rebuild"
    assert lw.known("ospd-openvas")[0].startswith("a Greenbone")
    assert lw.known("svchost") is None and lw.known("") is None


# ------------------------------------------------------------------------------------------------ known process
def test_a_known_job_for_a_normal_time_raises_nothing_but_a_long_one_does(conn):
    assert run(conn, T0, 85, top=DEFENDER) == []                                 # 85 minutes of Defender: within the 90 a scan may take
    ep = conn.execute("SELECT * FROM load_episodes").fetchone()
    assert "msmpeng" in ep["explained"] and ep["process"] == "MsMpEng"
    late = run(conn, T0 + timedelta(minutes=90), 40, top=DEFENDER)               # it goes on: now it is a problem
    assert late == ["metric_critical"]
    text = kinds(conn)[0][1]
    assert "mostly msmpeng (Windows Defender" in text and "longer than the usual 90" in text


def test_an_unknown_process_still_warns_and_is_named(conn):
    assert run(conn, T0, 30, top=[("fancyapp", 96.0)]) == ["metric_critical"]
    assert "mostly fancyapp" in kinds(conn)[0][1]


def test_a_process_that_holds_little_of_the_load_does_not_explain_it(conn):
    assert run(conn, T0, 30, top=[("MsMpEng", 20.0)]) == ["metric_critical"]


def test_switched_off_everything_warns_as_before(conn):
    lw.set_enabled(conn, False)
    assert run(conn, T0, 30, top=DEFENDER) == ["metric_critical"]
    assert "mostly" not in kinds(conn)[0][1] and conn.execute("SELECT COUNT(*) FROM load_episodes").fetchone()[0] == 0


def test_a_warning_that_is_already_out_is_not_hidden_afterwards(conn):
    assert run(conn, T0, 30, top=[("fancyapp", 96.0)]) == ["metric_critical"]
    assert run(conn, T0 + timedelta(minutes=35), 10, top=DEFENDER) == []        # no new event; it clears by itself when the load ends
    assert conn.execute("SELECT level FROM metric_state").fetchone()[0] == "critical"


# ------------------------------------------------------------------------------------------------ the busy periods are remembered
def test_a_busy_period_ends_after_ten_minutes_below_the_limit(conn):
    run(conn, T0, 10, top=DEFENDER)
    run(conn, T0 + timedelta(minutes=15), 15, value=10)
    row = conn.execute("SELECT * FROM load_episodes").fetchone()
    assert row["end_ts"] == row["last_ts"] and (row["end_ts"] - row["start_ts"]) == 600
    assert [e["minutes"] for e in lw.recent(conn, 1, now_ts=T0.timestamp() + 3600)] == [10]


# ------------------------------------------------------------------------------------------------ regular times
def seed(conn, starts, minutes=20):
    for t in starts:
        conn.execute("INSERT INTO load_episodes (monitor_id, metric, label, start_ts, last_ts, end_ts, peak) VALUES (?, 'cpu_pct', '', ?, ?, ?, 95)",
                     (mid(conn), int(t.timestamp()), int(t.timestamp()) + minutes * 60, int(t.timestamp()) + minutes * 60))
    conn.commit()


def test_a_busy_time_that_comes_back_every_day_is_expected(conn):
    seed(conn, [T0 - timedelta(days=d) for d in range(1, 6)])
    now = T0 + timedelta(minutes=2)
    assert run(conn, now, 25, top=[("somejob", 90.0)]) == []                      # an unknown process, but the host is always busy now
    assert "busy every day around 03:02" in conn.execute("SELECT explained FROM load_episodes WHERE end_ts IS NULL").fetchone()[0]
    assert run(conn, now + timedelta(minutes=30), 30, top=[("somejob", 90.0)]) == ["metric_critical"]      # but not for much longer than before
    assert "longer than the usual" in kinds(conn)[0][1]


def test_busy_at_an_unusual_time_is_not_expected(conn):
    seed(conn, [T0 - timedelta(days=d) for d in range(1, 6)])
    assert run(conn, T0 + timedelta(hours=9), 30) == ["metric_critical"]


def test_the_patterns():
    here = T0
    hour = lambda days: (here - timedelta(days=days), 1200)                           # noqa: E731
    daily = lw.recurring([(int(a.timestamp()), d) for a, d in (hour(d) for d in range(1, 6))], int(here.timestamp()))
    assert daily["text"] == "every day around 03:00" and daily["typical_min"] == 20 and 15 <= daily["allowed_min"] <= 40
    weekly = lw.recurring([(int((here - timedelta(weeks=w)).timestamp()), 1800) for w in range(1, 5)], int(here.timestamp()))
    assert weekly["text"].startswith("every Tuesday around 03:00")
    every4h = lw.recurring([(int((here - timedelta(hours=4 * k)).timestamp()), 600) for k in range(1, 7)], int(here.timestamp()))
    assert every4h["text"] == "about every 4 hours"
    assert lw.recurring([(int((here - timedelta(days=d)).timestamp()), 600) for d in (1, 2)], int(here.timestamp())) is None                 # too few
    scattered = [(int((here - timedelta(hours=h)).timestamp()), 600) for h in (5, 29, 40, 77, 130)]
    assert lw.recurring(scattered, int(here.timestamp())) is None                                                                      # no rhythm


# ------------------------------------------------------------------------------------------------ the readers
def test_linux_top_processes_from_two_rounds():
    sec1 = {"procs": ["  10 100 gvmd", "  11 50 sshd"], "cgroup": ["ncpu 4"]}
    sec2 = {"procs": ["  10 220 gvmd", "  11 51 sshd", "  12 8 new"], "cgroup": ["ncpu 4"]}
    state = {}
    assert ssh.top_processes(sec1, state, 1000.0) == []                          # the first round only remembers
    top = ssh.top_processes(sec2, state, 1060.0)                                 # 120 cpu-seconds in 60 s on 4 cores = 50% of the machine
    assert top[0][0] == "gvmd" and round(top[0][1]) == 50 and all(n != "sshd" for n, _ in top)


def test_windows_top_processes_are_a_share_of_the_machine():
    out = "##netlens-windows\n" + json.dumps({"cpu": 97, "nc": 8, "top": [{"n": "MsMpEng", "c": 700.0}, {"n": "svchost#2", "c": 40.0}]})
    state = {}
    points, _found = ssh.parse_windows(out, state, 1.0)
    assert ("cpu_pct", "", 97.0, "%") in points
    assert state["top"][0] == ("MsMpEng", 87.5) and state["top"][1][0] == "svchost#2"


def test_the_windows_script_asks_for_processes_only_while_busy():
    assert "$r.cpu -ge 50" in ssh.WIN_SCRIPT and "PerfProc_Process" in ssh.WIN_SCRIPT


def test_the_switch_is_in_the_limits_api(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    admin = {"Authorization": "Bearer secret"}
    with TestClient(app) as c:
        assert c.get("/api/monitoring/limits", headers=admin).json()["explain_load"] is True
        assert c.put("/api/monitoring/limits", json={"rules": {}, "explain_load": False}, headers=admin).json()["explain_load"] is False
        assert c.get("/api/monitoring/limits", headers=admin).json()["explain_load"] is False
        assert c.get("/api/devices/1/busy-periods", headers=admin).json() == {"enabled": False, "periods": []}
