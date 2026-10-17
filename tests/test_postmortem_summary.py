from datetime import datetime, timedelta, timezone

import pytest

from app import licence, postmortem, reports, reportsummary
from app.db import add_event, connect, init_db

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
STAMP = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def conn(tmp_path, monkeypatch):
    c = connect(tmp_path / "pm.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-11-01T11:00:00Z')")
    c.commit()
    yield c
    c.close()


def run(conn, ago_h, state="ok", recovered=True, device=1):
    created = (NOW - timedelta(hours=ago_h)).strftime(STAMP)
    rec = (NOW - timedelta(hours=ago_h) + timedelta(minutes=7)).strftime(STAMP) if recovered else None
    cur = conn.execute("INSERT INTO remediation_runs (rule_id, rule_name, action_type, device_id, kind, state, result, created, finished, recovered) VALUES (1, 'Restart smb', 'ssh', ?, 'service_down', ?, 'done', ?, ?, ?)",
                       (device, state, created, created, rec))
    conn.commit()
    return cur.lastrowid


def test_a_fix_that_worked_once_is_a_plain_success(conn):
    r = postmortem.postmortem(conn, run(conn, 5), NOW)
    assert r["verdict"] == "worked" and "within 7 minutes" in r["summary"] and r["recurring"] is False


def test_a_fix_that_keeps_being_needed_is_called_out(conn):
    for h in (24 * 9 + 3, 24 * 6 + 3, 24 * 3 + 3):
        run(conn, h)
    last = run(conn, 3)
    r = postmortem.postmortem(conn, last, NOW)
    assert r["recurring"] is True and "keeps coming back" in r["summary"] and "every 3.0 days" in r["summary"]


def test_failed_early_and_useless_runs(conn):
    assert postmortem.postmortem(conn, run(conn, 5, state="failed", recovered=False), NOW)["verdict"] == "failed"
    assert postmortem.postmortem(conn, run(conn, 5, recovered=False), NOW)["verdict"] == "no_effect"
    assert postmortem.postmortem(conn, run(conn, 0.2, recovered=False), NOW)["verdict"] == "too_early"
    assert postmortem.postmortem(conn, 999, NOW) is None
    assert postmortem.narrate(conn, postmortem.postmortem(conn, run(conn, 5), NOW), ask=lambda m: "It worked.") == "It worked."


def test_the_report_gets_a_short_opening_with_or_without_a_model(conn):
    add_event(conn, "device_offline", "x", device_id=1, now="2026-10-30T10:00:00Z")
    add_event(conn, "anomaly", "x", device_id=1, now="2026-10-30T10:05:00Z")
    report = reports.weekly(conn, NOW)
    text = reportsummary.summary(conn, report, NOW)
    assert text.startswith(("Nothing needs attention", "1 thing")) and "1 incident" in text and "1 reading was unusual" in text
    assert reportsummary.summary(conn, report, NOW, ask=lambda m: "A quiet week.") == "A quiet week."
    reportsummary.set_enabled(conn, False)
    assert reportsummary.enabled(conn) is False
