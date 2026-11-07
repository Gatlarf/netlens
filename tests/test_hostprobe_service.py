"""Host probe settings, the schedule (what is due now) and the audit line."""
import time
from datetime import datetime, timezone

import pytest

from app.db import connect, init_db
from app.hostprobe import scripts, service

STAMP = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "h.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    c.commit()
    yield c
    c.close()


def test_settings_are_clamped_and_validated(conn):
    out = service.save_settings(conn, {"keep_days": 9999, "names_to_llm": 1, "devices": {"1": {"enabled": True, "interval_h": 0, "ssh_port": 70000, "username": "  bob  ", "probes": ["cpu", "storage"]}}})
    assert out["keep_days"] == 365 and out["names_to_llm"] is True
    d = out["devices"]["1"]
    assert (d["enabled"], d["interval_h"], d["ssh_port"], d["username"], d["probes"]) == (True, 1, 65535, "bob", ["storage", "cpu"])
    for bad in ({"providers": {"nope": {}}}, {"devices": {"x": {}}}, {"devices": {"1": {"provider": "plain"}}}, {"devices": {"1": {"probes": ["rm -rf"]}}}, {"devices": {"1": {"probes": "cpu"}}},
                {"providers": {"vault_ssh": {"url": "ftp://x"}}}):
        with pytest.raises(ValueError):
            service.save_settings(conn, bad)


def test_secrets_are_never_returned_and_can_be_cleared(conn):
    out = service.save_settings(conn, {"providers": {"vault_ssh": {"url": "https://vault.lan", "token": "s.secret", "role_id": "r", "secret_id": "s", "ttl_s": 1}}})
    v = out["providers"]["vault_ssh"]
    assert v["has_token"] and v["has_approle"] and "s.secret" not in str(out)
    assert v["ttl_s"] >= 1
    v = service.save_settings(conn, {"providers": {"vault_ssh": {"clear_token": True, "clear_approle": True}}})["providers"]["vault_ssh"]
    assert not v["has_token"] and not v["has_approle"]


def test_a_damaged_settings_value_falls_back_to_defaults(conn):
    from app.db import set_setting
    set_setting(conn, service.SETTINGS_KEY, "[1, 2")
    assert service.public_settings(conn)["keep_days"] == service.KEEP_DAYS
    set_setting(conn, service.SETTINGS_KEY, "[1]")
    assert service.device_config(conn, 1)["enabled"] is False and service.device_config(conn, 1)["probes"] == list(scripts.PROBES)


def take(conn, probe, ts):
    conn.execute("INSERT INTO probe_snapshots (device_id, probe, taken, ok) VALUES (1, ?, ?, 1)", (probe, ts))
    conn.commit()


def test_due_follows_the_interval_and_the_daily_baseline(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "interval_h": 6, "probes": ["storage", "cpu"]}}})
    now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc).timestamp()
    assert sorted(service.due(conn, now)) == [(1, "cpu"), (1, "storage")]                         # never looked at: both are due
    take(conn, "storage", "2026-11-07T10:00:00Z"); take(conn, "cpu", "2026-11-07T10:00:00Z")
    assert service.due(conn, now) == []                                                           # two hours ago: neither
    take(conn, "storage", "2026-11-07T05:00:00Z"); conn.execute("DELETE FROM probe_snapshots WHERE taken = '2026-11-07T10:00:00Z' AND probe = 'storage'"); conn.commit()
    assert service.due(conn, now) == [(1, "storage")]                                             # storage every 6 h, the others once a day
    service.save_settings(conn, {"devices": {"1": {"enabled": False}}})
    assert service.due(conn, now) == []


def test_an_alarm_brings_a_probe_forward_but_not_more_often_than_the_gap(conn, monkeypatch):
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "interval_h": 24, "probes": ["storage", "cpu"]}}})
    now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc).timestamp()
    take(conn, "storage", "2026-11-07T11:00:00Z"); take(conn, "cpu", "2026-11-07T11:50:00Z")
    monkeypatch.setattr(service, "alarms", lambda c: {1: {"storage", "cpu"}})
    assert service.due_with_reason(conn, now) == [(1, "storage", "alarm")]                      # storage: an hour old, gap is 30 min; cpu: 10 min, gap is 15


def test_alarms_survive_a_broken_problem_list(conn, monkeypatch):
    monkeypatch.setattr(service.hm, "problems", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert service.alarms(conn) == {}


def test_alarms_include_container_trouble(conn):
    from app.db import add_event
    add_event(conn, "container_restarting", "sonarr", device_id=1, now=time.strftime(STAMP, time.gmtime()))
    assert service.alarms(conn)[1] == {"apps", "memory", "cpu"}


def test_the_audit_line_names_the_login_but_never_a_secret():
    ok = {"ok": True, "mode": "full", "probe": "cpu", "credential": {"source": "netlens_ca", "certificate": True, "key_id": "nl-1", "username": "netlens-ro", "expires": 1794000000}}
    text = service.audit_text("nas", ok, "scheduled")
    assert "Host probe 'cpu' of nas (scheduled)" in text and "Netlens CA" in text and "nl-1" in text and "ok, full script" in text
    bad = service.audit_text("nas", {"ok": False, "error": "x" * 400, "credential": {"username": "bob"}}, "started by a person")
    assert "Storage inspection" in bad and "user bob" in bad and len(bad) < 400


def test_the_audit_is_written_for_scheduled_and_manual_runs(conn):
    from types import SimpleNamespace
    service._audit(conn, 1, {"ok": True, "mode": "full", "probe": "storage"}, None)
    service._audit(conn, 99, {"ok": False, "error": "no route", "probe": "cpu"}, (SimpleNamespace(username="bert", role="admin"), "10.0.0.5"))      # unknown device: written by number
    rows = conn.execute("SELECT user, status, action FROM audit_log ORDER BY id").fetchall()
    assert [(r["user"], r["status"]) for r in rows] == [("netlens", 200), ("bert", 502)]
    assert "of nas (scheduled)" in rows[0]["action"] and "of device 99 (started by a person)" in rows[1]["action"] and "no route" in rows[1]["action"]
