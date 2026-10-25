"""The questions about vulnerabilities, traffic, notifications, on-call, the log and the cause of an incident."""

from datetime import datetime, timezone

import pytest

from app import ask, licence, tsdb
from app.db import connect, init_db
from app.notify import channels as ch

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "x.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.5', 'web1', 1, 'x', 'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


@pytest.mark.parametrize("question,tool", [
    ("which vulnerabilities do I have", "vulnerabilities"), ("is anything exploited", "vulnerabilities"),
    ("how much traffic is on the network", "traffic"), ("would I be told if something broke", "notifications"),
    ("who is on call", "oncall"), ("are there errors in the log", "system_log"),
    ("what caused the latest incident", "investigate"), ("why did web1 stop answering", "investigate"),
])
def test_questions_reach_their_tool(conn, question, tool):
    assert ask.route(question, ["web1"], conn)[0] == tool


def test_vulnerabilities_are_counted(conn):
    conn.execute("INSERT INTO vuln_servers (plugin_id, server_id, name, updated, last_scan) VALUES ('greenbone', 's', 'Greenbone', 'x', '2026-10-25T04:00:00Z')")
    conn.execute("INSERT INTO vuln_findings (plugin_id, finding_id, server_id, device_id, host_ip, title, severity, last_seen, updated) VALUES ('greenbone', 'f1', 's', 1, '192.168.1.5', 'Old OpenSSH', 'critical', 'x', 'x')")
    conn.commit()
    a = ask.answer(conn, "which vulnerabilities do I have", NOW)
    assert a["tools"] == ["vulnerabilities"] and "1 critical" in a["answer"] and "web1" in a["answer"]


def test_notifications_say_who_would_not_hear(conn):
    a = ask.answer(conn, "would I be told if something broke", NOW)
    assert "No notification channel" in a["answer"]
    ch.save_channels(conn, [{"id": "a", "type": "email", "name": "E-mail", "enabled": True, "events": ["device_new"],
                             "filters": {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}, "settings": {}}])
    assert "Nobody would hear about" in ask.answer(conn, "would I be told if something broke", NOW)["answer"]


def test_the_quiet_ones_answer_without_data(conn):
    for q in ("who is on call", "are there errors in the log", "how much traffic is on the network", "what caused the latest incident"):
        a = ask.answer(conn, q, NOW)
        assert a["answer"] and a["source"] == "rules"


def test_traffic_reports_the_newest_reading_and_the_peak(conn):
    store = tsdb.for_conn(conn)
    t0 = int(NOW.timestamp()) - 1800
    for n in range(7):
        store.record([("device", 1, "net_rx_bps", 2e6 + n * 1e6, "eth0", "bps"), ("device", 1, "net_tx_bps", 5e5, "eth0", "bps")], ts=t0 + n * 300)
    conn.commit()
    r = ask.TOOLS["traffic"][0](conn, {}, NOW)
    assert r["devices"]["in_mbps_now"] == 8.0 and r["devices"]["in_mbps_peak"] == 8.0 and r["devices"]["out_mbps_now"] == 0.5
    assert "8.0 Mbit/s in" in ask.render("traffic", r)
