from datetime import datetime, timezone

import pytest

from app import aireport, engineer, hierarchy, incidents, licence
from app.db import add_event, connect, init_db

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    c = connect(tmp_path / "r.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    for i, (name, ip) in enumerate([("sw-core", "192.168.1.2"), ("cam1", "192.168.1.31"), ("cam2", "192.168.1.32"), ("nas", "192.168.1.20"), ("router", "192.168.1.1")], 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')", (i, f"aa:bb:cc:dd:ee:0{i}", ip, name))
    c.commit()
    yield c
    c.close()


def ev(conn, kind, stamp, device_id, detail="x"):
    return add_event(conn, kind, detail, device_id=device_id, now=f"2026-11-01T{stamp}:00Z")


def tree(monkeypatch):
    """cam1 and cam2 sit behind sw-core, which sits behind router."""
    devices = {i: {"id": i} for i in range(1, 6)}
    return monkeypatch


def with_hierarchy(conn, monkeypatch, parents):
    devs, _ = hierarchy.load_hierarchy(conn)
    chain = {child: hierarchy.Parent(parent, "manual", "test") for child, parent in parents.items()}
    monkeypatch.setattr(aireport, "load_hierarchy", lambda c: (devs, chain))
    monkeypatch.setattr(incidents, "load_hierarchy", lambda c: (devs, chain))


def test_a_quiet_period_has_one_info_finding_and_a_plain_report(conn):
    facts = aireport.collect(conn, "24h", NOW)
    assert [f["strength"] for f in facts["findings"]] == ["info"] and "No problems" in facts["findings"][0]["text"] and facts["findings"][0]["id"] == "F1"
    report = aireport.write(conn, "24h", now=NOW)
    assert report["source"] == "plain" and report["lines"][0]["refs"] == ["F1"] and aireport.latest(conn, "24h")["source"] == "plain"


def test_a_shared_parent_that_stayed_quiet_is_a_likely_cause(conn, monkeypatch):
    with_hierarchy(conn, monkeypatch, {2: 1, 3: 1})
    ev(conn, "device_offline", "10:00", 2)
    ev(conn, "device_offline", "10:01", 3)
    facts = aireport.collect(conn, "24h", NOW)
    shared = [f for f in facts["findings"] if f["type"] == "shared_parent"]
    assert shared and shared[0]["strength"] == "likely" and "sw-core" in shared[0]["text"] and "did not report a problem" in shared[0]["text"]


def test_a_parent_that_failed_first_is_a_strong_finding(conn, monkeypatch):
    with_hierarchy(conn, monkeypatch, {2: 1, 3: 1})
    ev(conn, "device_offline", "10:00", 1)
    ev(conn, "device_offline", "10:01", 2)
    ev(conn, "device_offline", "10:02", 3)
    top = aireport.collect(conn, "24h", NOW)["findings"][0]
    assert top["strength"] == "strong" and "sw-core" in top["text"]


def test_a_change_shortly_before_a_problem_is_possible_and_an_old_one_is_not_mentioned(conn):
    conn.execute("INSERT INTO audit_log (ts, user, method, path, status, action) VALUES ('2026-11-01T09:45:00Z', 'admin', 'PUT', '/api/x', 200, 'changed the scan ranges')")
    conn.execute("INSERT INTO audit_log (ts, user, method, path, status, action) VALUES ('2026-11-01T05:00:00Z', 'admin', 'PUT', '/api/x', 200, 'changed the map')")
    conn.execute("UPDATE devices SET always_on = 1 WHERE id = 4")       # a server, not a phone: its outage is worth a closer look
    conn.commit()
    ev(conn, "device_offline", "10:00", 4)
    facts = aireport.collect(conn, "24h", NOW)
    changes = [f for f in facts["findings"] if f["type"] == "change"]
    assert len(changes) == 1 and changes[0]["strength"] == "possible" and "15 minutes before" in changes[0]["text"] and "by admin" in changes[0]["text"] and "scan ranges" in changes[0]["text"]


def test_a_problem_that_keeps_coming_back_at_the_same_hour(conn):
    for day in (28, 29, 30, 31):
        add_event(conn, "service_down", "x", device_id=4, now=f"2026-10-{day}T03:10:00Z")
    facts = aireport.collect(conn, "7d", NOW)
    rec = [f for f in facts["findings"] if f["type"] == "recurring"]
    assert rec and "4 times" in rec[0]["text"] and "around 03:00 UTC" in rec[0]["text"] and rec[0]["strength"] == "likely"


def test_findings_are_numbered_strongest_first(conn, monkeypatch):
    with_hierarchy(conn, monkeypatch, {2: 1, 3: 1})
    ev(conn, "device_offline", "10:00", 1)
    ev(conn, "device_offline", "10:01", 2)
    conn.execute("INSERT INTO audit_log (ts, user, method, path, status, action) VALUES ('2026-11-01T09:50:00Z', 'admin', 'PUT', '/api/x', 200, 'changed something')")
    conn.commit()
    ids = [(f["id"], f["strength"]) for f in aireport.collect(conn, "24h", NOW)["findings"]]
    assert ids[0] == ("F1", "strong") and ids[-1][1] == "possible" and [i for i, _ in ids] == [f"F{n}" for n in range(1, len(ids) + 1)]


FACTS = {"label": "the last 24 hours", "findings": [
    {"id": "F1", "text": "sw-core went wrong and 2 devices behind it were affected. 3 alerts within 2 minutes.", "strength": "strong", "devices": ["sw-core"]},
    {"id": "F2", "text": "15 minutes before it began, this changed by admin: changed the scan ranges", "strength": "possible", "devices": []}]}


def test_validation_keeps_only_sentences_tied_to_findings_with_known_numbers():
    raw = """Here is your report:
- The switch sw-core failed and 2 devices behind it were affected [F1].
The nas will fail at 14:00 tomorrow [F1].
The router was rebooted [F9].
A change 15 minutes earlier may be related [F2].
Everything is fine.
CHECK: look at the power of sw-core [F1]
CHECK: replace 5 cables [F2]"""
    lines, dropped = aireport.validate(raw, FACTS)
    assert [(l["kind"], l["refs"]) for l in lines] == [("line", ["F1"]), ("line", ["F2"]), ("check", ["F1"])]
    assert lines[0]["text"] == "The switch sw-core failed and 2 devices behind it were affected."
    assert dropped == 5          # the preamble, the invented time, the unknown finding, the sentence without one, the invented 5 cables


def test_a_model_report_is_stored_with_its_source_and_how_much_was_dropped(conn, monkeypatch):
    with_hierarchy(conn, monkeypatch, {2: 1, 3: 1})
    ev(conn, "device_offline", "10:00", 1)
    ev(conn, "device_offline", "10:01", 2)
    seen = {}

    def fake(messages):
        seen["system"], seen["user"] = messages[0]["content"], messages[1]["content"]
        return "The core switch failed and a device behind it was affected [F1].\nIt will rain tomorrow."

    monkeypatch.setattr(engineer, "settings", lambda c: {"enabled": True, "url": "x", "model": "llama3.1:8b", "has_key": False, "redact": True})
    report = aireport.write(conn, "24h", ask=fake, now=NOW)
    assert report["source"] == "model" and report["model"] == "llama3.1:8b" and report["dropped"] == 1
    assert [l["refs"] for l in report["lines"]] == [["F1"]]
    assert "F1 (strong)" in seen["user"] and "sw-core" not in seen["user"]           # the names went out as placeholders


def test_a_model_that_writes_nothing_usable_falls_back_to_the_findings(conn, monkeypatch):
    ev(conn, "device_offline", "10:00", 4)
    report = aireport.write(conn, "24h", ask=lambda m: "I cannot help with that.", now=NOW)
    assert report["source"] == "plain" and report["lines"] and report["dropped"] == 1
    assert aireport.write(conn, "24h", ask=lambda m: (_ for _ in ()).throw(RuntimeError("down")), now=NOW)["source"] == "plain"
    assert aireport.write(conn, "24h", ask=lambda m: "never used", now=NOW, use_model=False)["source"] == "plain"


def test_the_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    admin = {"Authorization": "Bearer secret"}
    with TestClient(app) as c:
        first = c.get("/api/insights/report?period=7d", headers=admin).json()
        assert first["report"] is None and first["now"]["findings"] and set(first["periods"]) == {"6h", "24h", "3d", "7d"}
        made = c.post("/api/insights/report", json={"period": "7d"}, headers=admin).json()
        assert made["source"] == "plain" and made["period"] == "7d"
        assert c.get("/api/insights/report?period=7d", headers=admin).json()["report"]["generated"] == made["generated"]
        assert c.get("/api/insights/report?period=1y", headers=admin).status_code == 422
        monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: False)
        assert c.get("/api/insights/report", headers=admin).status_code == 402


def test_minor_outages_rank_last_and_recurring_ones_are_told_once(conn):
    for hh, back in (("02:00", "02:20"), ("05:00", "05:20"), ("08:00", "08:20")):
        ev(conn, "device_offline", hh, 5)                                    # the router, three times: recurring
        ev(conn, "device_online", back, 5)
    ev(conn, "device_offline", "10:00", 4)                                   # a phone-like device, once: minor
    conn.execute("UPDATE devices SET always_on = 1 WHERE id = 5")
    conn.commit()
    found = aireport.collect(conn, "24h", NOW)["findings"]
    types = [(f["type"], f["strength"]) for f in found]
    assert types[0][0] == "recurring" and ("incident", "info") in types and types.index(("incident", "info")) > 0
    assert sum(1 for f in found if "router" in f["text"]) == 1               # not again as three separate single events


def test_the_same_parent_is_one_finding_with_all_the_names(conn, monkeypatch):
    with_hierarchy(conn, monkeypatch, {2: 1, 3: 1})
    for start, back in (("08:00", "08:30"), ("11:00", "11:30")):
        ev(conn, "device_offline", start, 2)
        ev(conn, "device_offline", start[:-1] + "1", 3)
        ev(conn, "device_online", back, 2)
        ev(conn, "device_online", back[:-1] + "1", 3)
    shared = [f for f in aireport.collect(conn, "24h", NOW)["findings"] if f["type"] == "shared_parent"]
    assert len(shared) == 1 and "2 problems" in shared[0]["text"] and "cam1" in shared[0]["text"] and "cam2" in shared[0]["text"] and "behind sw-core" in shared[0]["text"]
