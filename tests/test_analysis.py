"""Analysis reports: an id for the incident and for the report, one document in three shapes (JSON, text, HTML e-mail), pushed through the alert channels, fetchable later."""

import asyncio
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import analysis, incidents, licence, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db
from app.main import create_app
from app.notify import channels as ch
from tests.test_hostprobe import snapshot
from tests.test_investigate import JUMP, NOW, conn, make_incident  # noqa: F401  (the full-disk incident of the investigation tests)


def with_probe_data(conn):
    from app.hostprobe import service as probes

    probes.store(conn, 1, True, "locked", None, snapshot(0), now=(JUMP - timedelta(hours=4)).timestamp())
    probes.store(conn, 1, True, "locked", None, snapshot(16, with_big=True), now=(JUMP + timedelta(hours=2)).timestamp())


def first_incident(conn):
    return incidents.incidents(conn, 7, NOW)[0]


def test_an_incident_has_a_stable_id_and_every_event_in_it_can_be_traced_back(conn):
    make_incident(conn)
    inc = first_incident(conn)
    assert inc["ref"] == f"INC-{inc['id']}" and inc["event_ids"]
    for event_id in inc["event_ids"]:
        assert incidents.incident_of(conn, event_id, 7, NOW)["id"] == inc["id"]
    assert incidents.incident_of(conn, 999999, 7, NOW) is None


def test_the_report_is_kept_under_an_id_with_the_incident_id_in_it(conn):
    make_incident(conn)
    with_probe_data(conn)
    inc = first_incident(conn)
    doc = analysis.create_for_incident(conn, inc["id"], "manual", NOW)
    assert doc["report_ref"] == f"AR-{doc['report_id']}" and doc["incident_ref"] == f"INC-{inc['id']}" and doc["kind"] == "incident" and doc["read_only"] is True
    assert "grew by 16.0 GB" in doc["probable_cause"] and doc["links"]["report"].endswith(f"/api/analysis/{doc['report_id']}") and doc["links"]["mcp"]["tool"] == "get_analysis_report"
    assert doc["links"]["mcp_incident"]["arguments"] == {"incident_id": inc["id"]} and "Information only" in doc["note"]
    again = analysis.get(conn, doc["report_id"])
    assert again["findings"] == doc["findings"] and analysis.latest_for_incident(conn, inc["id"])["report_id"] == doc["report_id"]
    assert analysis.create_for_incident(conn, 424242, "manual", NOW) is None
    second = analysis.create_for_incident(conn, inc["id"], "manual", NOW)
    assert second["report_id"] > doc["report_id"] and [r["report_id"] for r in analysis.listing(conn, 10, inc["id"])] == [second["report_id"], doc["report_id"]]


def test_three_shapes_text_html_and_json_for_other_systems(conn):
    make_incident(conn)
    with_probe_data(conn)
    doc = analysis.create_for_incident(conn, first_incident(conn)["id"], "manual", NOW)
    text = analysis.render_text(doc)
    assert "PROBABLE CAUSE" in text and doc["report_ref"] in text and doc["incident_ref"] in text and "Information only" in text and "get_analysis_report" in text
    page = analysis.render_html(doc)
    assert page.startswith("<!doctype html>") and "PROBABLE CAUSE" in page and doc["report_ref"] in page and "FOR OTHER SYSTEMS" in page and "Information only" in page
    assert "<script" not in page
    payload = analysis.payload(doc)
    assert payload["type"] == "netlens.analysis" and payload["read_only"] is True and payload["report_id"] == doc["report_id"] and payload["incident_id"] == doc["incident_id"]
    assert payload["probable_cause"] == doc["probable_cause"] and payload["findings"] and set(payload["links"]) >= {"report", "mcp", "incident", "mcp_incident"}
    json.dumps(payload)                                                                     # plain JSON, nothing odd inside
    chat = analysis.render_chat(doc)
    assert doc["report_ref"] in chat and len(chat) < 1200 and "Information only" in chat


def test_html_is_escaped():
    doc = {"report_id": 1, "report_ref": "AR-1", "incident_id": None, "incident_ref": None, "kind": "diagnosis", "title": "<script>alert(1)</script>", "created": "2026-10-25T10:00:00Z", "devices": ["x"], "device_ids": [1],
           "window": None, "probable_cause": "Probable cause: <b>x</b>", "findings": [{"level": "warn", "text": "a <img src=x onerror=1>", "probes": ["cpu"], "private": False, "llm_text": None, "unusual": True}],
           "ruled_out": None, "left_out": [], "notified": [], "links": {"report": "http://n/api/analysis/1", "report_html": "http://n/api/analysis/1/html", "mcp": {}}}
    page = analysis.render_html(doc)
    assert "<script>" not in page and "<img" not in page and "&lt;script&gt;" in page and "&lt;b&gt;x&lt;/b&gt;" in page


def test_a_diagnosis_of_one_host_is_a_report_too(conn):
    from app.hostprobe import diagnose, parsers, service
    from tests.test_hostprobe_engineer import CPU

    service.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    import time

    service.store(conn, 1, True, "locked", None, parsers.parse_probe("cpu", "linux", CPU), now=time.time() - 30, probe="cpu")
    diag = diagnose.diagnose(conn, 1, "the server is slow")
    doc = analysis.create_for_diagnosis(conn, diag, "manual")
    assert doc["kind"] == "diagnosis" and doc["incident_ref"] is None and doc["symptom"] == "the server is slow" and "lxc-docker1" in doc["title"] and any("greenbone" in f["text"] for f in doc["findings"])


# ----------------------------------------------------------------------------- pushed through the channels
def channel(kind, **settings):
    base = {"email": {"smtp_host": "smtp", "smtp_port": "25", "security": "none", "from_addr": "netlens@example.com", "to_addrs": "ops@example.com"}, "webhook": {"url": "http://hook/x", "mode": "batch"}, "telegram": {"bot_token": "t", "chat_id": "1"}}[kind]
    return {"id": kind, "type": kind, "name": kind, "enabled": True, "events": ["analysis_ready"], "filters": {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}, "settings": {**base, **settings}}


def run_channels(conn, chans):
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    ch.save_channels(conn, [{**c, "last_event_id": ch.current_max_event_id(conn)} for c in chans])
    analysis.set_setting(conn, analysis.DONE_KEY, "[]")                                    # not the first run
    made = analysis.auto_analyse(conn, NOW)
    sent = {"mail": [], "post": []}

    def mailer(cfg, subject, body, **kw):
        sent["mail"].append({"subject": subject, "body": body, "html": kw.get("html")})

    def poster(url, data, headers, timeout):
        sent["post"].append({"url": url, "json": json.loads(data)})
        return 200, "ok"

    asyncio.run(ch.process_channels(path, now=NOW, poster=poster, mailer=mailer))
    return made, sent


def test_an_incident_is_analysed_automatically_and_pushed_in_the_right_shape_per_channel(conn):
    make_incident(conn)
    with_probe_data(conn)
    made, sent = run_channels(conn, [channel("email"), channel("webhook"), channel("telegram")])
    assert made and all(d["trigger"] == "auto" for d in made)
    mine = next(d for d in made if d["incident_id"] == first_incident(conn)["id"])           # the other incidents of the test data (restarts) are analysed too
    mail = next(m for m in sent["mail"] if m["subject"].startswith(f"[Netlens] {mine['report_ref']} / {mine['incident_ref']}:"))
    assert mail["html"].startswith("<!doctype html>") and "PROBABLE CAUSE" in mail["body"]
    hooks = [p["json"] for p in sent["post"] if p["url"] == "http://hook/x"]
    hook = next(h for h in hooks if h["analysis"]["report_id"] == mine["report_id"])
    assert hook["type"] == "netlens.analysis" and hook["analysis"]["incident_id"] == mine["incident_id"] and hook["analysis"]["read_only"] is True
    chat = next(p for p in sent["post"] if "telegram" in p["url"] and mine["report_ref"] in p["json"]["text"])["json"]["text"]
    assert "Information only" in chat
    assert analysis.auto_analyse(conn, NOW) == []                                           # one automatic analysis per incident, not one per minute


def test_the_first_run_treats_what_already_happened_as_history(conn):
    make_incident(conn)
    assert analysis.auto_analyse(conn, NOW) == []                                         # first run: nothing is analysed
    assert json.loads(analysis.get_setting(conn, analysis.DONE_KEY))                      # ... the incidents that exist are marked as handled
    assert analysis.auto_analyse(conn, NOW) == [] and conn.execute("SELECT COUNT(*) FROM analysis_reports").fetchone()[0] == 0
    add_event(conn, "device_offline", "lxc-docker1 is offline", device_id=1, now=(NOW - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert len(analysis.auto_analyse(conn, NOW)) == 1                                    # a new incident is analysed


def test_the_automatic_analysis_waits_for_the_probes_and_can_be_switched_off(conn):
    analysis.set_setting(conn, analysis.DONE_KEY, "[]")
    add_event(conn, "metric_critical", "lxc-docker1: disk full on / is 96% (limit 95%)", device_id=1, now=(NOW - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert analysis.auto_analyse(conn, NOW) == []                                         # 4 minutes old and still going: the alarm probes need time
    assert [d["report_ref"] for d in analysis.auto_analyse(conn, NOW + timedelta(minutes=8))] != []
    analysis.set_auto(conn, False)
    add_event(conn, "metric_critical", "other", device_id=1, now=(NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    assert analysis.auto_analyse(conn, NOW) == []


def test_a_report_with_nothing_to_say_is_kept_but_not_announced(conn):
    analysis.set_setting(conn, analysis.DONE_KEY, "[]")
    add_event(conn, "device_offline", "x is offline", device_id=1, now=(NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    before = conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'analysis_ready'").fetchone()[0]
    made = analysis.auto_analyse(conn, NOW)
    assert made and not analysis.worth_announcing(made[0]) and conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'analysis_ready'").fetchone()[0] == before


def test_each_event_mode_webhook_gets_one_message_per_report(conn):
    make_incident(conn)
    with_probe_data(conn)
    made, sent = run_channels(conn, [channel("webhook", mode="each")])
    hook = sent["post"][0]["json"]
    assert hook["analysis"]["report_id"] == made[0]["report_id"] and hook["event"]["kind"] == "analysis_ready"


def test_a_failing_channel_resumes_at_the_report(conn):
    make_incident(conn)
    with_probe_data(conn)
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    ch.save_channels(conn, [{**channel("email"), "last_event_id": ch.current_max_event_id(conn)}])
    analysis.set_setting(conn, analysis.DONE_KEY, "[]")
    analysis.auto_analyse(conn, NOW)

    def broken(cfg, subject, body, **kw):
        raise ch.MailError("smtp down")

    asyncio.run(ch.process_channels(path, now=NOW, mailer=broken))
    state = ch.load_channels(conn)[0]
    assert state["status"]["ok"] is False and "smtp down" in state["status"]["error"]
    sent = []
    asyncio.run(ch.process_channels(path, now=NOW, mailer=lambda cfg, s, b, **kw: sent.append(s)))
    assert sent and ch.load_channels(conn)[0]["status"]["ok"] is True                 # the next round sends it


# ----------------------------------------------------------------------------- the API for other systems
@pytest.fixture
def client(tmp_path, monkeypatch):
    tsdb.forget_all()
    path = tmp_path / "a.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.81', 'lxc-docker1', 1, 'x', 'x')")
    c.commit()
    c.close()
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as tc:
        yield tc, path
    tsdb.forget_all()


def test_other_systems_fetch_the_analysis_by_incident_id_or_report_id(client):
    tc, path = client
    db = connect(path)
    now = analysis.datetime.now(analysis.timezone.utc)
    eid = add_event(db, "metric_critical", "lxc-docker1: disk full on / is 99% (limit 95%)", device_id=1, now=(now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    db.close()
    found = tc.get(f"/api/events/{eid}/incident")
    assert found.status_code == 200 and found.json()["incident_ref"] == f"INC-{eid}" and found.json()["latest_report_id"] is None
    doc = tc.get(f"/api/insights/incidents/{eid}/analysis").json()
    assert doc["incident_ref"] == f"INC-{eid}" and doc["read_only"] is True and doc["report_ref"].startswith("AR-")
    assert tc.get(f"/api/events/{eid}/incident").json()["latest_report_id"] == doc["report_id"]
    assert tc.get(f"/api/analysis/{doc['report_id']}").json()["report_id"] == doc["report_id"]
    assert doc["report_ref"] in tc.get(f"/api/analysis/{doc['report_id']}/text").text
    assert tc.get(f"/api/analysis/{doc['report_id']}/html").headers["content-type"].startswith("text/html")
    assert [r["report_id"] for r in tc.get("/api/analysis", params={"incident_id": eid}).json()["reports"]] == [doc["report_id"]]
    assert tc.post(f"/api/insights/incidents/{eid}/analysis").json()["report_id"] > doc["report_id"]
    assert tc.get("/api/analysis/99999").status_code == 404 and tc.get("/api/events/99999/incident").status_code == 404 and tc.get("/api/insights/incidents/99999/analysis").status_code == 404
    assert tc.get("/api/insights/incidents/99999/analysis", params={"create": "false"}).status_code == 404


def test_sending_a_report_by_the_channels_and_the_audit_trail(client, monkeypatch):
    tc, path = client
    db = connect(path)
    eid = add_event(db, "metric_critical", "lxc-docker1: disk full on / is 99% (limit 95%)", device_id=1, now=(analysis.datetime.now(analysis.timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ch.save_channels(db, [channel("email")])
    db.close()
    doc = tc.get(f"/api/insights/incidents/{eid}/analysis").json()
    mails = []
    monkeypatch.setattr(ch, "send_mail", lambda cfg, subject, body, **kw: mails.append((subject, kw.get("html"))))
    monkeypatch.setattr("app.api.analysis.asyncio.to_thread", lambda fn, *a, **k: _async(fn(*a, **k)))
    r = tc.post(f"/api/analysis/{doc['report_id']}/send", json={})
    assert r.status_code == 200 and r.json()["sent"] == ["email"] and mails and mails[0][1].startswith("<!doctype html>")
    assert tc.post(f"/api/analysis/{doc['report_id']}/send", json={"channels": ["nope"]}).status_code == 422
    db = connect(path)
    actions = [a["action"] for a in db.execute("SELECT action FROM audit_log ORDER BY id")]
    db.close()
    assert any(a.startswith(f"Sent analysis report {doc['report_ref']} through: email") for a in actions) and any(a.startswith(f"Fetched the analysis {doc['report_ref']}") for a in actions)


async def _async(value):
    return value


def test_the_settings_for_the_reports(client):
    tc, path = client
    s = tc.get("/api/hostprobe/settings").json()
    assert s["analysis_auto"] is True and s["base_url"] == ""
    out = tc.put("/api/hostprobe/settings", json={"analysis_auto": False, "base_url": "https://netlens.example.lan/"}).json()
    assert out["analysis_auto"] is False and out["base_url"] == "https://netlens.example.lan"
    assert tc.put("/api/hostprobe/settings", json={"base_url": "ftp://x"}).status_code == 422
    db = connect(path)
    db.execute("INSERT INTO events (ts, kind, detail, device_id) VALUES ('2026-10-25T10:00:00Z', 'metric_critical', 'x', 1)")
    db.commit()
    doc = analysis.create_for_incident(db, db.execute("SELECT MAX(id) FROM events").fetchone()[0], "manual")
    db.close()
    assert doc is None or doc["links"]["report"].startswith("https://netlens.example.lan/api/analysis/")


def test_the_install_endpoint_is_checked_and_never_echoes_the_password(client):
    tc, _ = client
    r = tc.post("/api/devices/1/hostprobe/install", json={"action": "install", "username": "bert", "password": "hunter2"})
    assert r.status_code == 422 and "hunter2" not in r.text and "health monitor over SSH" in r.text
    assert tc.post("/api/devices/99/hostprobe/install", json={"action": "check"}).status_code == 404


def test_ask_finds_a_report_by_its_id_and_the_model_does_not_get_names(conn):
    from app import ask
    from app.hostprobe import service

    make_incident(conn)
    with_probe_data(conn)
    doc = analysis.create_for_incident(conn, first_incident(conn)["id"], "manual", NOW)
    assert ask.route(f"show me {doc['report_ref']}", [], conn) == ("analysis", {"ref": doc["report_ref"]})
    assert ask.route(f"what does {doc['incident_ref']} say", [], conn)[0] == "analysis"
    a = ask.answer(conn, f"what does {doc['report_ref']} say?", NOW)
    assert a["tools"] == ["analysis"] and doc["report_ref"] in a["answer"] and "Information only" in a["answer"] and "/media/torrents" in a["answer"]
    token = ask._FOR_MODEL.set(True)
    try:
        hidden = ask.TOOLS["analysis"][0](conn, {"ref": doc["report_ref"]}, NOW)
        assert "/media/torrents" not in str(hidden)
    finally:
        ask._FOR_MODEL.reset(token)
    assert "No analysis found" in ask.answer(conn, "what does AR-9999 say?", NOW)["answer"]
