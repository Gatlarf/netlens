import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from app import engineer, licence, remediation, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db, set_setting
from app.main import create_app

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "r.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    c.commit()
    remediation.plan(c, NOW)                  # the first look only sets the cursor
    yield c
    c.close()
    tsdb.forget_all()


def rule(conn, **kw):
    data = {"name": "Restart nas service", "kinds": ["service_down"], "device_id": 1, "action": {"type": "ssh", "command": "sudo systemctl restart smbd"}, "mode": "auto"}
    data.update(kw)
    return remediation.save_rule(conn, data)


def event(conn, kind="service_down", detail="smb is down", device_id=1, now=NOW):
    return add_event(conn, kind, detail, device_id=device_id, now=now.strftime("%Y-%m-%dT%H:%M:%SZ"))


def test_rules_are_validated(conn):
    with pytest.raises(remediation.RuleError):
        rule(conn, kinds=[])
    with pytest.raises(remediation.RuleError):
        rule(conn, kinds=["nonsense"])
    with pytest.raises(remediation.RuleError, match="one line"):
        rule(conn, action={"type": "ssh", "command": "a\nb"})
    with pytest.raises(remediation.RuleError, match="not allowed"):
        rule(conn, action={"type": "webhook", "url": "http://127.0.0.1:8080/x"})
    with pytest.raises(remediation.RuleError):
        rule(conn, action={"type": "shell", "command": "rm -rf /"})
    with pytest.raises(remediation.RuleError):
        rule(conn, mode="yolo")
    with pytest.raises(remediation.RuleError):
        rule(conn, cooldown_min=0)
    with pytest.raises(remediation.RuleError):
        rule(conn, device_id=999)


def test_a_webhook_secret_is_stored_encrypted_and_never_shown(conn):
    saved = rule(conn, action={"type": "webhook", "url": "http://192.168.1.5:8123/api/webhook/x", "header_name": "X-Key", "header_value": "s3cret"})
    assert saved["action"]["has_header_value"] is True and "s3cret" not in json.dumps(saved)
    assert "s3cret" not in conn.execute("SELECT secret FROM remediation_rules").fetchone()["secret"]
    assert remediation.get_rule(conn, saved["id"], with_secret=True)["secret"]["header_value"] == "s3cret"
    again = remediation.save_rule(conn, {"name": "renamed"}, saved["id"])          # a partial update keeps the secret
    assert again["name"] == "renamed" and remediation.get_rule(conn, saved["id"], with_secret=True)["secret"]["header_value"] == "s3cret"


def test_auto_rule_runs_on_a_matching_event_only(conn):
    rule(conn)
    event(conn, "device_offline", "x")
    event(conn, "service_down", "smb is down", device_id=None)
    assert remediation.plan(conn, NOW) == []                                            # other kind; no device
    event(conn, "service_down")
    ids = remediation.plan(conn, NOW)
    assert len(ids) == 1
    calls = []
    result = remediation.execute(conn, ids[0], {"ssh": lambda c, r, run: calls.append(run["device_id"]) or "done"}, NOW)
    assert result["state"] == "ok" and calls == [1]
    assert "remediation_ran" in [r["kind"] for r in conn.execute("SELECT kind FROM events")]


def test_a_failing_action_is_recorded(conn):
    rule(conn)
    event(conn)
    (run_id,) = remediation.plan(conn, NOW)

    def boom(c, r, run):
        raise RuntimeError("permission denied")

    result = remediation.execute(conn, run_id, {"ssh": boom}, NOW)
    assert result["state"] == "failed" and result["result"] == "permission denied"
    assert "remediation_failed" in [r["kind"] for r in conn.execute("SELECT kind FROM events")]


def test_cooldown_daily_limit_pause_and_maintenance(conn):
    r = rule(conn, cooldown_min=30, max_per_day=2)
    event(conn)
    (first,) = remediation.plan(conn, NOW)
    remediation.execute(conn, first, {"ssh": lambda *a: "ok"}, NOW)
    event(conn, now=NOW + timedelta(minutes=5))
    assert remediation.plan(conn, NOW + timedelta(minutes=5)) == []                    # cooldown
    event(conn, now=NOW + timedelta(minutes=40))
    (second,) = remediation.plan(conn, NOW + timedelta(minutes=40))
    remediation.execute(conn, second, {"ssh": lambda *a: "ok"}, NOW + timedelta(minutes=40))
    event(conn, now=NOW + timedelta(minutes=90))
    assert remediation.plan(conn, NOW + timedelta(minutes=90)) == []                    # the daily limit of 2
    assert conn.execute("SELECT state FROM remediation_runs WHERE state = 'skipped'").fetchone() is not None
    remediation.save_rule(conn, {"max_per_day": 50}, r["id"])
    remediation.set_paused(conn, True)
    event(conn, now=NOW + timedelta(hours=3))
    assert remediation.plan(conn, NOW + timedelta(hours=3)) == []                       # paused
    remediation.set_paused(conn, False)
    conn.execute("INSERT INTO maintenance_windows (name, start_ts, end_ts, scope) VALUES ('x', '2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', 'all')") if False else None
    stamp = (NOW + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("INSERT INTO events (ts, device_id, kind, detail, maintenance) VALUES (?, 1, 'service_down', 'held', 'window')", (stamp,))
    conn.commit()
    assert remediation.plan(conn, NOW + timedelta(hours=4)) == []                       # held by a maintenance window


def test_ask_mode_waits_for_a_person(conn):
    rule(conn, mode="ask")
    event(conn)
    assert remediation.plan(conn, NOW) == []
    (run,) = remediation.recent_runs(conn)
    assert run["state"] == "pending" and "remediation_pending" in [r["kind"] for r in conn.execute("SELECT kind FROM events")]
    denied = remediation.decide(conn, run["id"], False, "bert", NOW)
    assert denied["state"] == "denied" and denied["decided_by"] == "bert"
    with pytest.raises(remediation.RuleError):
        remediation.decide(conn, run["id"], True, "bert", NOW)
    event(conn, now=NOW + timedelta(hours=1))
    remediation.plan(conn, NOW + timedelta(hours=1))
    run2 = remediation.recent_runs(conn)[0]
    remediation.RUNNERS["ssh"], saved = (lambda c, r, rn: "restarted"), remediation.RUNNERS["ssh"]
    try:
        approved = remediation.decide(conn, run2["id"], True, "bert", NOW + timedelta(hours=1))
    finally:
        remediation.RUNNERS["ssh"] = saved
    assert approved["state"] == "ok" and approved["decided_by"] == "bert"


def test_suggest_mode_only_records(conn):
    rule(conn, mode="suggest")
    event(conn)
    assert remediation.plan(conn, NOW) == []
    assert remediation.recent_runs(conn)[0]["state"] == "suggested"
    assert "remediation_pending" not in [r["kind"] for r in conn.execute("SELECT kind FROM events")]


def test_recovery_is_noticed(conn):
    rule(conn)
    event(conn)
    (run_id,) = remediation.plan(conn, NOW)
    remediation.execute(conn, run_id, {"ssh": lambda *a: "ok"}, NOW)
    assert remediation.check_recovery(conn, NOW + timedelta(minutes=2)) == 0
    event(conn, "service_up", "smb is up", now=NOW + timedelta(minutes=3))
    assert remediation.check_recovery(conn, NOW + timedelta(minutes=4)) == 1
    assert remediation.recent_runs(conn)[0]["recovered"] and remediation.check_recovery(conn, NOW + timedelta(minutes=5)) == 0


def test_nothing_runs_without_a_licence(conn, monkeypatch):
    rule(conn)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: False)
    event(conn)
    assert remediation.plan(conn, NOW) == [] and remediation.recent_runs(conn) == []
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    assert remediation.plan(conn, NOW) == []                                            # and the old event is not replayed later


def test_the_wake_and_webhook_actions(conn, monkeypatch):
    from app import actions

    sent = []
    monkeypatch.setattr(actions, "wake", lambda mac, ip: sent.append((mac, ip)) or ["255.255.255.255"])
    assert "Wake-on-LAN" in remediation.run_wake(conn, {}, {"device_id": 1}) and sent == [("aa:bb:cc:dd:ee:01", "192.168.1.20")]
    with pytest.raises(RuntimeError):
        remediation.run_wake(conn, {}, {"device_id": None})
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"])).decode()
            seen["key"] = self.headers.get("X-Key")
            self.send_response(204 if self.path == "/ok" else 500)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        rl = {"action": {"type": "webhook", "url": base + "/ok", "method": "POST", "body": '{"device": "{device}", "ip": "{ip}"}', "header_name": "X-Key"}, "secret": {"header_value": "k"}}
        assert remediation.run_webhook(conn, rl, {"device_id": 1, "kind": "service_down"}) == "HTTP 204"
        assert json.loads(seen["body"]) == {"device": "nas", "ip": "192.168.1.20"} and seen["key"] == "k"
        rl["action"]["url"] = base + "/bad"
        with pytest.raises(RuntimeError, match="HTTP 500"):
            remediation.run_webhook(conn, rl, {"device_id": 1})
    finally:
        srv.shutdown()


# ----------------------------------------------------------------------------- the digital engineer
ANSWER = '{"diagnosis": "smbd stopped", "confidence": "high", "recommended_rule_id": %d, "reasoning": "r", "next_steps": ["check logs"]}'


def test_parse_answer_is_forgiving_and_strict():
    got = engineer.parse_answer('Sure! ```json\n{"diagnosis": "x", "confidence": "HIGH", "recommended_rule_id": "3", "next_steps": "no"}\n``` hope it helps')
    assert got["confidence"] == "high" and got["recommended_rule_id"] == 3 and got["next_steps"] == []
    assert engineer.parse_answer('{"confidence": "sure"}')["confidence"] == "low"
    with pytest.raises(engineer.EngineerError):
        engineer.parse_answer("no json here")


def test_redaction_hides_addresses_and_names():
    redact = engineer.Redactor(["nas"])
    text = redact("nas at 192.168.1.20 / aa:bb:cc:dd:ee:01 / fd00::5 and NAS again 192.168.1.20")
    assert "192.168" not in text and "aa:bb" not in text and "fd00" not in text and "nas" not in text.lower()
    assert text.count("<ip2>") == 2 and text.count("<ip1>") == 1


def test_the_engineer_approves_only_its_rule_with_high_confidence(conn):
    r = rule(conn, mode="engineer")
    other = rule(conn, name="other", action={"type": "wake"})
    engineer.save_settings(conn, {"enabled": True, "url": "http://llm.local/v1", "model": "m"})
    event(conn)
    remediation.plan(conn, NOW)
    run = [x for x in remediation.recent_runs(conn) if x["rule_id"] == r["id"]][0]
    captured = {}

    def ask(messages):
        captured["text"] = messages[1]["content"]
        return ANSWER % r["id"]

    verdict = engineer.advise(conn, run["id"], ask, NOW)
    assert verdict["approve"] is True and verdict["recommended_rule_id"] == r["id"]
    assert "192.168.1.20" not in captured["text"] and "sudo systemctl" not in captured["text"] and str(other["id"]) in captured["text"]     # redacted, commands never sent
    assert remediation._run(conn, run["id"])["analysis"]["diagnosis"] == "smbd stopped"
    assert engineer.advise(conn, run["id"], lambda m: ANSWER % other["id"], NOW)["approve"] is False       # another rule
    assert engineer.advise(conn, run["id"], lambda m: (ANSWER % r["id"]).replace("high", "medium"), NOW)["approve"] is False
    assert engineer.advise(conn, run["id"], lambda m: ANSWER % 9999, NOW)["recommended_rule_id"] is None   # not one of the rules


def test_engineer_settings_hide_the_key(conn):
    out = engineer.save_settings(conn, {"enabled": True, "url": "http://x/v1/", "model": "m", "api_key": "sk-secret"})
    assert out == {"enabled": True, "url": "http://x/v1", "model": "m", "has_key": True, "redact": True}
    assert "sk-secret" not in conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()["value"]
    with pytest.raises(engineer.EngineerError):
        engineer.save_settings(conn, {"url": "ftp://x"})


def test_process_runs_auto_rules_and_lets_the_engineer_decide(tmp_path, monkeypatch):
    tsdb.forget_all()
    path = tmp_path / "p.db"
    c = connect(path)
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    c.commit()
    asyncio.run(remediation.process(str(path), now=NOW))
    auto = rule(c, name="auto")
    eng = rule(c, name="eng", mode="engineer", kinds=["device_offline"], action={"type": "wake"})
    engineer.save_settings(c, {"enabled": True, "url": "http://x/v1", "model": "m"})
    event(c)
    event(c, "device_offline", "gone")
    ran = []
    runners = {"ssh": lambda *a: ran.append("ssh") or "ok", "wake": lambda *a: ran.append("wake") or "sent"}
    out = asyncio.run(remediation.process(str(path), runners=runners, now=NOW, ask=lambda m: ANSWER % eng["id"]))
    assert ran == ["ssh", "wake"] and out["executed"] == 2
    states = {r["rule_name"]: r["state"] for r in remediation.recent_runs(c)}
    assert states == {"auto": "ok", "eng": "ok"} and auto["id"] != eng["id"]
    c.close()
    tsdb.forget_all()


# ----------------------------------------------------------------------------- the API
def test_api_needs_a_licence_and_works_with_the_trial(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        body = {"name": "Wake it", "kinds": ["device_offline"], "action": {"type": "wake"}, "mode": "ask"}
        view = client.get("/api/remediation", headers=h).json()
        assert view["allowed"] is False and view["rules"] == [] and any(k["id"] == "service_down" for k in view["kinds"])
        refused = client.post("/api/remediation/rules", json=body, headers=h)
        assert refused.status_code == 402 and "licence" in refused.json()["detail"].lower()
        assert client.post("/api/licence/trial", headers=h).status_code == 200
        created = client.post("/api/remediation/rules", json=body, headers=h)
        assert created.status_code == 201
        rid = created.json()["id"]
        assert client.post("/api/remediation/rules", json={**body, "kinds": []}, headers=h).status_code == 422
        assert client.put(f"/api/remediation/rules/{rid}", json={"mode": "suggest"}, headers=h).json()["mode"] == "suggest"
        assert client.put("/api/remediation/paused", json={"paused": True}, headers=h).json() == {"paused": True}
        assert client.get("/api/remediation", headers=h).json()["paused"] is True
        assert client.get("/api/engineer", headers=h).json()["enabled"] is False
        assert client.post("/api/remediation/runs/999/ask", headers=h).status_code == 422          # switched off first
        assert client.put("/api/engineer", json={"enabled": True, "url": "http://127.0.0.1:9/v1", "model": "m"}, headers=h).json()["enabled"] is True
        assert client.delete(f"/api/remediation/rules/{rid}", headers=h).json() == {"removed": rid}
    tsdb.forget_all()


def test_the_ssh_action_runs_the_command_with_the_login_of_the_host_monitor(conn):
    import asyncssh

    from app import vault

    log = []

    async def handle(process):
        command = process.command
        log.append(command)
        if "fail" in command:
            process.stderr.write("denied\n")
            process.exit(3)
        else:
            process.stdout.write("restarted ok\n")
            process.exit(0)

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return (username, password) == ("netlens", "pw")

    async def start():
        return await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")], process_factory=handle)

    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(start())
    port = server.sockets[0].getsockname()[1]
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    try:
        conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, created) VALUES (1, 'ssh', '127.0.0.1', ?, ?, '2026-10-01T00:00:00Z')",
                     (port, vault.encrypt(conn, json.dumps({"username": "netlens", "password": "pw"}))))
        conn.commit()
        good = rule(conn, action={"type": "ssh", "command": "sudo systemctl restart smbd"})
        assert remediation.run_ssh(conn, remediation.get_rule(conn, good["id"], with_secret=True), {"device_id": 1}) == "done: restarted ok"
        assert log == ["sudo systemctl restart smbd"]
        bad = rule(conn, name="bad", action={"type": "ssh", "command": "fail please"})
        with pytest.raises(RuntimeError, match="status 3"):
            remediation.run_ssh(conn, remediation.get_rule(conn, bad["id"], with_secret=True), {"device_id": 1})
        conn.execute("UPDATE host_monitors SET method = 'snmp'")
        with pytest.raises(RuntimeError, match="SSH host monitor"):
            remediation.run_ssh(conn, remediation.get_rule(conn, good["id"], with_secret=True), {"device_id": 1})
    finally:
        loop.call_soon_threadsafe(server.close)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
