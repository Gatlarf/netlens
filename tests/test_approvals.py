"""Four-eyes approval: another administrator has to say yes, once, for that target, never for oneself."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import approvals, licence, secpolicy
from app.config import load_settings
from app.db import connect
from app.main import create_app
from tests.fake_terminal import FakeBackend
from tests.test_api_terminal_session import make_app

ADMIN = {"Authorization": "Bearer t"}
URL = "/api/terminal/1/ws?proto=ssh"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    secpolicy.forget()
    FakeBackend.reset()
    app = make_app(tmp_path)
    app.state.settings  # noqa: B018
    with TestClient(app, headers=ADMIN) as root:
        for name in ("alice", "bella", "carl"):
            assert root.post("/api/users", json={"username": name, "password": "longenough1", "role": "admin"}).status_code == 201
        yield app, tmp_path / "t.db", root
    secpolicy.forget()


def signin(app, name):
    c = TestClient(app)
    c.headers.pop("authorization", None)            # the access token of the first client must not leak into a person's session
    assert c.post("/api/login", json={"username": name, "password": "longenough1"}).status_code == 200
    return c


def switch_on(root, *actions, minutes=15):
    r = root.put("/api/security-policy", json={"four_eyes": list(actions), "four_eyes_minutes": minutes})
    assert r.status_code == 200, r.text


def open_terminal(c, extra=None):
    with c.websocket_connect(URL) as ws:
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 80, "rows": 24, **(extra or {})})
        return ws.receive_json()


def test_the_policy_needs_two_administrators_and_validates(tmp_path, monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    secpolicy.forget()
    app = make_app(tmp_path)
    with TestClient(app, headers=ADMIN) as root:
        assert root.put("/api/security-policy", json={"four_eyes": ["terminal"]}).status_code == 422           # nobody to approve
        root.post("/api/users", json={"username": "alice", "password": "longenough1", "role": "admin"})
        assert root.put("/api/security-policy", json={"four_eyes": ["terminal"]}).status_code == 422           # one is not enough
        root.post("/api/users", json={"username": "bella", "password": "longenough1", "role": "admin"})
        for bad in ("terminal", ["nope"], [1]):
            assert root.put("/api/security-policy", json={"four_eyes": bad}).status_code == 422, bad
        assert root.put("/api/security-policy", json={"four_eyes_minutes": 0}).status_code == 422
        assert root.put("/api/security-policy", json={"four_eyes": ["terminal", "terminal", "restore"]}).json()["policy"]["four_eyes"] == ["restore", "terminal"]
    secpolicy.forget()


def test_a_terminal_needs_another_administrator_and_an_approval_works_once(env):
    app, path, root = env
    switch_on(root, "terminal")
    alice, bella = signin(app, "alice"), signin(app, "bella")
    msg = open_terminal(alice)
    assert msg["type"] == "error" and msg["code"] == "approval_required" and msg["target"] == "1" and not FakeBackend.created
    ask = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "INC-1 restart"})
    assert ask.status_code == 201 and ask.json()["status"] == "pending"
    assert open_terminal(alice)["code"] == "approval_required"                                       # still waiting
    assert alice.post(f"/api/approvals/{ask.json()['id']}/decide", json={"approve": True}).status_code == 403      # not one's own
    assert [a["requester"] for a in bella.get("/api/approvals").json()["waiting"]] == ["alice"]
    assert alice.get("/api/approvals").json()["waiting"] == []
    done = bella.post(f"/api/approvals/{ask.json()['id']}/decide", json={"approve": True, "comment": "ok"})
    assert done.status_code == 200 and done.json()["status"] == "approved" and done.json()["decided_by"] == "bella"
    assert bella.post(f"/api/approvals/{ask.json()['id']}/decide", json={"approve": False}).status_code == 409        # already decided
    assert open_terminal(alice)["state"] == "connected" and len(FakeBackend.created) == 1                            # used
    assert open_terminal(alice)["code"] == "approval_required"                                         # one use only
    audit = " ".join(r["action"] for r in root.get("/api/audit").json()["entries"])
    assert "Asked for approval" in audit and "INC-1 restart" in audit and "Approved the request of alice" in audit


def test_an_approval_is_for_that_person_that_action_and_that_target(env):
    app, path, root = env
    switch_on(root, "terminal", "remote")
    alice, bella, carl = signin(app, "alice"), signin(app, "bella"), signin(app, "carl")
    made = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "INC-2 check"}).json()
    bella.post(f"/api/approvals/{made['id']}/decide", json={"approve": True})
    assert open_terminal(carl)["code"] == "approval_required"                                          # somebody else cannot use it
    r = alice.post("/api/remote/1/session", json={"proto": "rdp"})
    assert r.status_code == 403 and r.json()["detail"] == "approval_required:remote:1"
    assert alice.post("/api/approvals", json={"action": "terminal", "target": "999", "reason": "no such device"}).status_code == 404
    assert alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "x"}).status_code == 422       # a reason is needed
    assert alice.post("/api/approvals", json={"action": "format", "target": "1", "reason": "xyz"}).status_code == 422
    assert open_terminal(alice)["state"] == "connected"


def test_denied_cancelled_and_expired_requests_give_nothing(env):
    app, path, root = env
    switch_on(root, "terminal")
    alice, bella = signin(app, "alice"), signin(app, "bella")
    a = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "first"}).json()
    assert bella.post(f"/api/approvals/{a['id']}/decide", json={"approve": False, "comment": "not now"}).json()["status"] == "denied"
    assert open_terminal(alice)["code"] == "approval_required"
    b = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "second"}).json()
    assert alice.post(f"/api/approvals/{b['id']}/cancel").json()["status"] == "cancelled"
    assert bella.post(f"/api/approvals/{b['id']}/decide", json={"approve": True}).status_code == 409
    c = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "third"}).json()
    bella.post(f"/api/approvals/{c['id']}/decide", json={"approve": True})
    conn = connect(path)
    conn.execute("UPDATE approvals SET expires = ? WHERE id = ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), c["id"]))
    conn.commit()
    assert open_terminal(alice)["code"] == "approval_required"                                          # the approval ran out
    d = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "fourth"}).json()
    conn.execute("UPDATE approvals SET created = '2020-01-01T00:00:00Z' WHERE id = ?", (d["id"],))
    conn.commit()
    assert bella.get("/api/approvals").json()["waiting"] == []                                          # a request nobody answered lapses
    assert bella.post(f"/api/approvals/{d['id']}/decide", json={"approve": True}).status_code == 409


def test_a_request_is_not_duplicated_and_the_number_open_is_limited(env):
    app, path, root = env
    switch_on(root, "terminal")
    alice = signin(app, "alice")
    first = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "same thing"}).json()
    again = alice.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "same thing again"}).json()
    assert again["id"] == first["id"]
    for n in range(2, approvals.MAX_PENDING_PER_USER + 1):
        assert alice.post("/api/approvals", json={"action": "restore", "target": f"b{n}", "reason": "restore it"}).status_code == 201
    assert alice.post("/api/approvals", json={"action": "restore", "target": "one-more", "reason": "restore it"}).status_code == 422


def test_restore_and_the_access_token_and_break_glass(env):
    app, path, root = env
    switch_on(root, "restore", "terminal")
    alice, bella = signin(app, "alice"), signin(app, "bella")
    r = alice.post("/api/backups/netlens-x.db/restore")
    assert r.status_code == 403 and r.json()["detail"] == "approval_required:restore:netlens-x.db"
    assert root.post("/api/restore", content=b"x").status_code == 403 and "approval_required:restore:upload" in root.post("/api/restore", content=b"x").text      # the access token cannot ask
    assert root.post("/api/approvals", json={"action": "restore", "target": "upload", "reason": "token"}).status_code == 400
    made = alice.post("/api/approvals", json={"action": "restore", "target": "netlens-x.db", "reason": "INC-3 roll back"}).json()
    bella.post(f"/api/approvals/{made['id']}/decide", json={"approve": True})
    assert alice.post("/api/backups/netlens-x.db/restore").status_code == 404                           # approved: now it fails only because that backup does not exist
    assert alice.post("/api/backups/netlens-x.db/restore").status_code == 403                           # and the approval was used


def test_break_glass_accounts_are_exempt_and_only_people_can_ask():
    from types import SimpleNamespace

    policy = {"four_eyes": ["terminal"]}
    glass = SimpleNamespace(user_id=1, auth_method="password", assistant=None, break_glass=True, username="glass")
    assert approvals.require(None, glass, policy, "terminal", "1") is None
    token = SimpleNamespace(user_id=None, auth_method=None, assistant=None, break_glass=False, username="access token")
    assert not approvals.person(token) and not approvals.person(None)
    with pytest.raises(approvals.ApprovalError, match="approval_required:terminal:1"):
        approvals.require(None, token, policy, "terminal", "1")
    assert approvals.require(None, token, {"four_eyes": []}, "terminal", "1") is None                      # not asked for: nothing needed


def test_the_dashboard_and_an_event_tell_the_other_administrators(env):
    app, path, root = env
    switch_on(root, "terminal")
    signin(app, "alice").post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "INC-9 please"})
    conn = connect(path)
    assert conn.execute("SELECT detail FROM events WHERE kind = 'approval_requested'").fetchone()[0].startswith("alice asks to open a terminal") 
    from app import dashboard

    assert [p for p in dashboard.current_problems(conn) if "approval request" in p["text"]]
    assert signin(app, "alice").get("/api/approvals/9999").status_code == 404


def test_a_viewer_cannot_use_the_approval_routes(env):
    app, path, root = env
    root.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    vera = signin(app, "vera")
    assert vera.get("/api/approvals").status_code == 403 and vera.post("/api/approvals", json={"action": "terminal", "target": "1", "reason": "abc"}).status_code == 403
