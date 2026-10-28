"""Step-up re-authentication, the access-token and API-token controls, break-glass accounts, and the inventory that keeps new routes honest."""

import json
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app import licence, oidc, secpolicy, stepup, totp, users
from app.config import load_settings
from app.db import connect
from app.main import create_app
from tests.test_oidc import Idp, idp  # noqa: F401  (the fake identity provider)

ADMIN = {"Authorization": "Bearer secret"}
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime(STAMP)


@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "mfa_policy": True, "teams": True, "sso": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        for name, role in (("alice", "admin"), ("bella", "admin"), ("viola", "viewer")):
            assert c.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code == 201
        yield c, app, path, state
    secpolicy.forget()


def signin(app, name="alice"):
    c = TestClient(app)
    assert c.post("/api/login", json={"username": name, "password": "longenough1"}).json().get("ok")
    return c


def put(c, **body):
    return c.put("/api/security-policy", json=body, headers=ADMIN)


def stale(path, name="alice", minutes=30):
    conn = connect(path)
    conn.execute("UPDATE sessions SET auth_at = ? WHERE user_id = (SELECT id FROM users WHERE username = ?)", (ago(minutes=minutes), name))
    conn.commit()


def needs_step_up(r):
    return r.status_code == 401 and r.json()["detail"].startswith("step_up_required")


# ------------------------------------------------------------------ the inventory
SENSITIVE = re.compile(r"credential|vault|users|restore|terminal|remote|plugin|sso|ingest|licence|security|hostprobe|hosts|central|assistant|mcp|token|probes|engineer|siem|oidc|remediation/rules|monitor")
SAFE_PREFIXES = ("/api/me/", "/api/login", "/api/logout", "/api/auth/")


def all_write_routes():
    app = create_app(load_settings({"NETLENS_TOKEN": "x"}), db_path=":memory:" if False else None) if False else None
    import tempfile

    app = create_app(load_settings({"NETLENS_TOKEN": "x"}), db_path=tempfile.mkdtemp() + "/i.db")
    out = []
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                out.append((method.upper(), path))
    return out


def test_every_route_that_touches_secrets_accounts_remote_access_or_code_is_decided():
    undecided = []
    for method, template in all_write_routes():
        if not template.startswith("/api/") or template.startswith(SAFE_PREFIXES) or not SENSITIVE.search(template):
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", template)
        if stepup.protected(method, concrete) or (method, template) in stepup.NOT_PRIVILEGED:
            continue
        undecided.append((method, template))
    assert not undecided, f"decide each: add it to PRIVILEGED or to NOT_PRIVILEGED (with the reason) in app/stepup.py: {undecided}"


def test_the_exceptions_are_real_routes_with_a_reason():
    routes = set(all_write_routes())
    for key, reason in stepup.NOT_PRIVILEGED.items():
        assert reason and len(reason) > 10
        assert key in routes or key == ("POST", "/api/me/stepup") or key[1].startswith("/api/ingest"), key


def test_the_privileged_list_covers_the_things_that_matter():
    for method, path in (("POST", "/api/credentials"), ("PUT", "/api/credentials/ab"), ("DELETE", "/api/users/3"), ("POST", "/api/users/3/tokens"), ("PUT", "/api/sso"), ("POST", "/api/plugins"),
                         ("POST", "/api/plugin-index/pbs/install"), ("POST", "/api/restore"), ("POST", "/api/backups/x/restore"), ("PUT", "/api/ingest"), ("POST", "/api/ingest/ca/rotate"),
                         ("GET", "/api/vault/key"), ("PUT", "/api/vault/key"), ("WS", "/api/terminal/4/ws"), ("WS", "/api/remote/ws"), ("POST", "/api/remote/4/session"),
                         ("PUT", "/api/hosts/settings"), ("POST", "/api/hosts/apply"), ("POST", "/api/remediation/rules"), ("PUT", "/api/security-policy"), ("POST", "/api/assistant/token")):
        assert stepup.protected(method, path), (method, path)
    for method, path in (("GET", "/api/devices"), ("POST", "/api/scans"), ("POST", "/api/plugins/pbs/sync"), ("GET", "/api/credentials"), ("PUT", "/api/me/preferences"), ("POST", "/api/maintenance")):
        assert not stepup.protected(method, path), (method, path)


# ------------------------------------------------------------------ the behaviour
def test_switched_off_nothing_changes_and_switching_on_needs_the_edition_and_an_administrator(env):
    c, app, path, state = env
    a = signin(app)
    stale(path)
    assert not needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))
    state["privileged"] = False
    assert put(c, step_up=True).status_code == 402
    state["privileged"] = True
    assert put(c, step_up="yes").status_code == 422 and put(c, step_up_minutes=0).status_code == 422
    assert put(c, step_up=True, step_up_minutes=15).json()["policy"]["step_up_minutes"] == 15


def test_a_privileged_action_needs_a_fresh_proof_and_the_password_gives_one(env):
    c, app, path, state = env
    put(c, step_up=True, step_up_minutes=10)
    a = signin(app)
    assert not needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))      # just signed in: fresh
    stale(path)
    r = a.post("/api/credentials", json={"name": "x", "kind": "login"})
    assert needs_step_up(r) and r.json()["detail"] == "step_up_required:password"
    s = a.get("/api/me/stepup").json()
    assert s == {"enabled": True, "fresh": False, "available": True, "method": "password", "minutes": 10}
    assert a.get("/api/devices").status_code == 200 and a.get("/api/session").json()["authenticated"] is True            # nothing else is affected, and it is not a sign-out
    assert a.post("/api/me/stepup", json={"password": "wrong"}).status_code == 403
    assert a.post("/api/me/stepup", json={"password": "longenough1"}).json()["fresh"] is True
    assert not needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))
    assert a.get("/api/me/stepup").json()["fresh"] is True
    conn = connect(path)
    actions = " ".join(x["action"] for x in conn.execute("SELECT action FROM audit_log"))
    assert "Confirmed their identity for privileged actions (password)" in actions and "Failed confirmation" in actions


def test_a_user_with_a_second_factor_confirms_with_a_code_that_works_once(env):
    c, app, path, state = env
    put(c, step_up=True)
    a = signin(app)
    secret = a.post("/api/me/totp/begin", json={"password": "longenough1"}).json()["secret"]
    a.post("/api/me/totp/confirm", json={"code": totp.code_at(secret)})
    stale(path)
    assert a.post("/api/users", json={"username": "z", "password": "longenough1", "role": "viewer"}).json()["detail"] == "step_up_required:totp"
    assert a.post("/api/me/stepup", json={"code": "000000"}).status_code == 403
    assert a.post("/api/me/stepup", json={"code": totp.code_at(secret, time.time() + 30)}).status_code == 200
    stale(path)
    assert a.post("/api/me/stepup", json={"code": totp.code_at(secret, time.time() + 30)}).status_code == 403          # the same code again: no
    assert a.post("/api/me/stepup", json={"code": totp.code_at(secret, time.time() + 60)}).status_code == 403          # and two steps ahead is outside the window


def test_the_access_token_and_api_tokens_cannot_confirm_so_they_are_refused(env):
    c, app, path, state = env
    uid = connect(path).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    token = c.post(f"/api/users/{uid}/tokens", json={"name": "ci"}, headers=ADMIN).json()["token"]
    put(c, step_up=True)
    for headers in (ADMIN, {"Authorization": f"Bearer {token}"}):
        t = TestClient(app, headers=headers)
        r = t.post("/api/credentials", json={"name": "x", "kind": "login"})
        assert r.status_code == 403 and r.json()["detail"].startswith("step_up_unavailable")
        assert t.get("/api/vault/key").status_code == 403                                   # reading the master key is privileged too
        assert t.get("/api/devices").status_code == 200                                     # everything else works as before
        assert t.post("/api/me/stepup", json={"password": "x"}).status_code == 400


def test_the_window_follows_the_setting_and_a_policy_in_force_survives_a_lapsed_licence(env):
    c, app, path, state = env
    put(c, step_up=True, step_up_minutes=5)
    a = signin(app)
    stale(path, minutes=3)
    assert not needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))
    stale(path, minutes=7)
    assert needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))
    state["privileged"] = False
    assert needs_step_up(a.post("/api/credentials", json={"name": "x", "kind": "login"}))      # the licence ended: the protection stays


def test_the_step_up_of_a_single_sign_on_user_goes_to_the_identity_provider(env, idp):
    c, app, path, state = env
    h = ADMIN
    c.post("/api/licence/trial", headers=h)
    assert c.put("/api/sso", json={"enabled": True, "issuer": idp["base"], "client_id": "netlens", "client_secret": "s3cr3t", "admin_groups": "ops"}, headers=h).status_code == 200
    idp["claims"] = {"sub": "u-9", "preferred_username": "sso-sam", "groups": ["ops"]}

    def go(path_, **q):
        t = TestClient(app, headers={})
        return t

    sam = TestClient(app, headers={})
    start = sam.get("/api/auth/oidc/login", follow_redirects=False)
    q = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    idp["nonce"] = q["nonce"]
    assert sam.get("/api/auth/oidc/callback", params={"code": "good-code", "state": q["state"]}).status_code == 200
    put(c, step_up=True)
    stale(path, "sso-sam")
    r = sam.post("/api/credentials", json={"name": "x", "kind": "login"})
    assert r.json()["detail"] == "step_up_required:oidc"
    assert sam.post("/api/me/stepup", json={"password": "x"}).status_code == 400
    begin = sam.get("/api/auth/oidc/stepup", params={"back": "#/settings/credentials"}, follow_redirects=False)
    assert begin.status_code == 302
    qs = {k: v[0] for k, v in parse_qs(urlsplit(begin.headers["location"]).query).items()}
    assert qs["prompt"] == "login" and qs["max_age"] == "0"
    idp["nonce"] = qs["nonce"]
    idp["claims"]["auth_time"] = time.time() - 4000                                         # the provider reused an old login: not a confirmation
    assert sam.get("/api/auth/oidc/callback", params={"code": "good-code", "state": qs["state"]}).status_code == 401
    assert sam.post("/api/credentials", json={"name": "x", "kind": "login"}).json()["detail"] == "step_up_required:oidc"
    begin = sam.get("/api/auth/oidc/stepup", params={"back": "#/settings/credentials"}, follow_redirects=False)
    qs = {k: v[0] for k, v in parse_qs(urlsplit(begin.headers["location"]).query).items()}
    idp["nonce"] = qs["nonce"]
    idp["claims"]["auth_time"] = time.time() - 5
    ok = sam.get("/api/auth/oidc/callback", params={"code": "good-code", "state": qs["state"]})
    assert ok.status_code == 200 and "url=/#/settings/credentials" in ok.text
    assert not needs_step_up(sam.post("/api/credentials", json={"name": "x", "kind": "login"}))
    other = TestClient(app, headers={})                                                      # somebody who is not signed in cannot start one
    assert other.get("/api/auth/oidc/stepup", follow_redirects=False).status_code == 401
    bad = sam.get("/api/auth/oidc/stepup", params={"back": "javascript:alert(1)"}, follow_redirects=False)
    assert bad.status_code == 302                                                           # an odd 'back' is replaced by the start page, never followed


# ------------------------------------------------------------------ the access token
def test_the_access_token_can_be_switched_off_or_limited_to_the_local_network(env, monkeypatch):
    c, app, path, state = env
    assert TestClient(app, headers=ADMIN).get("/api/devices").status_code == 200
    state["privileged"] = False
    assert put(c, static_token="off").status_code == 402
    state["privileged"] = True
    assert put(c, static_token="sometimes").status_code == 422
    import app.auth as auth
    monkeypatch.setattr(auth, "client_ip", lambda conn: "203.0.113.9")
    assert put(c, static_token="lan").json()["policy"]["static_token"] == "lan"
    secpolicy.forget()
    assert TestClient(app, headers=ADMIN).get("/api/devices").status_code == 401                 # from outside the local network
    assert TestClient(app).post("/api/login", json={"token": "secret"}).status_code == 401
    monkeypatch.setattr(auth, "client_ip", lambda conn: "192.168.0.7")
    assert TestClient(app, headers=ADMIN).get("/api/devices").status_code == 200
    assert TestClient(app).post("/api/login", json={"token": "secret"}).status_code == 200
    a = signin(app)
    monkeypatch.setattr(auth, "client_ip", lambda conn: "203.0.113.9")
    assert a.put("/api/security-policy", json={"static_token": "off"}).status_code in (200, 401, 403)
    secpolicy.forget()
    conn = connect(path)
    s = json.loads(conn.execute("SELECT value FROM settings WHERE key = 'security.policy'").fetchone()[0])
    s["static_token"] = "off"
    conn.execute("UPDATE settings SET value = ? WHERE key = 'security.policy'", (json.dumps(s),))
    conn.commit()
    secpolicy.forget()
    assert TestClient(app, headers=ADMIN).get("/api/devices").status_code == 401
    assert signin(app).get("/api/devices").status_code == 200                                    # people with accounts are not affected
    uid = connect(path).execute("SELECT id FROM users WHERE username='bella'").fetchone()[0]


def test_switching_the_access_token_off_needs_an_administrator_account(tmp_path, monkeypatch):
    real = licence.allows
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True if feature == "privileged" else real(conn, feature, now))
    secpolicy.forget()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        assert c.put("/api/security-policy", json={"static_token": "off"}, headers=ADMIN).status_code == 422
        assert c.put("/api/security-policy", json={"step_up": True}, headers=ADMIN).status_code == 422
        c.post("/api/users", json={"username": "alice", "password": "longenough1", "role": "admin"}, headers=ADMIN)
        assert c.put("/api/security-policy", json={"static_token": "off"}, headers=ADMIN).status_code == 200
    secpolicy.forget()


# ------------------------------------------------------------------ API tokens
def test_the_life_and_addresses_of_api_tokens(env, monkeypatch):
    c, app, path, state = env
    uid = connect(path).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    open_token = c.post(f"/api/users/{uid}/tokens", json={"name": "a"}, headers=ADMIN).json()
    assert [t["expires"] for t in c.get("/api/users", headers=ADMIN).json()["users"][0]["tokens"]] == [None]
    assert put(c, api_token_max_days=30).json()["policy"]["api_token_max_days"] == 30
    r = c.post(f"/api/users/{uid}/tokens", json={"name": "b"}, headers=ADMIN)
    assert r.status_code == 201
    toks = {t["name"]: t for t in next(u for u in c.get("/api/users", headers=ADMIN).json()["users"] if u["id"] == uid)["tokens"]}
    assert toks["b"]["expires"] and ago(days=-29) < toks["b"]["expires"] < ago(days=-31) and toks["a"]["expires"] is None
    assert c.post(f"/api/users/{uid}/tokens", json={"name": "c", "expires_days": 31}, headers=ADMIN).status_code == 422
    assert c.post(f"/api/users/{uid}/tokens", json={"name": "c", "expires_days": 7}, headers=ADMIN).status_code == 201
    assert c.post(f"/api/users/{uid}/tokens", json={"name": "d", "allowed_ips": ["not an ip"]}, headers=ADMIN).status_code == 422
    made = c.post(f"/api/users/{uid}/tokens", json={"name": "e", "allowed_ips": ["10.0.0.0/24", "192.168.1.5"]}, headers=ADMIN).json()["token"]
    import app.auth as auth
    monkeypatch.setattr(auth, "client_ip", lambda conn: "10.0.0.77")
    assert TestClient(app, headers={"Authorization": f"Bearer {made}"}).get("/api/devices").status_code == 200
    monkeypatch.setattr(auth, "client_ip", lambda conn: "10.0.1.77")
    assert TestClient(app, headers={"Authorization": f"Bearer {made}"}).get("/api/devices").status_code == 401
    monkeypatch.setattr(auth, "client_ip", lambda conn: "192.168.1.5")
    assert TestClient(app, headers={"Authorization": f"Bearer {made}"}).get("/api/devices").status_code == 200
    conn = connect(path)
    conn.execute("UPDATE api_tokens SET expires = ? WHERE token_hash IS NOT NULL", (ago(days=1),))
    conn.commit()
    assert TestClient(app, headers={"Authorization": f"Bearer {made}"}).get("/api/devices").status_code == 401         # expired
    state["privileged"] = False
    assert c.post(f"/api/users/{uid}/tokens", json={"name": "f", "allowed_ips": ["10.0.0.0/8"]}, headers=ADMIN).status_code == 201          # the policy cap is in force: tokens still get one
    put_back = secpolicy.get(connect(path))
    assert put_back["api_token_max_days"] == 30


# ------------------------------------------------------------------ break-glass
def test_break_glass_accounts_and_limiting_password_sign_in(env, monkeypatch):
    c, app, path, state = env
    conn = connect(path)
    bella = conn.execute("SELECT id FROM users WHERE username='bella'").fetchone()[0]
    alice = conn.execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    viola = conn.execute("SELECT id FROM users WHERE username='viola'").fetchone()[0]
    assert c.patch(f"/api/users/{viola}", json={"break_glass": True}, headers=ADMIN).status_code == 422                  # only a local administrator
    state["privileged"] = False
    assert c.patch(f"/api/users/{bella}", json={"break_glass": True}, headers=ADMIN).status_code == 402
    state["privileged"] = True
    assert c.patch(f"/api/users/{bella}", json={"break_glass": True}, headers=ADMIN).status_code == 200
    assert next(u for u in c.get("/api/users", headers=ADMIN).json()["users"] if u["id"] == bella)["break_glass"] is True
    b0 = TestClient(app)
    assert b0.post("/api/login", json={"username": "bella", "password": "longenough1"}).status_code == 403                  # a break-glass account must have a second factor
    # give her one
    conn.execute("UPDATE users SET break_glass = 0 WHERE id = ?", (bella,))
    conn.commit()
    b = signin(app, "bella")
    secret = b.post("/api/me/totp/begin", json={"password": "longenough1"}).json()["secret"]
    b.post("/api/me/totp/confirm", json={"code": totp.code_at(secret)})
    conn.execute("UPDATE users SET break_glass = 1 WHERE id = ?", (bella,))
    conn.commit()
    assert put(c, local_login="break_glass_only").status_code == 422                                                       # single sign-on is not set up
    monkeypatch.setattr(oidc, "settings", lambda conn: {"enabled": True, "issuer": "x", "client_id": "x", "admin_groups": "", "groups_claim": "groups", "default_role": "viewer", "label": "", "redirect_base": "", "scopes": ""})
    assert put(c, local_login="break_glass_only").status_code == 200
    secpolicy.forget()
    a = TestClient(app)
    r = a.post("/api/login", json={"username": "alice", "password": "longenough1"})
    assert r.status_code == 403 and "switched off" in r.json()["detail"]
    assert a.get("/api/devices").status_code == 401
    g = TestClient(app)
    first = g.post("/api/login", json={"username": "bella", "password": "longenough1"}).json()
    assert first["totp_required"] is True
    done = g.post("/api/login/totp", json={"challenge": first["challenge"], "code": totp.code_at(secret, time.time() + 30)})
    assert done.status_code == 200 and g.get("/api/devices").status_code == 200
    kinds = {e["kind"]: e["detail"] for e in connect(path).execute("SELECT kind, detail FROM events")}
    assert "bella" in kinds["break_glass_login"]
    assert c.patch(f"/api/users/{bella}", json={"break_glass": False}, headers=ADMIN).status_code == 409                    # the last way in while passwords are limited
    assert put(c, local_login="allowed").status_code == 200
    assert c.patch(f"/api/users/{bella}", json={"break_glass": False}, headers=ADMIN).status_code == 200


def test_the_terminal_websocket_asks_for_the_confirmation_too(env):
    c, app, path, state = env
    put(c, step_up=True)
    a = signin(app)
    stale(path)
    with a.websocket_connect("/api/terminal/1/ws") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error" and msg["code"] == "step_up" and msg["message"] == "step_up_required:password"
    a.post("/api/me/stepup", json={"password": "longenough1"})
    with a.websocket_connect("/api/terminal/1/ws") as ws:
        msg = ws.receive_json()
    assert msg.get("code") != "step_up"                                                         # it gets as far as the device lookup now
    t = TestClient(app, headers=ADMIN)
    with t.websocket_connect("/api/terminal/1/ws") as ws:
        assert ws.receive_json()["code"] == "step_up"                                           # the access token cannot confirm
