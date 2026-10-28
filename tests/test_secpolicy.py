"""Sign-in security policy: requiring a second factor, the grace period, the restricted state, session limits, and who may see and end sessions."""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import licence, secpolicy, totp, users
from app.config import load_settings
from app.db import connect
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime(STAMP)


@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"mfa_policy": True, "privileged": True, "teams": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        for name, role in (("alice", "admin"), ("olga", "operator"), ("viola", "viewer")):
            assert c.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code in (201, 402), name
        conn = connect(path)
        conn.execute("UPDATE users SET role = 'operator' WHERE username = 'olga'")
        conn.commit()
        conn.close()
        yield c, app, path, state
    secpolicy.forget()


def signin(app, name):
    c = TestClient(app)
    r = c.post("/api/login", json={"username": name, "password": "longenough1"})
    assert r.status_code == 200 and "ok" in r.json(), r.text
    return c


def admin_put(c, **body):
    return c.put("/api/security-policy", json=body, headers=ADMIN)


# ------------------------------------------------------------------ the policy itself
def test_defaults_validation_and_the_audit_line(env):
    c, app, path, state = env
    d = c.get("/api/security-policy", headers=ADMIN).json()
    assert d["policy"]["require_totp"] == "off" and d["policy"]["idle_minutes"] == 0 and d["allowed"] == {"mfa_policy": True, "privileged": True}
    assert admin_put(c, require_totp="sometimes").status_code == 422
    for bad in ({"idle_minutes": -1}, {"idle_minutes": "x"}, {"max_sessions": 999}, {"grace_days": True}, {"absolute_hours": 10_000}):
        assert admin_put(c, **bad).status_code == 422, bad
    r = admin_put(c, require_totp="admins", grace_days=7, idle_minutes=30)
    assert r.status_code == 200 and r.json()["policy"]["require_totp"] == "admins" and r.json()["policy"]["require_since"]
    conn = connect(path)
    assert any("sign-in security policy" in a["action"] and "require_totp: off -> admins" in a["action"] for a in conn.execute("SELECT action FROM audit_log"))
    assert admin_put(c, require_totp="off").json()["policy"]["require_since"] is None


def test_the_editions_gate_changes_and_a_lapsed_licence_never_weakens_the_policy(env):
    c, app, path, state = env
    assert admin_put(c, require_totp="admins", idle_minutes=15, max_sessions=2).status_code == 200
    state.update(mfa_policy=False, privileged=False)
    assert admin_put(c, require_totp="off").status_code == 402 and admin_put(c, idle_minutes=0).status_code == 402 and admin_put(c, max_sessions=5).status_code == 402
    assert admin_put(c, idle_minutes=15).status_code == 200                                     # saving the same value is not a change
    pol = c.get("/api/security-policy", headers=ADMIN).json()
    assert pol["policy"]["require_totp"] == "admins" and pol["policy"]["idle_minutes"] == 15 and pol["allowed"] == {"mfa_policy": False, "privileged": False}
    state.update(mfa_policy=True, privileged=False)
    assert admin_put(c, require_totp="everyone").status_code == 200 and admin_put(c, idle_minutes=20).status_code == 402        # Small business: the policy yes, the session limits no


# ------------------------------------------------------------------ requiring a second factor
def test_the_grace_period_then_the_restricted_state_and_enrolment_lifts_it(env):
    c, app, path, state = env
    admin_put(c, require_totp="admins", grace_days=14)
    a = signin(app, "alice")
    m = a.get("/api/session").json()["user"]["mfa"]
    assert m["required"] and not m["enrolled"] and not m["restricted"] and m["deadline"]
    assert a.get("/api/devices").status_code == 200                                              # still inside the grace period
    conn = connect(path)
    conn.execute("UPDATE users SET created = ? WHERE username = 'alice'", (ago(days=40),))
    conn.commit()
    s = json.loads(conn.execute("SELECT value FROM settings WHERE key = 'security.policy'").fetchone()[0])
    s["require_since"] = ago(days=30)
    conn.execute("UPDATE settings SET value = ? WHERE key = 'security.policy'", (json.dumps(s),))
    conn.commit()
    secpolicy.forget()
    m = a.get("/api/session").json()["user"]["mfa"]
    assert m["restricted"] is True
    for path_ in ("/api/devices", "/api/users", "/api/security-policy", "/api/credentials", "/api/ingest"):
        r = a.get(path_)
        assert r.status_code == 403 and r.json()["detail"] == "mfa_enrolment_required", path_
    assert a.put("/api/security-policy", json={"require_totp": "off"}).status_code == 403          # a restricted administrator administers nothing
    assert a.get("/api/me/totp").status_code == 200
    secret = a.post("/api/me/totp/begin", json={"password": "longenough1"}).json()["secret"]
    assert a.post("/api/me/totp/confirm", json={"code": totp.code_at(secret)}).status_code == 200
    assert a.get("/api/devices").status_code == 200 and a.get("/api/session").json()["user"]["mfa"]["restricted"] is False


def test_who_the_policy_applies_to(env):
    c, app, path, state = env
    conn = connect(path)
    for name in ("alice", "olga", "viola"):
        conn.execute("UPDATE users SET created = ? WHERE username = ?", (ago(days=90), name))
    conn.commit()
    def restricted(mode):
        admin_put(c, require_totp=mode, grace_days=0)
        conn.execute("UPDATE settings SET value = replace(value, '\"require_since\": \"', '\"require_since\": \"2020-01-01T00:00:00Z\", \"x\": \"') WHERE key = 'security.policy'") if False else None
        s = json.loads(conn.execute("SELECT value FROM settings WHERE key = 'security.policy'").fetchone()[0])
        s["require_since"] = ago(days=100)
        conn.execute("UPDATE settings SET value = ? WHERE key = 'security.policy'", (json.dumps(s),))
        conn.commit()
        secpolicy.forget()
        return {n: signin(app, n).get("/api/session").json()["user"].get("mfa", {}).get("restricted", False) for n in ("alice", "olga", "viola")}
    assert restricted("admins") == {"alice": True, "olga": False, "viola": False}
    assert restricted("operators") == {"alice": True, "olga": True, "viola": False}
    assert restricted("everyone") == {"alice": True, "olga": True, "viola": True}
    assert restricted("off") == {"alice": False, "olga": False, "viola": False}


def test_single_sign_on_users_and_api_tokens_are_not_asked_for_a_second_factor(env):
    c, app, path, state = env
    conn = connect(path)
    conn.execute("UPDATE users SET created = ?, oidc_sub = 'idp-1' WHERE username = 'alice'", (ago(days=90),))
    conn.commit()
    admin_put(c, require_totp="everyone", grace_days=0)
    s = json.loads(conn.execute("SELECT value FROM settings WHERE key = 'security.policy'").fetchone()[0])
    s["require_since"] = ago(days=100)
    conn.execute("UPDATE settings SET value = ? WHERE key = 'security.policy'", (json.dumps(s),))
    conn.commit()
    secpolicy.forget()
    a = signin(app, "alice")
    assert a.get("/api/devices").status_code == 200                                                  # the identity provider does the second factor
    uid = conn.execute("SELECT id FROM users WHERE username = 'olga'").fetchone()[0]
    token = c.post(f"/api/users/{uid}/tokens", json={"name": "ha", "readonly": True}, headers=ADMIN).json()["token"]
    assert TestClient(app).get("/api/devices", headers={"Authorization": f"Bearer {token}"}).status_code == 200      # a token is not interactive


def test_the_restriction_follows_the_policy_off_and_never_touches_the_access_token(env):
    c, app, path, state = env
    admin_put(c, require_totp="admins")
    assert c.get("/api/devices", headers=ADMIN).status_code == 200                                    # the access token has no second factor and is not asked for one


# ------------------------------------------------------------------ session limits
def test_idle_and_absolute_limits_and_the_one_minute_write(env):
    c, app, path, state = env
    admin_put(c, idle_minutes=30, absolute_hours=2)
    a = signin(app, "alice")
    conn = connect(path)
    before = conn.execute("SELECT last_seen FROM sessions WHERE user_id = (SELECT id FROM users WHERE username='alice')").fetchone()[0]
    assert a.get("/api/devices").status_code == 200
    assert conn.execute("SELECT last_seen FROM sessions WHERE user_id = (SELECT id FROM users WHERE username='alice')").fetchone()[0] == before            # within a minute: not written again
    conn.execute("UPDATE sessions SET last_seen = ? WHERE user_id = (SELECT id FROM users WHERE username='alice')", (ago(minutes=45),))
    conn.commit()
    assert a.get("/api/devices").status_code == 401                                                  # idle for 45 minutes
    b = signin(app, "alice")
    conn.execute("UPDATE sessions SET created = ?, last_seen = ? WHERE user_id = (SELECT id FROM users WHERE username='alice')", (ago(hours=3), ago(seconds=5)))
    conn.commit()
    assert b.get("/api/devices").status_code == 401                                                  # three hours since signing in, whatever the activity
    d = signin(app, "alice")
    conn.execute("UPDATE sessions SET last_seen = ? WHERE user_id = (SELECT id FROM users WHERE username='alice')", (ago(minutes=5),))
    conn.commit()
    assert d.get("/api/devices").status_code == 200
    assert conn.execute("SELECT last_seen FROM sessions WHERE user_id = (SELECT id FROM users WHERE username='alice')").fetchone()[0] > ago(minutes=1)


def test_the_newest_sessions_stay_when_the_number_is_limited(env):
    c, app, path, state = env
    admin_put(c, max_sessions=2)
    first = signin(app, "viola")
    second = signin(app, "viola")
    third = signin(app, "viola")
    assert first.get("/api/devices").status_code == 401 and second.get("/api/devices").status_code == 200 and third.get("/api/devices").status_code == 200


def test_a_user_sees_and_ends_their_own_sessions_but_never_the_secret(env):
    c, app, path, state = env
    state.update(mfa_policy=False, privileged=False)                                                         # free edition: your own sessions are not a paid feature
    one, two = signin(app, "viola"), signin(app, "viola")
    s = two.get("/api/me/sessions").json()["sessions"]
    assert len(s) == 2 and sum(x["current"] for x in s) == 1 and all(len(x["id"]) == 16 and x["method"] == "password" for x in s)
    cookie = two.cookies.get("netlens_session")
    assert cookie not in json.dumps(s) and cookie.split(".")[-1] not in json.dumps(s)
    other = next(x for x in s if not x["current"])["id"]
    assert two.post("/api/me/sessions/end", json={"id": next(x for x in s if x["current"])["id"]}).json()["ended"] == 0         # the session in use is not ended this way
    assert two.post("/api/me/sessions/end", json={"id": other}).json()["ended"] == 1 and one.get("/api/devices").status_code == 401
    three = signin(app, "viola")
    assert two.post("/api/me/sessions/revoke-others").json()["ended"] == 1 and three.get("/api/devices").status_code == 401 and two.get("/api/devices").status_code == 200
    assert TestClient(app, headers=ADMIN).get("/api/me/sessions").status_code == 400                   # the access token has no sessions


def test_an_administrator_ends_other_peoples_sessions_with_the_enterprise_edition(env):
    c, app, path, state = env
    v = signin(app, "viola")
    uid = connect(path).execute("SELECT id FROM users WHERE username='viola'").fetchone()[0]
    a = signin(app, "alice")
    assert len(a.get(f"/api/users/{uid}/sessions").json()["sessions"]) == 1
    assert v.get("/api/users/%d/sessions" % uid).status_code == 403                                   # a viewer may not
    state["privileged"] = False
    assert a.get(f"/api/users/{uid}/sessions").status_code == 402 and a.post(f"/api/users/{uid}/sessions/end", json={}).status_code == 402
    state["privileged"] = True
    assert a.post(f"/api/users/{uid}/sessions/end", json={}).json()["ended"] == 1 and v.get("/api/devices").status_code == 401


# ------------------------------------------------------------------ resetting somebody's second factor
def enrol(app, name):
    c = signin(app, name)
    secret = c.post("/api/me/totp/begin", json={"password": "longenough1"}).json()["secret"]
    c.post("/api/me/totp/confirm", json={"code": totp.code_at(secret)})
    return c, secret


def test_an_administrator_resets_a_second_factor_after_proving_who_they_are(env):
    c, app, path, state = env
    v, secret = enrol(app, "viola")
    uid = connect(path).execute("SELECT id FROM users WHERE username='viola'").fetchone()[0]
    a = signin(app, "alice")                                                                           # an administrator without a factor: the password proves it
    assert a.post(f"/api/users/{uid}/totp/reset", json={"password": "wrong"}).status_code == 403
    assert TestClient(app, headers=ADMIN).post(f"/api/users/{uid}/totp/reset", json={"password": "x"}).status_code == 400             # the access token cannot prove who it is
    assert v.post(f"/api/users/{uid}/totp/reset", json={"password": "longenough1"}).status_code == 403                                  # a viewer may not
    assert a.post("/api/users/%d/totp/reset" % connect(path).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0], json={"password": "longenough1"}).status_code == 400   # not your own
    state["mfa_policy"] = False
    assert a.post(f"/api/users/{uid}/totp/reset", json={"password": "longenough1"}).status_code == 402
    state["mfa_policy"] = True
    assert a.post(f"/api/users/{uid}/totp/reset", json={"password": "longenough1"}).json() == {"reset": True}
    assert v.get("/api/devices").status_code == 401                                                    # their sessions ended
    assert TestClient(app).post("/api/login", json={"username": "viola", "password": "longenough1"}).json() == {"ok": True}
    conn = connect(path)
    assert any(e["kind"] == "totp_reset" and "viola" in e["detail"] and "alice" in e["detail"] for e in conn.execute("SELECT kind, detail FROM events"))
    assert any("Reset the second factor of viola" in x["action"] for x in conn.execute("SELECT action FROM audit_log"))
    a2, secret_a = enrol(app, "alice")                                                                 # now the administrator has a factor: a code is needed
    b, secret_b = enrol(app, "olga")
    uid_b = connect(path).execute("SELECT id FROM users WHERE username='olga'").fetchone()[0]
    assert a2.post(f"/api/users/{uid_b}/totp/reset", json={"password": "longenough1"}).status_code == 403                 # the password is not enough any more
    assert a2.post(f"/api/users/{uid_b}/totp/reset", json={"code": totp.code_at(secret_a, time.time() + 30)}).status_code == 200
