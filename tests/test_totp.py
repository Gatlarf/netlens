"""The second factor (TOTP): the algorithm against the RFC vectors, the one-use rules, and the two-step sign-in."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from app import totp, users
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}
RFC_KEY = b"12345678901234567890"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # the same key in base32


# ------------------------------------------------------------------ the algorithm
@pytest.mark.parametrize("when,expected", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_rfc_6238_vectors(when, expected):
    assert totp.hotp(RFC_KEY, when // 30, 8) == expected                                  # the published SHA-1 vectors
    assert totp.code_at(RFC_SECRET, when) == expected[-6:]                                 # the 6-digit code is the last six digits


def test_rfc_4226_vectors():
    assert [totp.hotp(RFC_KEY, i) for i in range(4)] == ["755224", "287082", "359152", "969429"]


def test_verify_window_replay_and_format():
    now = 1_700_000_000
    code = totp.code_at(RFC_SECRET, now)
    c = totp.counter_at(now)
    assert totp.verify(RFC_SECRET, code, 0, now) == c
    assert totp.verify(RFC_SECRET, code, 0, now + 30) == c and totp.verify(RFC_SECRET, code, 0, now - 30) == c      # a phone clock one step off
    assert totp.verify(RFC_SECRET, code, 0, now + 90) is None                                                       # two steps: too far
    assert totp.verify(RFC_SECRET, code, c, now) is None                                                             # used already
    assert totp.verify(RFC_SECRET, code[:5], 0, now) is None and totp.verify(RFC_SECRET, "abcdef", 0, now) is None and totp.verify(RFC_SECRET, "", 0, now) is None
    assert totp.verify(RFC_SECRET, code[:3] + " " + code[3:], 0, now) == c                                           # the grouping some apps show
    secret = totp.new_secret()
    assert len(secret) == 32 and secret.isalnum() and totp.new_secret() != secret
    assert totp.otpauth_uri(secret, "alice", "Netlens").startswith("otpauth://totp/Netlens%3Aalice?secret=" + secret)


# ------------------------------------------------------------------ the app
@pytest.fixture
def env(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        for name, role in (("alice", "admin"), ("viola", "viewer")):
            assert c.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code == 201
        yield app, path


def user_client(app, name="alice", password="longenough1"):
    c = TestClient(app)
    assert c.post("/api/login", json={"username": name, "password": password}).status_code == 200
    return c


def enrol(app, name="alice", password="longenough1"):
    """(client, secret, recovery codes) for a user whose second factor is on."""
    c = user_client(app, name, password)
    r = c.post("/api/me/totp/begin", json={"password": password})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    codes = c.post("/api/me/totp/confirm", json={"code": totp.code_at(secret)})
    assert codes.status_code == 200, codes.text
    return c, secret, codes.json()["recovery_codes"]


def password_step(app, name="alice", password="longenough1"):
    c = TestClient(app)
    r = c.post("/api/login", json={"username": name, "password": password})
    return c, r


def test_enrolment_confirms_with_a_code_and_the_secret_is_encrypted(env):
    app, path = env
    c = user_client(app)
    assert c.get("/api/me/totp").json() == {"enabled": False, "since": None, "recovery_left": 0, "pending": False}
    assert c.post("/api/me/totp/begin", json={"password": "wrong"}).status_code == 403
    r = c.post("/api/me/totp/begin", json={"password": "longenough1"}).json()
    assert r["uri"].startswith("otpauth://totp/") and c.get("/api/me/totp").json()["pending"] is True and not c.get("/api/me/totp").json()["enabled"]
    assert c.post("/api/me/totp/confirm", json={"code": "000000"}).status_code == 422
    assert c.get("/api/me/totp").json()["enabled"] is False                                     # a wrong code does not switch it on
    codes = c.post("/api/me/totp/confirm", json={"code": totp.code_at(r["secret"])}).json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(x.replace("-", "")) == 16 for x in codes)
    st = c.get("/api/me/totp").json()
    assert st["enabled"] and st["recovery_left"] == 10 and st["since"]
    conn = connect(path)
    raw = conn.execute("SELECT totp_secret FROM users WHERE username = 'alice'").fetchone()[0]
    assert raw.startswith("enc:v1:") and r["secret"] not in raw                                   # encrypted at rest
    hashes = " ".join(x[0] for x in conn.execute("SELECT code_hash FROM user_recovery_codes"))
    assert not any(code.replace("-", "") in hashes for code in codes)                              # recovery codes only as hashes
    assert c.post("/api/me/totp/begin", json={"password": "longenough1"}).status_code == 409        # already on
    assert c.get("/api/me/totp").status_code == 200


def test_the_password_alone_gives_no_session_once_the_factor_is_on(env):
    app, path = env
    enrol(app)
    anon, r = password_step(app)
    body = r.json()
    assert r.status_code == 200 and body["totp_required"] is True and "ok" not in body and not anon.cookies.get("netlens_session")
    assert anon.get("/api/devices").status_code == 401 and anon.get("/api/session").json()["authenticated"] is False
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id = (SELECT id FROM users WHERE username='alice')").fetchone()[0] == 1       # only the enrolment session
    assert users.login(conn, "alice", "longenough1") is None                                         # no caller can skip the second factor by accident


def test_the_code_completes_the_sign_in_and_a_code_works_once(env):
    app, path = env
    c0, secret, _ = enrol(app)
    c, r = password_step(app)
    code = totp.code_at(secret, time.time() + 30)                                                    # the next step: newer than the one used to enrol
    ok = c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": code})
    assert ok.status_code == 200 and c.get("/api/session").json()["authenticated"] is True
    again, r2 = password_step(app)
    replay = again.post("/api/login/totp", json={"challenge": r2.json()["challenge"], "code": code})
    assert replay.status_code == 401 and again.get("/api/session").json()["authenticated"] is False  # the same code a second time
    assert c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": code}).status_code == 401            # and the challenge is gone


def test_five_wrong_codes_end_the_challenge_and_the_address_is_limited(env):
    app, path = env
    _c, secret, _ = enrol(app)
    c, r = password_step(app)
    ch = r.json()["challenge"]
    codes = [c.post("/api/login/totp", json={"challenge": ch, "code": "000000"}).status_code for _ in range(5)]
    assert codes == [401] * 5
    good = totp.code_at(secret, time.time() + 30)
    assert c.post("/api/login/totp", json={"challenge": ch, "code": good}).status_code in (401, 429)          # ended: the right code no longer helps
    assert c.get("/api/session").json()["authenticated"] is False
    c2, r2 = password_step(app)
    assert r2.status_code == 429 or c2.post("/api/login/totp", json={"challenge": r2.json().get("challenge", "x"), "code": good}).status_code == 429      # the address is blocked for a minute


def test_a_correct_password_does_not_reset_the_failures_of_the_second_step(env):
    app, path = env
    _c, secret, _ = enrol(app)
    for _ in range(4):
        c, r = password_step(app)
        assert c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": "111111"}).status_code == 401
    c, r = password_step(app)
    assert c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": "111111"}).status_code == 401         # the fifth failure
    c, r = password_step(app)
    assert r.status_code == 429                                                                       # cycling the password did not give a fresh budget


def test_an_expired_or_invented_challenge_is_refused(env, monkeypatch):
    app, path = env
    _c, secret, _ = enrol(app)
    c, r = password_step(app)
    assert c.post("/api/login/totp", json={"challenge": "invented", "code": "123456"}).status_code == 401
    ch = r.json()["challenge"]
    real = time.time
    monkeypatch.setattr(totp.time, "time", lambda: real() + 400)                                      # more than five minutes later
    assert c.post("/api/login/totp", json={"challenge": ch, "code": totp.code_at(secret, real() + 430)}).status_code == 401


def test_recovery_codes_work_once_and_raise_an_event(env):
    app, path = env
    _c, secret, recovery = enrol(app)
    c, r = password_step(app)
    ok = c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": recovery[0].upper()})
    assert ok.status_code == 200 and c.get("/api/session").json()["authenticated"] is True
    conn = connect(path)
    assert any(e["kind"] == "totp_recovery_used" and "9 left" in e["detail"] for e in conn.execute("SELECT kind, detail FROM events"))
    c2, r2 = password_step(app)
    assert c2.post("/api/login/totp", json={"challenge": r2.json()["challenge"], "code": recovery[0]}).status_code == 401           # used
    assert c.get("/api/me/totp").json()["recovery_left"] == 9


def test_removing_the_factor_and_new_recovery_codes_need_the_password_and_a_code(env):
    app, path = env
    c, secret, recovery = enrol(app)
    good = totp.code_at(secret, time.time() + 30)
    assert c.post("/api/me/totp/disable", json={"password": "wrong", "code": good}).status_code == 403
    assert c.post("/api/me/totp/disable", json={"password": "longenough1", "code": "000000"}).status_code == 403
    new = c.post("/api/me/totp/recovery", json={"password": "longenough1", "code": good})
    assert new.status_code == 200 and len(new.json()["recovery_codes"]) == 10
    d, r = password_step(app)
    assert d.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": recovery[1]}).status_code == 401             # the old set is dead
    nxt = new.json()["recovery_codes"][0]                                   # a time-step code would have to wait for the next 30 seconds; a recovery code may confirm the removal
    assert c.post("/api/me/totp/disable", json={"password": "longenough1", "code": nxt}).json() == {"enabled": False}
    conn = connect(path)
    assert conn.execute("SELECT totp_secret, totp_enabled FROM users WHERE username='alice'").fetchone()[:] == (None, 0)
    assert conn.execute("SELECT COUNT(*) FROM user_recovery_codes").fetchone()[0] == 0
    assert TestClient(app).post("/api/login", json={"username": "alice", "password": "longenough1"}).json() == {"ok": True}      # a plain sign-in again


def test_a_viewer_can_set_up_a_second_factor_and_tokens_and_assistants_cannot(env):
    app, path = env
    v, secret, _ = enrol(app, "viola")
    assert v.get("/api/me/totp").json()["enabled"] is True
    builtin = TestClient(app, headers=ADMIN)
    assert builtin.get("/api/me/totp").status_code == 400 and builtin.post("/api/me/totp/begin", json={"password": "x"}).status_code == 400
    anon = TestClient(app)
    assert anon.get("/api/me/totp").status_code == 401


def test_a_disabled_user_cannot_finish_the_sign_in_and_changing_the_password_keeps_the_browser_signed_in(env):
    app, path = env
    c0, secret, _ = enrol(app, "viola")
    c, r = password_step(app, "viola")
    conn = connect(path)
    conn.execute("UPDATE users SET disabled = 1 WHERE username = 'viola'")
    conn.commit()
    assert c.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": totp.code_at(secret, time.time() + 30)}).status_code == 401
    conn.execute("UPDATE users SET disabled = 0 WHERE username = 'viola'")
    conn.commit()
    c2, r2 = password_step(app, "viola")
    ok = c2.post("/api/login/totp", json={"challenge": r2.json()["challenge"], "code": totp.code_at(secret, time.time() + 30)})      # the code was not used up by the refused attempt
    assert ok.status_code == 200
    assert c2.post("/api/me/password", json={"current": "longenough1", "new": "another-longer-1"}).status_code == 200
    assert c2.get("/api/session").json()["authenticated"] is True                                      # still signed in (and still has the factor)
    assert TestClient(app).post("/api/login", json={"username": "viola", "password": "another-longer-1"}).json()["totp_required"] is True


def test_the_console_reset_and_the_user_list(env):
    app, path = env
    enrol(app)
    users_list = TestClient(app, headers=ADMIN).get("/api/users").json()["users"]
    assert {u["username"]: u["totp"] for u in users_list} == {"alice": True, "viola": False}
    from app import cli
    assert cli.run(["--db", str(path), "reset-totp", "alice"]) == 0
    anon, r = password_step(app)
    assert r.json() == {"ok": True}
    assert cli.run(["--db", str(path), "reset-totp", "alice"]) == 0                                    # harmless when it is off already
    with pytest.raises(SystemExit):
        cli.run(["--db", str(path), "reset-totp", "nobody"])


def test_the_log_never_holds_a_code_a_secret_or_a_password(env):
    app, path = env
    c, secret, recovery = enrol(app)
    d, r = password_step(app)
    d.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": "123456"})
    d.post("/api/login/totp", json={"challenge": r.json()["challenge"], "code": recovery[0]})
    conn = connect(path)
    dump = json.dumps([dict(x) for x in conn.execute("SELECT * FROM audit_log")] + [dict(x) for x in conn.execute("SELECT * FROM events")])
    for secretish in (secret, recovery[0], recovery[0].replace("-", ""), "longenough1", "123456", r.json()["challenge"]):
        assert secretish not in dump, secretish
    assert "Signed in (recovery code)" in dump and "Switched on the second factor" in dump and "Wrong second-factor code" in dump
