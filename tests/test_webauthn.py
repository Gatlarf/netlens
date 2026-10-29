"""Security keys and passkeys: the verification (every way it can go wrong), and the sign-in, step-up, recovery and reset flows through the API."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app import licence, secpolicy, webauthn
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from tests.webauthn_helpers import Authenticator, cbor

RP, ORIGIN = "netlens.example.com", "https://netlens.example.com"
ADMIN = {"Authorization": "Bearer secret"}


def register(auth, rp=RP, origin=ORIGIN, **kw):
    challenge = webauthn.b64e(b"c" * 32)
    return challenge, webauthn.verify_registration(auth.create(challenge, rp, origin, **kw), challenge, rp, origin)


# ------------------------------------------------------------------ the library
def test_cbor_round_trip_and_limits():
    value = {"a": [1, -5, b"xy", "text", True, None], 3: {1: 2}}
    assert webauthn.cbor_decode(cbor(value))[0] == value
    for bad in (b"", b"\x1f", b"\x5f", b"\xa1", b"\x58", b"\x99\xff\xff", b"\xff"):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.cbor_decode(bad)
    nested = b"\x81" * 20 + b"\x01"
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.cbor_decode(nested)


@pytest.mark.parametrize("kind", ["es256", "rs256", "ed25519"])
def test_registration_and_sign_in_with_every_supported_key_type(kind):
    auth = Authenticator(kind)
    _, verified = register(auth)
    row = {"id": 1, "credential_id": verified["credential_id"], "public_key": verified["public_key"], "sign_count": 0}
    challenge = webauthn.b64e(b"d" * 32)
    key, counter = webauthn.verify_assertion(auth.get(challenge, RP, ORIGIN), [row], challenge, RP, ORIGIN)
    assert key["id"] == 1 and counter == 1


@pytest.mark.parametrize("kw,text", [({"bad_rp": True}, "another site"), ({"flags": 0}, "not touched"), ({"cred_type": "webauthn.get"}, "something else"),
                                    ({"cross_origin": True}, "inside another page")])
def test_a_registration_that_is_not_right_is_refused(kw, text):
    with pytest.raises(webauthn.WebAuthnError, match=text):
        register(Authenticator(), **kw)


def test_registration_checks_challenge_origin_and_key_type():
    auth = Authenticator()
    response = auth.create(webauthn.b64e(b"c" * 32), RP, ORIGIN)
    with pytest.raises(webauthn.WebAuthnError, match="does not match this request"):
        webauthn.verify_registration(response, webauthn.b64e(b"x" * 32), RP, ORIGIN)
    with pytest.raises(webauthn.WebAuthnError, match="another site"):
        webauthn.verify_registration(response, webauthn.b64e(b"c" * 32), RP, "https://evil.example")
    weird = auth.create(webauthn.b64e(b"c" * 32), RP, ORIGIN)
    att = webauthn.cbor_decode(webauthn.b64d(weird["response"]["attestationObject"]))[0]
    data = att["authData"]
    att["authData"] = data[:-len(auth.cose)] + cbor({1: 2, 3: -36, -1: 2, -2: b"x" * 66, -3: b"y" * 66})          # ES512: not supported
    weird["response"]["attestationObject"] = webauthn.b64e(cbor(att))
    with pytest.raises(webauthn.WebAuthnError, match="not supported"):
        webauthn.verify_registration(weird, webauthn.b64e(b"c" * 32), RP, ORIGIN)


def keyrow(auth, count=0):
    _, v = register(auth)
    return {"id": 1, "credential_id": v["credential_id"], "public_key": v["public_key"], "sign_count": count}


@pytest.mark.parametrize("kw,text", [({"tamper": True}, "signature is not valid"), ({"bad_rp": True}, "another site"), ({"flags": 0}, "not touched"),
                                    ({"cred_type": "webauthn.create"}, "something else")])
def test_an_assertion_that_is_not_right_is_refused(kw, text):
    auth = Authenticator()
    row = keyrow(auth)
    challenge = webauthn.b64e(b"e" * 32)
    with pytest.raises(webauthn.WebAuthnError, match=text):
        webauthn.verify_assertion(auth.get(challenge, RP, ORIGIN, **kw), [row], challenge, RP, ORIGIN)


def test_assertions_are_bound_to_challenge_origin_key_and_counter():
    auth, other = Authenticator(), Authenticator()
    row = keyrow(auth)
    challenge = webauthn.b64e(b"e" * 32)
    good = auth.get(challenge, RP, ORIGIN)
    with pytest.raises(webauthn.WebAuthnError, match="does not match this request"):
        webauthn.verify_assertion(good, [row], webauthn.b64e(b"z" * 32), RP, ORIGIN)
    with pytest.raises(webauthn.WebAuthnError, match="another site"):
        webauthn.verify_assertion(good, [row], challenge, RP, "https://phish.example")
    with pytest.raises(webauthn.WebAuthnError, match="not set up for this account"):
        webauthn.verify_assertion(other.get(challenge, RP, ORIGIN), [row], challenge, RP, ORIGIN)
    imposter = Authenticator()
    imposter.credential_id = auth.credential_id                                         # same id, another private key
    with pytest.raises(webauthn.WebAuthnError, match="signature is not valid"):
        webauthn.verify_assertion(imposter.get(challenge, RP, ORIGIN), [row], challenge, RP, ORIGIN)
    stale = dict(row, sign_count=5)
    with pytest.raises(webauthn.WebAuthnError, match="counter went backwards"):
        webauthn.verify_assertion(auth.get(challenge, RP, ORIGIN), [stale], challenge, RP, ORIGIN)           # counter 1 after 5
    zero = Authenticator()
    zrow = keyrow(zero)
    assert webauthn.verify_assertion(zero.get(challenge, RP, ORIGIN, bump=False), [zrow], challenge, RP, ORIGIN)[1] == 0      # authenticators that always say 0 are fine


def test_challenges_are_single_use_expire_and_belong_to_one_purpose():
    c = webauthn.Challenges()
    ch = c.issue("k", 1, "login", now=1000)
    assert c.take("k", 1, "login", now=1001) == ch
    with pytest.raises(webauthn.WebAuthnError):
        c.take("k", 1, "login", now=1002)                                              # used
    c.issue("k", 1, "login", now=1000)
    with pytest.raises(webauthn.WebAuthnError):
        c.take("k", 2, "login", now=1001)                                              # another user
    c.issue("k", 1, "login", now=1000)
    with pytest.raises(webauthn.WebAuthnError):
        c.take("k", 1, "step", now=1001)                                               # another purpose
    c.issue("k", 1, "login", now=1000)
    with pytest.raises(webauthn.WebAuthnError):
        c.take("k", 1, "login", now=1000 + webauthn.CHALLENGE_SECONDS + 1)             # too old


@pytest.mark.parametrize("host,origin,ok", [("netlens.example.com", "https://netlens.example.com", True), ("netlens.example.com:8443", "https://netlens.example.com:8443", True),
                                            ("localhost:8080", "http://localhost:8080", True), ("netlens.example.com", "http://netlens.example.com", False),
                                            ("netlens.example.com", "https://evil.example", False), ("netlens.example.com", None, False), ("192.168.0.5", "http://192.168.0.5", False)])
def test_the_relying_party_comes_from_the_request_and_needs_https(host, origin, ok):
    if ok:
        assert webauthn.rp_for(host, origin)[0] == host.split(":")[0]
    else:
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.rp_for(host, origin)


# ------------------------------------------------------------------ the flows
@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "mfa_policy": True, "teams": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, base_url=ORIGIN) as admin:
        for name, role in (("alice", "admin"), ("bella", "admin")):
            assert admin.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code in (201, 402)
        yield app, path, state, admin
    secpolicy.forget()


def client(app):
    c = TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
    return c


def login_password(app, name="alice"):
    c = client(app)
    r = c.post("/api/login", json={"username": name, "password": "longenough1"})
    assert r.status_code == 200, r.text
    return c, r.json()


def add_key(c, auth=None, name="My key"):
    auth = auth or Authenticator()
    options = c.post("/api/me/webauthn/begin", json={"password": "longenough1"}).json()
    assert options["rp"]["id"] == RP and options["attestation"] == "none" and options["pubKeyCredParams"]
    r = c.post("/api/me/webauthn/finish", json={"credential": auth.create(options["challenge"], RP, ORIGIN), "name": name})
    assert r.status_code == 200, r.text
    return auth, r.json()


def test_adding_a_key_gives_recovery_codes_and_switches_the_factor_on(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, done = add_key(c)
    assert len(done["recovery_codes"]) == 10 and done["keys"][0]["name"] == "My key"
    second = Authenticator()
    _, more = add_key(c, second, "Backup key")
    assert len(more["keys"]) == 2 and more["recovery_codes"] == []                       # recovery codes only come with the first factor
    listing = c.get("/api/me/webauthn").json()
    assert [k["name"] for k in listing["keys"]] == ["My key", "Backup key"] and "public_key" not in json.dumps(listing)
    conn = connect(path)
    assert conn.execute("SELECT webauthn_enabled FROM users WHERE username = 'alice'").fetchone()[0] == 1
    stored = conn.execute("SELECT public_key, credential_id FROM user_webauthn").fetchall()
    assert len(stored) == 2 and all(len(r["public_key"]) < 200 for r in stored)


def test_a_wrong_password_a_replay_and_a_foreign_page_cannot_add_a_key(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    assert c.post("/api/me/webauthn/begin", json={"password": "nope"}).status_code == 403
    options = c.post("/api/me/webauthn/begin", json={"password": "longenough1"}).json()
    auth = Authenticator()
    cred = auth.create(options["challenge"], RP, ORIGIN)
    assert c.post("/api/me/webauthn/finish", json={"credential": cred}, headers={"Origin": "http://evil.example"}).status_code == 400
    options = c.post("/api/me/webauthn/begin", json={"password": "longenough1"}).json()
    cred = auth.create(options["challenge"], RP, ORIGIN)
    assert c.post("/api/me/webauthn/finish", json={"credential": cred}).status_code == 200
    assert c.post("/api/me/webauthn/finish", json={"credential": cred}).status_code == 422          # the challenge was used
    options = c.post("/api/me/webauthn/begin", json={"password": "longenough1"}).json()
    assert c.post("/api/me/webauthn/finish", json={"credential": auth.create(options["challenge"], RP, ORIGIN)}).status_code == 422      # the same key twice
    assert c.post("/api/me/webauthn/finish", json={"credential": cred}, headers={"Origin": "http://evil.example"}).status_code in (400, 422)


def test_the_second_step_of_a_sign_in_with_a_key(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, _ = add_key(c)
    fresh = client(app)
    first = fresh.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    assert first["totp_required"] and first["methods"] == {"totp": False, "webauthn": True} and first["webauthn"]["rpId"] == RP
    assert first["webauthn"]["allowCredentials"][0]["id"] == webauthn.b64e(auth.credential_id)
    assert fresh.get("/api/session").json().get("user") is None                          # the password alone made no session
    bad = auth.get(first["webauthn"]["challenge"], RP, ORIGIN, tamper=True)
    assert fresh.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": bad}).status_code == 401
    retry = fresh.post("/api/login/webauthn/options", json={"challenge": first["challenge"]}).json()          # the failed try used up the key's challenge: ask for a new one
    assert retry["challenge"] != first["webauthn"]["challenge"] and retry["rpId"] == RP
    good = auth.get(retry["challenge"], RP, ORIGIN)
    ok = fresh.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": good})
    assert ok.status_code == 200 and fresh.get("/api/session").json()["user"]["username"] == "alice"


def test_a_key_signs_in_once_and_the_assertion_cannot_be_replayed(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, _ = add_key(c)
    one = client(app)
    first = one.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    assertion = auth.get(first["webauthn"]["challenge"], RP, ORIGIN)
    r = one.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": assertion})
    assert r.status_code == 200 and one.get("/api/session").json()["user"]["username"] == "alice"
    two = client(app)
    second = two.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    replay = two.post("/api/login/webauthn", json={"challenge": second["challenge"], "credential": assertion})
    assert replay.status_code == 401                                                       # the old answer is for the old challenge
    conn = connect(path)
    assert conn.execute("SELECT auth_method FROM sessions ORDER BY seq DESC LIMIT 1").fetchone()[0] == "webauthn"
    assert conn.execute("SELECT sign_count, last_used FROM user_webauthn").fetchone()["sign_count"] == 1


def test_five_wrong_answers_end_the_sign_in_and_a_key_of_another_user_is_refused(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, _ = add_key(c)
    b, _ = login_password(app, "bella")
    bella_key, _ = add_key(b)
    victim = client(app)
    first = victim.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    wrong = bella_key.get(first["webauthn"]["challenge"], RP, ORIGIN)
    r = victim.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": wrong})
    assert r.status_code == 401 and "not set up for this account" in r.json()["detail"]
    for _ in range(4):
        r = victim.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": wrong})
    assert r.status_code == 401 and "ended" in r.json()["detail"]
    assert victim.post("/api/login/webauthn/options", json={"challenge": first["challenge"]}).status_code == 401          # nothing more can be asked of an ended sign-in


def test_a_user_with_only_keys_can_use_a_recovery_code_and_a_removed_key_stops_working(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, done = add_key(c)
    code = done["recovery_codes"][0]
    r = client(app)
    first = r.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    ok = r.post("/api/login/totp", json={"challenge": first["challenge"], "code": code})
    assert ok.status_code == 200
    again = client(app)
    f2 = again.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    assert again.post("/api/login/totp", json={"challenge": f2["challenge"], "code": code}).status_code == 401            # a recovery code works once
    key_id = c.get("/api/me/webauthn").json()["keys"][0]["id"]
    assert c.post("/api/me/webauthn/remove", json={"id": key_id, "password": "wrong"}).status_code == 403
    assert c.post("/api/me/webauthn/remove", json={"id": key_id, "password": "longenough1"}).json()["keys"] == []
    conn = connect(path)
    assert conn.execute("SELECT webauthn_enabled FROM users WHERE username = 'alice'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM user_recovery_codes").fetchone()[0] == 0
    plain = client(app).post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    assert plain == {"ok": True}                                                         # no factor left: password only (the policy may still require one)


def test_a_lapsed_licence_stops_adding_keys_but_never_the_ones_that_exist(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, _ = add_key(c)
    state["privileged"] = False
    assert c.post("/api/me/webauthn/begin", json={"password": "longenough1"}).status_code == 402
    f = client(app)
    first = f.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    assert f.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": auth.get(first["webauthn"]["challenge"], RP, ORIGIN)}).status_code == 200


def test_the_policy_counts_a_key_as_a_second_factor_and_break_glass_may_use_one(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    session = c.get("/api/session").json()
    add_key(c)
    assert admin.put("/api/security-policy", json={"require_totp": "admins"}, headers=ADMIN).status_code == 200
    s = c.get("/api/session").json()
    assert not s.get("restricted") and (s.get("mfa") or {}).get("enrolled", True)
    users_list = admin.get("/api/users", headers=ADMIN).json()
    row = next(u for u in (users_list["users"] if isinstance(users_list, dict) else users_list) if u["username"] == "alice")
    assert row["webauthn"] is True and row["second_factor"] is True
    assert admin.patch(f"/api/users/{row['id']}", json={"break_glass": True}, headers=ADMIN).status_code == 200


def test_step_up_with_a_key(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    auth, _ = add_key(c)
    assert admin.put("/api/security-policy", json={"step_up": True, "step_up_minutes": 5}, headers=ADMIN).status_code == 200
    f = client(app)
    first = f.post("/api/login", json={"username": "alice", "password": "longenough1"}).json()
    f.post("/api/login/webauthn", json={"challenge": first["challenge"], "credential": auth.get(first["webauthn"]["challenge"], RP, ORIGIN)})
    conn = connect(path)
    conn.execute("UPDATE sessions SET auth_at = '2000-01-01T00:00:00Z'")             # a long time ago
    conn.commit()
    status = f.get("/api/me/stepup").json()
    assert status["method"] == "webauthn" and status["fresh"] is False and status["webauthn"]["rpId"] == RP
    new_login = {"name": "x", "kind": "login", "username": "u", "password": "p"}
    blocked = f.post("/api/credentials", json=new_login)
    assert blocked.status_code == 401 and blocked.json()["detail"] == "step_up_required:webauthn"
    wrong = f.post("/api/me/stepup", json={"credential": auth.get(status["webauthn"]["challenge"], RP, ORIGIN, tamper=True)})
    assert wrong.status_code == 403
    status = f.get("/api/me/stepup").json()
    ok = f.post("/api/me/stepup", json={"credential": auth.get(status["webauthn"]["challenge"], RP, ORIGIN)})
    assert ok.status_code == 200 and f.post("/api/credentials", json=new_login).status_code == 200
    stale = f.post("/api/me/stepup", json={"credential": auth.get(status["webauthn"]["challenge"], RP, ORIGIN)})
    assert stale.status_code == 403                                                    # the challenge was used


def test_an_administrator_resets_keys_too_and_the_console_does(env, tmp_path):
    app, path, state, admin = env
    c, _ = login_password(app)
    add_key(c)
    conn = connect(path)
    uid = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    b, _ = login_password(app, "bella")
    boss_key, _ = add_key(b)
    r = b.post(f"/api/users/{uid}/totp/reset", json={"password": "longenough1"})
    assert r.status_code == 403                                                        # bella has a key: a password is not enough
    # an administrator with a key proves it with the key
    assert admin.put("/api/security-policy", json={"step_up": True}, headers=ADMIN).status_code == 200
    status = b.get("/api/me/stepup").json()
    cred = boss_key.get(status["webauthn"]["challenge"], RP, ORIGIN)
    done = b.post(f"/api/users/{uid}/totp/reset", json={"credential": cred})
    assert done.status_code == 200 and done.json() == {"reset": True}
    assert conn.execute("SELECT COUNT(*) FROM user_webauthn WHERE user_id = ?", (uid,)).fetchone()[0] == 0


def test_the_console_reset_removes_keys(env):
    app, path, state, admin = env
    c, _ = login_password(app)
    add_key(c)
    from app import cli

    assert cli.run(["--db", str(path), "reset-totp", "alice"]) == 0
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM user_webauthn").fetchone()[0] == 0
    assert conn.execute("SELECT webauthn_enabled FROM users WHERE username = 'alice'").fetchone()[0] == 0
