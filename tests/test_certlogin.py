"""Sign in with a client certificate that a reverse proxy has checked: believed only from the listed proxies, only when verified, only for a linked identity."""

import pytest
from fastapi.testclient import TestClient

from app import certlogin, licence, secpolicy
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}
GOOD = {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-S-DN": "CN=alice,O=Example"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "mfa_policy": True, "teams": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    boot = connect(tmp_path / "t.db")
    init_db(boot)
    boot.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    proxy = TestClient(app, client=("10.0.0.5", 4000))            # the reverse proxy
    stranger = TestClient(app, client=("203.0.113.7", 4000))      # somebody who reaches Netlens directly and sends the headers himself
    for name in ("alice", "bob"):
        assert proxy.post("/api/users", json={"username": name, "password": "longenough1", "role": "admin" if name == "alice" else "viewer"}, headers=ADMIN).status_code == 201
    yield app, tmp_path / "t.db", state, proxy, stranger
    secpolicy.forget()


def uid(path, name):
    c = connect(path)
    try:
        return c.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()[0]
    finally:
        c.close()


def setup(proxy, path, enabled=True, **over):
    r = proxy.put("/api/cert-login", json={"enabled": enabled, "proxies": ["10.0.0.5"], **over}, headers=ADMIN)
    assert r.status_code == 200, r.text
    assert proxy.patch(f"/api/users/{uid(path, 'alice')}", json={"cert_identity": "CN=alice,O=Example"}, headers=ADMIN).status_code == 200


def test_a_verified_certificate_from_the_proxy_signs_the_linked_user_in(env):
    app, path, state, proxy, stranger = env
    setup(proxy, path)
    c = TestClient(app, client=("10.0.0.5", 4000))
    assert c.get("/api/session", headers=GOOD).json()["certificate_login"] is True
    r = c.post("/api/login/certificate", headers=GOOD)
    assert r.status_code == 200 and c.get("/api/session").json()["user"]["username"] == "alice"
    conn = connect(path)
    assert conn.execute("SELECT auth_method FROM sessions ORDER BY seq DESC LIMIT 1").fetchone()[0] == "certificate"


def test_nothing_is_believed_from_anywhere_else_or_when_the_proxy_did_not_verify(env):
    app, path, state, proxy, stranger = env
    setup(proxy, path)
    assert stranger.get("/api/session", headers=GOOD).json()["certificate_login"] is False
    assert stranger.post("/api/login/certificate", headers=GOOD).status_code == 401           # a direct client forging the headers
    for headers in ({"X-SSL-Client-Verify": "FAILED", "X-SSL-Client-S-DN": "CN=alice,O=Example"}, {"X-SSL-Client-S-DN": "CN=alice,O=Example"}, {"X-SSL-Client-Verify": "SUCCESS"},
                    {"X-SSL-Client-Verify": "success", "X-SSL-Client-S-DN": "CN=alice,O=Example"}, {"X-SSL-Client-Verify": "SUCCESS", "X-SSL-Client-S-DN": "CN=alice,O=Example\x01"}):
        r = proxy.post("/api/login/certificate", headers={k: v for k, v in headers.items() if "\x01" not in v})
        assert r.status_code == 401, headers
    assert proxy.post("/api/login/certificate", headers={**GOOD, "X-SSL-Client-S-DN": "CN=alice,O=Example "}).status_code == 200      # a trailing space of the header is trimmed, nothing more
    unknown = proxy.post("/api/login/certificate", headers={**GOOD, "X-SSL-Client-S-DN": "CN=mallory"})
    assert unknown.status_code == 401 and "not linked" in unknown.json()["detail"]
    assert proxy.post("/api/login/certificate", headers={**GOOD, "X-SSL-Client-S-DN": "cn=alice,o=example"}).status_code == 401      # exact match only


def test_switched_off_unlicensed_disabled_and_second_factor(env):
    app, path, state, proxy, stranger = env
    setup(proxy, path)
    state["privileged"] = False
    assert proxy.post("/api/login/certificate", headers=GOOD).status_code == 401
    state["privileged"] = True
    conn = connect(path)
    conn.execute("UPDATE users SET disabled = 1 WHERE username = 'alice'")
    conn.commit()
    assert proxy.post("/api/login/certificate", headers=GOOD).status_code == 401
    conn.execute("UPDATE users SET disabled = 0, totp_enabled = 1, totp_secret = NULL WHERE username = 'alice'")
    conn.commit()
    r = proxy.post("/api/login/certificate", headers=GOOD)
    assert r.status_code == 200 and r.json()["totp_required"] is True and r.json()["methods"]["totp"] is True and "user" not in proxy.get("/api/session").text.lower().replace("authenticated", "")
    proxy.put("/api/cert-login", json={"enabled": False}, headers=ADMIN)
    assert proxy.post("/api/login/certificate", headers=GOOD).status_code == 401


def test_the_settings_are_validated_and_an_identity_belongs_to_one_user(env):
    app, path, state, proxy, stranger = env
    for bad in ({"enabled": True, "proxies": []}, {"proxies": ["nope"]}, {"proxies": ["0.0.0.0/0"]}, {"proxies": ["::/0"]}, {"proxies": ["10.0.0.5"], "verify_header": "bad header"},
                {"proxies": ["10.0.0.5"], "identity_header": "X-SSL-Client-Verify"}, {"proxies": ["10.0.0.5"], "verify_value": ""}, {"enabled": "yes"}):
        assert proxy.put("/api/cert-login", json=bad, headers=ADMIN).status_code == 422, bad
    setup(proxy, path)
    r = proxy.patch(f"/api/users/{uid(path, 'bob')}", json={"cert_identity": "CN=alice,O=Example"}, headers=ADMIN)
    assert r.status_code == 422 and "already" in r.json()["detail"]
    assert proxy.patch(f"/api/users/{uid(path, 'bob')}", json={"cert_identity": "CN=b\nob"}, headers=ADMIN).status_code == 422
    state["privileged"] = False
    assert proxy.put("/api/cert-login", json={"enabled": False}, headers=ADMIN).status_code == 402
    assert proxy.patch(f"/api/users/{uid(path, 'bob')}", json={"cert_identity": "CN=bob"}, headers=ADMIN).status_code == 402
    assert proxy.patch(f"/api/users/{uid(path, 'alice')}", json={"cert_identity": ""}, headers=ADMIN).status_code == 200       # unlinking is always allowed


def test_admin_networks_and_break_glass_rules_apply_to_certificate_sign_in_too(env):
    app, path, state, proxy, stranger = env
    setup(proxy, path)
    assert proxy.put("/api/security-policy", json={"admin_networks": ["10.0.0.0/8"]}, headers=ADMIN).status_code == 200
    conn = connect(path)
    conn.execute("UPDATE users SET break_glass = 1 WHERE username = 'alice'")
    conn.commit()
    r = proxy.post("/api/login/certificate", headers=GOOD)
    assert r.status_code == 403 and "second factor" in r.json()["detail"]                 # break-glass without a second factor
