import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from fastapi.testclient import TestClient

from app import licence, oidc, tsdb
from app.config import load_settings
from app.main import create_app

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC = ec.generate_private_key(ec.SECP256R1())


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_rsa(kid="k1"):
    n = KEY.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64(n.n.to_bytes(256, "big")), "e": b64(n.e.to_bytes(3, "big"))}


def jwk_ec(kid="e1"):
    n = EC.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def make_token(claims, alg="RS256", kid="k1", key=None):
    head = b64(json.dumps({"alg": alg, "kid": kid}).encode())
    body = b64(json.dumps(claims).encode())
    signed = f"{head}.{body}".encode()
    if alg == "RS256":
        sig = (key or KEY).sign(signed, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        r, s = utils.decode_dss_signature(EC.sign(signed, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = b""
    return f"{head}.{body}.{b64(sig)}"


def claims(**kw):
    base = {"iss": "https://idp.example", "aud": "netlens", "sub": "u-1", "exp": time.time() + 600, "nonce": "N", "preferred_username": "anna", "email": "anna@example.com", "groups": ["staff"]}
    base.update(kw)
    return base


JWKS = {"keys": [jwk_rsa(), jwk_ec()]}


def verify(token, **kw):
    args = {"issuer": "https://idp.example", "audience": "netlens", "nonce": "N"}
    args.update(kw)
    return oidc.verify_id_token(token, JWKS, **args)


def test_a_genuine_token_is_accepted_with_rsa_and_ec():
    assert verify(make_token(claims()))["sub"] == "u-1"
    assert verify(make_token(claims(), "ES256", "e1"))["sub"] == "u-1"
    assert verify(make_token(claims(aud=["x", "netlens"])))["sub"] == "u-1"


@pytest.mark.parametrize("bad", [
    lambda: make_token(claims(), "none"),
    lambda: make_token(claims(), key=rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    lambda: make_token(claims(iss="https://evil.example")),
    lambda: make_token(claims(aud="other")),
    lambda: make_token(claims(exp=time.time() - 3600)),
    lambda: make_token(claims(nonce="other")),
    lambda: make_token(claims(sub="")),
    lambda: make_token(claims(), kid="unknown"),
    lambda: "not.a.token",
    lambda: "x",
])
def test_everything_else_is_refused(bad):
    with pytest.raises(oidc.OidcError):
        verify(bad())


def test_tampered_payload_is_refused():
    head, body, sig = make_token(claims()).split(".")
    forged = b64(json.dumps(claims(sub="admin")).encode())
    with pytest.raises(oidc.OidcError):
        verify(f"{head}.{forged}.{sig}")


class Idp(BaseHTTPRequestHandler):
    state = {}

    def _json(self, doc):
        raw = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        base = Idp.state["base"]
        if self.path.endswith("/.well-known/openid-configuration"):
            return self._json({"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/jwks"})
        if self.path == "/jwks":
            return self._json(JWKS)
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        Idp.state["form"] = {k: v[0] for k, v in form.items()}
        if form.get("code") != ["good-code"]:
            self.send_response(400)
            self.end_headers()
            return
        self._json({"id_token": make_token({**Idp.state["claims"], "iss": Idp.state["base"], "aud": "netlens", "nonce": Idp.state["nonce"], "exp": time.time() + 300}), "token_type": "Bearer"})

    def log_message(self, *a):
        pass


@pytest.fixture
def idp():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Idp)
    Idp.state = {"base": f"http://127.0.0.1:{srv.server_address[1]}", "claims": {"sub": "u-1", "preferred_username": "anna", "groups": ["staff"]}}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield Idp.state
    srv.shutdown()


def test_the_whole_flow(tmp_path, idp):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        anon = TestClient(client.app, headers={})
        assert anon.get("/api/session").json()["oidc"]["enabled"] is False
        assert client.put("/api/sso", json={"issuer": idp["base"]}, headers=h).status_code == 402          # needs the trial or a licence
        client.post("/api/licence/trial", headers=h)
        saved = client.put("/api/sso", json={"enabled": True, "issuer": idp["base"], "client_id": "netlens", "client_secret": "s3cr3t", "admin_groups": "netlens-admins", "label": "Company login"}, headers=h).json()
        assert saved["has_secret"] is True and "s3cr3t" not in json.dumps(saved) and saved["redirect_uri"].endswith("/api/auth/oidc/callback")
        assert client.put("/api/sso", json={"issuer": "http://idp.example.com"}, headers=h).status_code == 422       # plain http only on your own network
        assert client.post("/api/sso/test", headers=h).status_code == 200
        assert anon.get("/api/session").json()["oidc"] == {"enabled": True, "label": "Company login"}
        start = anon.get("/api/auth/oidc/login", follow_redirects=False)
        assert start.status_code == 302
        query = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
        assert query["code_challenge_method"] == "S256" and query["client_id"] == "netlens" and query["response_type"] == "code"
        idp["nonce"] = query["nonce"]
        bad = anon.get("/api/auth/oidc/callback", params={"code": "good-code", "state": "unknown"})
        assert bad.status_code == 401 and "expired" in bad.text
        done = anon.get("/api/auth/oidc/callback", params={"code": "good-code", "state": query["state"]})
        assert done.status_code == 200 and "netlens_session" in done.headers.get("set-cookie", "") or "session" in done.headers.get("set-cookie", "")
        assert idp["form"]["code_verifier"] and idp["form"]["client_secret"] == "s3cr3t"
        me = anon.get("/api/session").json()
        assert me["authenticated"] and me["user"]["username"] == "anna" and me["user"]["role"] == "viewer"
        again = anon.get("/api/auth/oidc/callback", params={"code": "good-code", "state": query["state"]})
        assert again.status_code == 401                                                                              # a state works once
        # the provider makes her an administrator later; the role follows, and no second user appears
        idp["claims"]["groups"] = ["netlens-admins"]
        second = TestClient(client.app, headers={})
        start = second.get("/api/auth/oidc/login", follow_redirects=False)
        q2 = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
        idp["nonce"] = q2["nonce"]
        second.get("/api/auth/oidc/callback", params={"code": "good-code", "state": q2["state"]})
        assert second.get("/api/session").json()["user"] == {"username": "anna", "role": "admin", "builtin": False}
        assert [u["username"] for u in client.get("/api/users", headers=h).json()["users"]] == ["anna"]
        # a wrong code is refused with a sentence, not a crash
        start = TestClient(client.app, headers={}).get("/api/auth/oidc/login", follow_redirects=False)
        q3 = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
        idp["nonce"] = q3["nonce"]
        assert anon.get("/api/auth/oidc/callback", params={"code": "wrong", "state": q3["state"]}).status_code == 401
    tsdb.forget_all()


def test_a_provider_without_matching_issuer_is_refused(tmp_path, idp, monkeypatch):
    with pytest.raises(oidc.OidcError):
        oidc._cache.clear()
        monkeypatch.setattr(oidc, "_fetch", lambda url, data=None, timeout=15: {"issuer": "https://other", "authorization_endpoint": "a", "token_endpoint": "t", "jwks_uri": "j"})
        oidc.discovery("https://idp.example")


def test_a_local_account_cannot_be_taken_over_by_name(tmp_path, idp):
    from app import users
    from app.db import connect, init_db

    c = connect(tmp_path / "t.db")
    init_db(c)
    local = users.create_user(c, "anna", "Correct-horse-1", "admin")
    cfg = {"groups_claim": "groups", "admin_groups": "", "default_role": "viewer"}
    cookie = oidc.sign_in(c, {"sub": "other-person", "preferred_username": "anna", "groups": []}, cfg)
    row = users.user_for_session(c, cookie)
    assert row["id"] != local and row["username"] != "anna" and row["role"] == "viewer"
    assert c.execute("SELECT role FROM users WHERE id = ?", (local,)).fetchone()["role"] == "admin"
    c.close()


def test_the_group_map_gives_the_most_privileged_role_and_the_provider_decides_every_time(tmp_path, monkeypatch):
    from app import licence, roles, users
    from app.db import connect, init_db

    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c = connect(tmp_path / "t.db")
    init_db(c)
    roles.save(c, "Auditor", "viewer", ["audit"])
    saved = oidc.save_settings(c, {"group_map": [{"group": "ops", "role": "operator"}, {"group": "Auditors", "role": "custom:auditor"}, {"group": "root", "role": "admin"}], "default_role": "viewer"})
    cfg = {**saved, "admin_groups": ""}
    assert [m["group"] for m in saved["group_map"]] == ["ops", "Auditors", "root"]

    def login(sub, groups):
        cookie = oidc.sign_in(c, {"sub": sub, "preferred_username": sub, "groups": groups}, cfg)
        return users.user_for_session(c, cookie)

    assert login("a", [])["role"] == "viewer"                                               # no group: the default role
    row = login("b", ["AUDITORS"])                                                          # case-insensitive; a custom role
    assert row["role"] == "viewer" and row["custom_role"] == "auditor"
    assert login("c", ["ops", "auditors"])["role"] == "operator"                           # the operator outranks the narrower custom role
    assert login("d", ["ops", "root"])["role"] == "admin"                                   # the most privileged wins
    again = login("d", ["ops"])                                                             # the group was removed at the provider: the role follows at the next sign-in
    assert again["role"] == "operator" and again["custom_role"] is None
    assert login("b", ["ops"])["custom_role"] is None                                       # and a custom role is dropped when the group goes
    cfg2 = {**cfg, "admin_groups": "netlens-admins"}
    cookie = oidc.sign_in(c, {"sub": "e", "preferred_username": "e", "groups": ["netlens-admins", "ops"]}, cfg2)
    assert users.user_for_session(c, cookie)["role"] == "admin"                             # the older admin-groups setting still works
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "privileged")
    assert login("f", ["root"])["role"] == "viewer"                                         # without the edition the map is ignored (the default role)
    c.close()


def test_the_group_map_is_validated(tmp_path):
    from app import roles
    from app.db import connect, init_db

    c = connect(tmp_path / "t.db")
    init_db(c)
    roles.save(c, "Auditor", "viewer", ["audit"])
    for bad in ("x", [{"group": "", "role": "admin"}], [{"group": "g", "role": "root"}], [{"group": "g", "role": "custom:nope"}], [{"group": "g", "role": "admin"}, {"group": "G", "role": "viewer"}],
                [{"group": "g\nx", "role": "admin"}], [{"group": "g" * 201, "role": "admin"}], [{"group": str(i), "role": "viewer"} for i in range(51)]):
        with pytest.raises(oidc.OidcError):
            oidc.save_settings(c, {"group_map": bad})
    assert oidc.save_settings(c, {"group_map": [{"group": " ok ", "role": "custom:auditor"}]})["group_map"] == [{"group": "ok", "role": "custom:auditor"}]
    c.close()
