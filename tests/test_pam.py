"""Using the customer's PAM: the Vault/OpenBao KV provider against a stand-in server, the `pam` credential kind, fail-closed behaviour, audit lines without secrets."""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from app import credstore, licence, pam
from app.config import load_settings
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.main import create_app
from tests.fake_vault import ROLE, SECRET, Fake

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def bao():
    fake = Fake().start()
    yield fake
    fake.stop()


def entry(bao, **over):
    return {"id": "e1", "name": "Linux admin", "kind": "pam", "provider": "vault_kv", "url": bao.url, "mount": "secret", "kv_version": "2", "path": "netlens/linux",
            "role_id": ROLE, "secret_id": SECRET, **over}


def get(bao, reason="", interactive=True, **over):
    ctx = pam.Context("test", "anna", reason=reason, device="web01")
    return pam.checkout(entry(bao, **over), ctx, interactive)


# ------------------------------------------------------------------ the provider
def test_approle_reads_the_login_and_revokes_its_token_afterwards(bao):
    f = get(bao)
    assert f.values == {"username": "svc", "password": "pw-1"}
    assert bao.revoked == []                                  # still held until the caller is done
    f.done()
    assert len(bao.revoked) == 1 and bao.tokens[bao.revoked[0]] == "approle"
    f.done()
    assert len(bao.revoked) == 1                              # done twice does nothing more
    read = [r for r in bao.requests if r["path"] == "/v1/secret/data/netlens/linux"][0]
    assert read["headers"]["X-Vault-Token"] == bao.revoked[0] and read["headers"]["X-Netlens-Correlation"].startswith("nl-")


def test_a_fixed_token_is_used_and_never_revoked(bao):
    f = get(bao, role_id="", secret_id="", token=bao.static_token)
    f.done()
    assert f.values["password"] == "pw-1" and bao.revoked == []


def test_kv_version_1_and_a_namespace_header(bao):
    f = get(bao, mount="kv1", kv_version="1", path="old/db", namespace="team/a")
    f.done()
    assert f.values == {"username": "legacy", "password": "pw-v1"}
    assert any(r["headers"].get("X-Vault-Namespace") == "team/a" for r in bao.requests)


def test_field_names_can_be_mapped_and_a_missing_user_name_falls_back(bao):
    f = get(bao, path="netlens/key", username_field="user", key_field="key", passphrase_field="pass", password_field="nothing")
    f.done()
    assert f.values == {"username": "root", "private_key": "KEYDATA", "passphrase": "kp"}
    f = get(bao, path="netlens/nouser", username="fallback")
    f.done()
    assert f.values["username"] == "fallback"
    with pytest.raises(pam.PamError, match="does not hold a user name"):
        get(bao, path="netlens/nouser")


@pytest.mark.parametrize("bad", ["../sys/seal-status", "a/../b", "/abs//x", "a?b=c", "a#b", "", "a/\n/b"])
def test_a_path_cannot_leave_its_place(bao, bad):
    with pytest.raises(pam.PamError):
        get(bao, path=bad)
    assert not [r for r in bao.requests if "sys" in r["path"]]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/", "http://169.254.169.254/", "http://[fe80::1]/", "http://user:pw@127.0.0.1:1/", "", "vault.example.com"])
def test_the_address_goes_through_the_outbound_guard(url, bao):
    with pytest.raises(pam.PamError):
        get(bao, url=url)


def test_every_refusal_is_a_sentence_without_a_secret(bao):
    cases = [({"path": "other/x"}, "may not read"), ({"path": "netlens/missing"}, "no secret at that path"), ({"secret_id": "wrong"}, "AppRole sign-in was refused"),
             ({"url": "http://127.0.0.1:1"}, "cannot reach the PAM system")]
    for over, text in cases:
        with pytest.raises(pam.PamError, match=text) as exc:
            get(bao, **over)
        assert SECRET not in str(exc.value) and "pw-1" not in str(exc.value)
    bao.down = 1
    with pytest.raises(pam.PamError, match="not available"):
        get(bao)


def test_an_oversized_answer_is_refused(bao):
    bao.big = True
    with pytest.raises(pam.PamError, match="larger answer"):
        get(bao)


def test_the_token_is_revoked_even_when_the_read_fails(bao):
    with pytest.raises(pam.PamError):
        get(bao, path="netlens/missing")
    assert len(bao.revoked) == 1


def test_a_reason_is_required_for_people_and_refused_for_jobs(bao):
    with pytest.raises(pam.PamError, match="needs a reason"):
        get(bao, reason_required=True)
    with pytest.raises(pam.PamError, match="needs a reason"):
        get(bao, reason="x ", reason_required=True)
    with pytest.raises(pam.PamError, match="only be used by a person"):
        get(bao, reason="INC-42", interactive=False, reason_required=True)
    f = get(bao, reason="  INC-42   disk   check ", reason_required=True)
    f.done()
    assert f.values["password"] == "pw-1"


def test_status_and_the_audit_line_never_hold_a_secret(bao):
    get(bao).done()
    with pytest.raises(pam.PamError):
        get(bao, path="netlens/missing")
    st = pam.last_status("e1")
    assert st["ok"] is False and "pw-1" not in json.dumps(st)
    ctx = pam.Context("remote RDP to web01", "anna", reason="INC-1", device="web01")
    line = pam.audit_line(entry(bao), ctx, "req-1", True)
    assert "INC-1" in line and "req-1" in line and ctx.correlation in line and SECRET not in line and "pw-1" not in line and ROLE not in line


def test_a_provider_bug_fails_closed_with_a_generic_sentence(bao, monkeypatch):
    class Broken:
        @staticmethod
        def validate(e):
            pass

        @staticmethod
        def fetch(e, ctx):
            raise KeyError("pw-1 is in this message")

    monkeypatch.setitem(pam.PROVIDERS, "broken", Broken)
    with pytest.raises(pam.PamError) as exc:
        pam.checkout({"id": "b", "provider": "broken"}, pam.Context("t", "u"), True)
    assert "pw-1" not in str(exc.value) and "KeyError" in str(exc.value)


# ------------------------------------------------------------------ the credential store
@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    yield c
    c.close()


def make(conn, bao, **over):
    fields = {"provider": "vault_kv", "url": bao.url, "mount": "secret", "path": "netlens/linux", "role_id": ROLE, "secret_id": SECRET, **over}
    return credstore.create(conn, "anna", "PAM linux", "pam", fields, shared=True)


def audit_rows(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM audit_log WHERE method = 'PAM' ORDER BY id")]


def test_a_pam_entry_stores_where_the_secret_is_and_shows_no_secret(conn, bao):
    made = make(conn, bao)
    shown = json.dumps(credstore.listing(conn, "anna"))
    assert made["kind"] == "pam" and made["has_secret"] and made["pam"]["where"] == "secret/netlens/linux" and made["pam"]["auth"] == "approle"
    assert SECRET not in shown and "secret_id" not in shown
    stored = conn.execute("SELECT value FROM settings WHERE key = 'credstore.entries'").fetchone()[0]
    assert stored.startswith("enc:v1:") and SECRET not in stored


def test_an_entry_that_could_never_work_is_refused_early(conn, bao):
    for over in ({"path": "../x"}, {"url": "ftp://x"}, {"provider": "nope"}, {"role_id": "", "secret_id": ""}, {"kv_version": "3"}):
        with pytest.raises(credstore.CredentialError):
            make(conn, bao, **over)


def test_changing_an_entry_keeps_secrets_and_can_switch_the_sign_in(conn, bao):
    made = make(conn, bao)
    credstore.update(conn, "anna", made["id"], {"path": "netlens/linux", "secret_id": ""}, True)       # a blank secret keeps the old one
    assert credstore.use_bound(conn, made["id"], "t")["password"] == "pw-1"
    credstore.update(conn, "anna", made["id"], {"token": bao.static_token}, True)
    entry_ = credstore.peek(conn, "anna", made["id"])
    assert entry_["token"] == bao.static_token and "secret_id" not in entry_ and credstore.listing(conn, "anna")[0]["pam"]["auth"] == "token"
    assert credstore.use_bound(conn, made["id"], "t")["password"] == "pw-1"


def test_resolve_fetches_now_audits_and_leaves_no_copy(conn, bao):
    made = make(conn, bao)
    before = len(bao.requests)
    assert credstore.peek(conn, "anna", made["id"]) and credstore.peek_bound(conn, made["id"])
    assert len(bao.requests) == before                         # showing a name never asks the PAM
    got = credstore.resolve(conn, "bob", made["id"], "remote RDP to web01", "INC-7", "web01")
    assert got["username"] == "svc" and got["password"] == "pw-1" and got["name"] == "PAM linux" and "secret_id" not in got and "token" not in got
    rows = audit_rows(conn)
    assert len(rows) == 1 and rows[0]["user"] == "bob" and rows[0]["status"] == 200 and "INC-7" in rows[0]["action"] and "web01" in rows[0]["action"]
    everywhere = json.dumps([dict(r) for r in conn.execute("SELECT * FROM audit_log")]) + json.dumps([dict(r) for r in conn.execute("SELECT * FROM events")])
    assert "pw-1" not in everywhere and SECRET not in everywhere
    assert "pw-1" not in conn.execute("SELECT group_concat(value) FROM settings").fetchone()[0]
    assert len(bao.revoked) == 1


def test_a_refusal_is_audited_and_fails_closed(conn, bao):
    made = make(conn, bao)
    bao.down = 5
    with pytest.raises(credstore.CredentialError, match="not available"):
        credstore.resolve(conn, made["owner"], made["id"], "SSH terminal to web01")
    rows = audit_rows(conn)
    assert len(rows) == 1 and rows[0]["status"] == 403 and "REFUSED" in rows[0]["action"]
    assert credstore.listing(conn, "anna")[0]["pam"]["last"]["ok"] is False


def test_jobs_cannot_use_a_login_that_needs_a_reason_and_repeat_uses_make_one_audit_line(conn, bao):
    needs = make(conn, bao, reason_required=True)
    with pytest.raises(credstore.CredentialError, match="only be used by a person"):
        credstore.use_bound(conn, needs["id"], "monitoring SSH")
    plain = credstore.create(conn, "anna", "second", "pam", {"provider": "vault_kv", "url": bao.url, "path": "netlens/linux", "role_id": ROLE, "secret_id": SECRET}, shared=True)
    credstore._AUDITED.clear()
    for _ in range(3):
        assert credstore.use_bound(conn, plain["id"], "monitoring SSH", "device 1")["password"] == "pw-1"
    ok = [r for r in audit_rows(conn) if r["status"] == 200]
    assert len(ok) == 1                                       # a monitor that polls every minute does not flood the log
    assert any(r["status"] == 403 for r in audit_rows(conn))  # the refusal above is always written


def test_a_monitor_asks_the_pam_when_it_polls_but_not_when_it_is_listed(conn, bao):
    made = make(conn, bao, username="")
    secret = {"credential_id": made["id"], "platform": "linux"}
    before = len(bao.requests)
    listed = hm.resolve_secret(conn, "ssh", secret, fetch=False)
    assert len(bao.requests) == before and listed.get("via_pam") and not listed.get("password")
    used = hm.resolve_secret(conn, "ssh", secret)
    assert used["username"] == "svc" and used["password"] == "pw-1" and "platform" in used
    bao.down = 5
    assert hm.resolve_secret(conn, "ssh", secret) == {}        # fail closed: no login, no poll


def test_the_event_loop_is_not_held_by_the_pam(conn, bao):
    made = make(conn, bao)
    got = asyncio.run(credstore.resolve_async(conn, "anna", made["id"], "SSH terminal", "", "web01"))
    assert got["password"] == "pw-1"


# ------------------------------------------------------------------ the API
@pytest.fixture
def api(tmp_path, monkeypatch):
    state = {"privileged": True}
    real = licence.allows
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        yield c, state, tmp_path / "t.db"


def body(bao, **over):
    return {"name": "PAM linux", "kind": "pam", "provider": "vault_kv", "url": bao.url, "mount": "secret", "path": "netlens/linux", "role_id": ROLE, "secret_id": SECRET, **over}


def test_the_api_is_enterprise_only_for_creating_and_never_returns_a_secret(api, bao):
    c, state, path = api
    state["privileged"] = False
    r = c.post("/api/credentials", json=body(bao), headers=ADMIN)
    assert r.status_code == 402
    state["privileged"] = True
    made = c.post("/api/credentials", json=body(bao), headers=ADMIN)
    assert made.status_code == 200 and SECRET not in made.text
    listing = c.get("/api/credentials", headers=ADMIN).json()
    assert listing["pam"]["allowed"] and "vault_kv" in listing["pam"]["providers"] and SECRET not in json.dumps(listing)
    state["privileged"] = False
    assert c.put(f"/api/credentials/{made.json()['id']}", json={"path": "netlens/key"}, headers=ADMIN).status_code == 402
    # a lapsed licence does not stop a login that already exists from being used: it is the safer way to hold a secret
    assert c.post(f"/api/credentials/{made.json()['id']}/test", json={}, headers=ADMIN).json()["ok"] is True


def test_try_it_says_which_fields_came_back_and_why_it_failed(api, bao):
    c, state, path = api
    made = c.post("/api/credentials", json=body(bao), headers=ADMIN).json()
    ok = c.post(f"/api/credentials/{made['id']}/test", json={}, headers=ADMIN).json()
    assert ok == {"ok": True, "message": "the PAM system handed out the login", "fields": ["password", "username"]}
    bad = c.post("/api/credentials", json=body(bao, name="missing", path="netlens/missing"), headers=ADMIN).json()
    res = c.post(f"/api/credentials/{bad['id']}/test", json={}, headers=ADMIN).json()
    assert res["ok"] is False and "no secret at that path" in res["message"]
    plain = c.post("/api/credentials", json={"name": "p", "kind": "login", "username": "u", "password": "x"}, headers=ADMIN).json()
    assert c.post(f"/api/credentials/{plain['id']}/test", json={}, headers=ADMIN).status_code == 422
    needs = c.post("/api/credentials", json=body(bao, name="needs", reason_required=True), headers=ADMIN).json()
    assert "needs a reason" in c.post(f"/api/credentials/{needs['id']}/test", json={}, headers=ADMIN).json()["message"]
    assert c.post(f"/api/credentials/{needs['id']}/test", json={"reason": "INC-9 check"}, headers=ADMIN).json()["ok"] is True


def test_the_terminal_login_route_passes_a_refusal_through(api, bao):
    c, state, path = api
    made = c.post("/api/credentials", json=body(bao, reason_required=True), headers=ADMIN).json()
    conn = connect(path)
    try:
        with pytest.raises(credstore.CredentialError, match="needs a reason"):
            credstore.resolve(conn, made["owner"], made["id"], "SSH terminal to web01")
        assert credstore.resolve(conn, made["owner"], made["id"], "SSH terminal to web01", "INC-3 restart")["username"] == "svc"
    finally:
        conn.close()


# ------------------------------------------------------------------ the terminal, end to end
def test_a_terminal_session_gets_its_login_from_the_pam_and_a_reason_when_asked(tmp_path, monkeypatch, bao):
    from tests.fake_terminal import FakeBackend
    from tests.test_api_terminal_session import make_app

    FakeBackend.reset()
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    app = make_app(tmp_path)
    auth = {"Authorization": "Bearer t"}
    url = "/api/terminal/1/ws?proto=ssh"
    with TestClient(app, headers=auth) as client:
        plain = client.post("/api/credentials", json=body(bao, name="PAM plain")).json()
        needs = client.post("/api/credentials", json=body(bao, name="PAM needs reason", reason_required=True)).json()
        with client.websocket_connect(url, headers=auth) as ws:
            ws.send_json({"type": "auth", "credential_id": plain["id"], "cols": 80, "rows": 24})
            assert ws.receive_json()["state"] == "connected"
        assert FakeBackend.created[-1]["username"] == "svc" and FakeBackend.created[-1]["password"] == "pw-1"
        with client.websocket_connect(url, headers=auth) as ws:
            ws.send_json({"type": "auth", "credential_id": needs["id"], "cols": 80, "rows": 24})
            err = ws.receive_json()
            assert err["type"] == "error" and "needs a reason" in err["message"] and "pw-1" not in json.dumps(err)
        n = len(FakeBackend.created)
        with client.websocket_connect(url, headers=auth) as ws:
            ws.send_json({"type": "auth", "credential_id": needs["id"], "reason": "INC-5 restart nginx", "cols": 80, "rows": 24})
            assert ws.receive_json()["state"] == "connected"
        assert len(FakeBackend.created) == n + 1
        bao.down = 5
        with client.websocket_connect(url, headers=auth) as ws:
            ws.send_json({"type": "auth", "credential_id": plain["id"], "cols": 80, "rows": 24})
            err = ws.receive_json()
            assert err["type"] == "error" and "not available" in err["message"]               # fail closed
        assert len(FakeBackend.created) == n + 1
        log = client.get("/api/audit", params={"limit": 50}).text if client.get("/api/audit").status_code == 200 else ""
        assert "pw-1" not in log and SECRET not in log


def test_a_refused_login_shows_up_in_the_problem_list_the_answers_and_reports_use(conn, bao):
    from app import dashboard

    made = make(conn, bao)
    assert not [p for p in dashboard.current_problems(conn) if "PAM" in p["text"]]
    bao.down = 5
    with pytest.raises(credstore.CredentialError):
        credstore.resolve(conn, "anna", made["id"], "SSH terminal")
    found = [p for p in dashboard.current_problems(conn) if "PAM" in p["text"]]
    assert found and "PAM linux" in found[0]["text"] and "pw-1" not in found[0]["text"]
    bao.down = 0
    credstore.resolve(conn, "anna", made["id"], "SSH terminal")
    assert not [p for p in dashboard.current_problems(conn) if "PAM" in p["text"]]
