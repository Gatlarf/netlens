import pytest
from fastapi.testclient import TestClient

from app import assistant, licence
from app.config import load_settings
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture(autouse=True)
def licensed(monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture
def env(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        c.post("/api/users", json={"username": "boss", "password": "longenough1", "role": "admin"}, headers=ADMIN)
        boss = TestClient(app)
        assert boss.post("/api/login", json={"username": "boss", "password": "longenough1"}).status_code == 200
        yield c, app, boss


def token(boss, mode):
    r = boss.post("/api/assistant/token", json={"name": f"t-{mode}", "mode": mode})
    assert r.status_code == 201, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_read_token_looks_but_cannot_change(env):
    _, app, boss = env
    h = token(boss, "read")
    anon = TestClient(app)
    assert anon.get("/api/config", headers=h).status_code == 200
    assert anon.get("/api/dashboard", headers=h).status_code == 200
    r = anon.post("/api/groups", json={"name": "x", "color": "#112233"}, headers=h)
    assert r.status_code == 403 and "only read" in r.json()["detail"]
    assert anon.put("/api/config/general", json={}, headers=h).status_code == 403


def test_change_token_changes_settings_and_is_audited(env):
    c, app, boss = env
    h = token(boss, "change")
    anon = TestClient(app)
    r = anon.post("/api/groups", json={"name": "Kitchen", "color": "#112233"}, headers=h)
    assert r.status_code in (200, 201), r.text
    log = c.get("/api/audit", headers=ADMIN).json()
    assert "assistant: t-change" in str(log)
    gid = next(g["id"] for g in anon.get("/api/groups", headers=h).json()["groups"] if g["name"] == "Kitchen") if isinstance(anon.get("/api/groups", headers=h).json(), dict) else None
    if gid:
        assert anon.delete(f"/api/groups/{gid}", headers=h).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("get", "/api/users"), ("get", "/api/vault"), ("get", "/api/shares"), ("get", "/api/backup"), ("get", "/api/sso"), ("get", "/api/me/preferences"), ("get", "/api/central"),
    ("post", "/api/assistant/token"), ("delete", "/api/users/1"), ("post", "/api/backups/x/restore"), ("post", "/api/plugins"), ("put", "/api/licence"), ("post", "/api/remediation/rules"),
    ("put", "/api/engineer"), ("put", "/api/update"), ("delete", "/api/devices/1"), ("delete", "/api/backups/x"), ("post", "/api/probes/1/token"),
])
def test_what_an_assistant_may_never_do(env, method, path):
    _, app, boss = env
    h = token(boss, "change")
    r = getattr(TestClient(app), method)(path, headers=h, **({"json": {}} if method in ("post", "put") else {}))
    assert r.status_code == 403, (path, r.status_code, r.text)


def test_other_people_cannot_make_assistant_tokens(env):
    c, app, boss = env
    c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=ADMIN)
    vera = TestClient(app)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.post("/api/assistant/token", json={"mode": "read"}).status_code == 403
    assert boss.post("/api/assistant/token", json={"mode": "root"}).status_code == 422
    assert c.post("/api/assistant/token", json={"mode": "read"}, headers=ADMIN).status_code == 409      # the built-in access token has no user behind it


def test_change_needs_a_licence_and_falls_back_to_read(env, monkeypatch):
    _, app, boss = env
    h = token(boss, "change")
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "assistant")
    assert boss.post("/api/assistant/token", json={"mode": "change"}).status_code == 402
    assert boss.post("/api/assistant/token", json={"mode": "read"}).status_code == 201
    anon = TestClient(app)
    assert anon.get("/api/config", headers=h).status_code == 200                     # still works for reading
    assert anon.post("/api/groups", json={"name": "x", "color": "#112233"}, headers=h).status_code == 403
    assert boss.get("/api/assistant").json()["change_allowed"] is False


def test_guide_and_endpoints(env):
    _, app, boss = env
    h = token(boss, "read")
    anon = TestClient(app)
    guide = anon.get("/api/assistant/guide", headers=h)
    assert guide.status_code == 200 and "markdown" in guide.headers["content-type"] and "**read** mode" in guide.text
    assert "testserver" in guide.text and "`read` mode" not in guide.text and "{{" not in guide.text
    eps = anon.get("/api/assistant/endpoints", headers=h).json()
    assert eps["mode"] == "read"
    by = {(e["method"], e["path"]): e for e in eps["endpoints"]}
    assert by[("GET", "/api/config")]["allowed"] is True and by[("PUT", "/api/config/general")]["allowed"] is False
    assert not any(p.startswith("/api/users") or p.startswith("/api/vault") for _, p in by)
    change = TestClient(app).get("/api/assistant/endpoints", headers=token(boss, "change")).json()
    assert {(e["method"], e["path"]): e for e in change["endpoints"]}[("PUT", "/api/config/general")]["allowed"] is True


def test_assistant_tokens_are_listed_and_deletable(env):
    _, app, boss = env
    token(boss, "read")
    listing = boss.get("/api/assistant").json()
    assert [t["mode"] for t in listing["tokens"]] == ["read"]
    t = listing["tokens"][0]
    assert boss.delete(f"/api/users/{t['user_id']}/tokens/{t['id']}").status_code == 200
    assert boss.get("/api/assistant").json()["tokens"] == []


def test_check_function_directly():
    with pytest.raises(Exception):
        assistant.check("GET", "/api/users", "change")
    assistant.check("GET", "/api/devices", "read")
    assistant.check("PUT", "/api/config/ranges", "change")
