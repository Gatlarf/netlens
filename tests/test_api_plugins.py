import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device, get_setting, init_db
from app.main import create_app
from tests.plugin_helpers import fake, make_runner
from tests.test_plugin_service import HV, TOPO, AuthRefused

AUTH = {"Authorization": "Bearer secret"}
GOOD_PY = "def test(config):\n    return {'message': 'x'}\ndef fetch(config):\n    return {'nodes': [], 'clients': []}\n"
MANIFEST = {"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology",
            "config": [{"key": "host", "type": "text", "label": "Host", "required": True}, {"key": "pw", "type": "password", "label": "Password"}]}


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


class State:
    hv = HV
    topo = TOPO
    error = None


@pytest.fixture
def env(tmp_path):
    State.hv, State.topo, State.error = HV, TOPO, None

    def maybe(out):
        def run(cfg):
            if State.error:
                raise State.error
            return out()
        return run

    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    ids = {
        "host": get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.5"),
        "web": get_or_create_device(conn, "02:00:00:00:00:64", "10.0.0.64"),
        "main": get_or_create_device(conn, "aa:00:00:00:00:10", "10.0.0.1"),
        "wired": get_or_create_device(conn, "02:00:00:00:00:01", "10.0.0.11"),
    }
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    app.state.plugin_runner = make_runner(
        proxmox=fake(fetch=maybe(lambda: State.hv), test=maybe(lambda: {"message": "Connected: 1 node"})),
        asus=fake(fetch=maybe(lambda: State.topo)),
    )
    with TestClient(app, headers=AUTH) as c:
        yield c, ids, tmp_path


def test_list_shows_builtins_with_status(env):
    c, _, _ = env
    body = c.get("/api/plugins").json()
    by_id = {p["id"]: p for p in body["plugins"]}
    assert {"proxmox", "asus"} <= set(by_id) and body["api_version"] == 1
    assert by_id["proxmox"]["kind"] == "hypervisor" and by_id["proxmox"]["builtin"] is True
    assert by_id["proxmox"]["enabled"] is False and by_id["proxmox"]["configured"] is False and by_id["proxmox"]["status"] is None


def test_get_masks_secrets_and_returns_the_form_schema(env):
    c, _, _ = env
    c.put("/api/plugins/asus", json={"config": {"url": "10.0.0.1", "username": "u", "password": "TOPSECRET"}})
    r = c.get("/api/plugins/asus")
    assert "TOPSECRET" not in r.text
    body = r.json()
    assert body["secrets_set"] == {"password": True} and body["config"]["username"] == "u" and "password" not in body["config"]
    assert [f["key"] for f in body["manifest"]["config"]] == ["url", "verify_tls", "username", "password"]
    assert c.get("/api/plugins/nope").status_code == 404


def test_enable_syncs_immediately_and_secrets_survive_partial_updates(env):
    c, ids, tmp = env
    r = c.put("/api/plugins/proxmox", json={"enabled": True, "config": {"url": "10.0.0.5", "token_id": "u@pam!n", "token_secret": "SECRET"}})
    assert r.status_code == 200 and "SECRET" not in r.text
    out = r.json()
    assert out["enabled"] is True and out["status"]["ok"] is True and out["status"]["guests"] == 3 and out["status"]["links"] == 1
    c.put("/api/plugins/proxmox", json={"config": {"verify_tls": False}})  # partial update keeps the secret
    conn = connect(tmp / "t.db")
    assert json.loads(get_setting(conn, "plugin.proxmox"))["config"]["token_secret"] == "SECRET"
    conn.close()
    edges = {(e["from"], e["to"], e["kind"]) for e in c.get("/api/map").json()["edges"]}
    assert (ids["web"], ids["host"], "host-of") in edges
    detail = c.get(f"/api/devices/{ids['web']}").json()["virtualization"]
    assert detail["guest"]["plugin_id"] == "proxmox" and detail["guest"]["name"] == "web" and detail["guest"]["host_name"] == "10.0.0.5"
    host = c.get(f"/api/devices/{ids['host']}").json()["virtualization"]
    assert [g["name"] for g in host["guests"]] == ["db", "off", "web"] and host["guest"] is None


def test_disabling_removes_links_but_keeps_settings(env):
    c, ids, _ = env
    c.put("/api/plugins/asus", json={"enabled": True, "config": {"url": "10.0.0.1", "username": "u", "password": "p"}})
    assert any(e["kind"] == "uplink" for e in c.get("/api/map").json()["edges"])
    out = c.put("/api/plugins/asus", json={"enabled": False}).json()
    assert out["enabled"] is False and out["config"]["username"] == "u" and out["secrets_set"]["password"] is True
    assert not any(e["kind"] == "uplink" for e in c.get("/api/map").json()["edges"])


@pytest.mark.parametrize("body", [
    {"enabled": True},  # required fields missing
    {"config": {"url": 5}},  # wrong type
    {"config": {"verify_tls": "yes"}} and {"enabled": True, "config": {"url": "x"}},  # username / password missing
])
def test_validation(env, body):
    c, _, _ = env
    assert c.put("/api/plugins/asus", json=body).status_code == 422
    assert c.get("/api/plugins/asus").json()["enabled"] is False


def test_test_endpoint_saves_nothing_and_reports_failures(env):
    c, _, _ = env
    r = c.post("/api/plugins/proxmox/test", json={"config": {"url": "10.0.0.5", "username": "root@pam", "password": "pw"}})
    assert r.json() == {"ok": True, "message": "Connected: 1 node"}
    assert c.get("/api/plugins/proxmox").json()["configured"] is False
    assert c.post("/api/plugins/proxmox/test", json={}).status_code == 422
    State.error = RuntimeError("the TLS certificate could not be verified")
    r = c.post("/api/plugins/proxmox/test", json={"config": {"url": "10.0.0.5"}})
    assert r.status_code == 502 and "TLS" in r.json()["detail"]


def test_sync_endpoint(env):
    c, _, _ = env
    assert c.post("/api/plugins/asus/sync").status_code == 502  # not configured
    c.put("/api/plugins/asus", json={"enabled": True, "config": {"url": "10.0.0.1", "username": "u", "password": "p"}})
    assert c.post("/api/plugins/asus/sync").json()["links"] >= 1
    State.error = AuthRefused("login refused")
    r = c.post("/api/plugins/asus/sync")
    assert r.status_code == 502 and "refused" in r.json()["detail"]
    assert c.get("/api/plugins/asus").json()["status"]["auth_failed"] is True
    assert c.post("/api/plugins/nope/sync").status_code == 404
    assert c.post("/api/plugins/asus/sync", headers={"Authorization": "Bearer no"}).status_code == 401


# ------------------------------------------------------------------ upload / remove
def upload(c, data, **params):
    return c.post("/api/plugins", content=data, headers={"Content-Type": "application/zip"}, params=params)


def test_upload_installs_a_plugin_that_starts_off(env):
    c, _, tmp = env
    r = upload(c, make_zip({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY}))
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "demo" and body["replaced"] is False and len(body["sha256"]) == 64
    assert (tmp / "plugins" / "demo" / "plugin.py").exists()
    listed = {p["id"]: p for p in c.get("/api/plugins").json()["plugins"]}
    assert listed["demo"]["enabled"] is False and listed["demo"]["builtin"] is False and listed["demo"]["configured"] is False
    # it can be configured, tested and enabled like a built-in plugin (real subprocess runner is not used here: fake only knows built-ins)
    assert c.get("/api/plugins/demo").json()["manifest"]["config"][1]["secret"] is True


def test_upload_refuses_bad_input(env):
    c, _, tmp = env
    for data, text in [
        (b"not a zip", "not a zip"),
        (make_zip({"plugin.py": GOOD_PY}), "plugin.json not found"),
        (make_zip({"plugin.json": json.dumps({**MANIFEST, "id": "proxmox"}), "plugin.py": GOOD_PY}), "built-in"),
        (make_zip({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY, "../x.py": "1"}), "unsafe"),
    ]:
        r = upload(c, data)
        assert r.status_code == 422 and text in r.json()["detail"], (text, r.text)
    assert not (tmp / "plugins").exists() or not list((tmp / "plugins").iterdir())
    assert upload(c, b"x" * (3 * 1024 * 1024)).status_code == 413


def test_upload_twice_needs_replace_and_keeps_the_settings(env):
    c, _, _ = env
    files = {"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY}
    upload(c, make_zip(files))
    c.put("/api/plugins/demo", json={"config": {"host": "h", "pw": "SECRET"}})
    assert upload(c, make_zip(files)).status_code == 422
    r = upload(c, make_zip({**files, "plugin.json": json.dumps({**MANIFEST, "version": "2.0.0"})}), replace="true")
    assert r.json()["replaced"] is True
    got = c.get("/api/plugins/demo").json()
    assert got["manifest"]["version"] == "2.0.0" and got["config"]["host"] == "h" and got["secrets_set"]["pw"] is True


def test_remove_user_plugin_and_protect_builtins(env):
    c, ids, tmp = env
    upload(c, make_zip({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY}))
    c.put("/api/plugins/demo", json={"config": {"host": "h"}})
    assert c.delete("/api/plugins/demo").json() == {"removed": "demo"}
    assert c.get("/api/plugins/demo").status_code == 404 and not (tmp / "plugins" / "demo").exists()
    conn = connect(tmp / "t.db")
    assert get_setting(conn, "plugin.demo") is None  # its settings are gone too
    conn.close()
    r = c.delete("/api/plugins/proxmox")
    assert r.status_code == 400 and "built-in" in r.json()["detail"]
    assert c.delete("/api/plugins/nope").status_code == 404


def test_guide_and_example_download(env):
    c, _, tmp = env
    guide = c.get("/api/plugins/guide")
    assert guide.status_code == 200 and "plugin.json" in guide.text and "markdown" in guide.headers["content-type"]
    example = c.get("/api/plugins/example.zip")
    assert example.headers["content-type"] == "application/zip"
    assert upload(c, example.content).status_code == 200  # the template installs as it is


def test_everything_requires_login(env):
    c, _, _ = env
    bad = {"Authorization": "Bearer no"}
    for method, url in [("get", "/api/plugins"), ("get", "/api/plugins/guide"), ("get", "/api/plugins/example.zip"),
                        ("put", "/api/plugins/asus"), ("post", "/api/plugins"), ("delete", "/api/plugins/demo")]:
        assert getattr(c, method)(url, headers=bad).status_code == 401, url
