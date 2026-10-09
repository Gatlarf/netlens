import io
import json
import zipfile
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins import diagnose, registry
from app.plugins.contract import validate_manifest
from app.plugins.runner import run_subprocess
from tests.plugin_helpers import make_runner, write_plugin

ADMIN = {"Authorization": "Bearer secret"}
MANIFEST = {"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology", "diagnose": True,
            "config": [{"key": "url", "type": "text", "label": "URL", "required": True}, {"key": "user", "type": "text", "label": "User"},
                       {"key": "pw", "type": "password", "label": "Password"}, {"key": "tls", "type": "bool", "label": "TLS"}]}
PY = "def test(c):\n    return {'message': 'x'}\ndef fetch(c):\n    return {'nodes': [], 'clients': []}\ndef diagnose(c):\n    return {'shape': {'name': '<text 4 chars>'}, 'echo': c['url'] + ' ' + c['user'] + ' ' + c['pw']}\n"


def manifest(**kw):
    return validate_manifest({**MANIFEST, **kw})


def test_manifest_flag_defaults_to_off_and_must_not_be_required():
    assert manifest()["diagnose"] is True
    assert validate_manifest({k: v for k, v in MANIFEST.items() if k != "diagnose"})["diagnose"] is False


def test_scrub_removes_settings_hosts_and_macs():
    cfg = {"url": "https://nas.example.org:8043/x", "user": "bertvets", "pw": "S3cret-Pass", "tls": False}
    report = {"msg": "login to NAS.example.ORG as BertVets with S3cret-Pass failed", "mac": "aa:bb:cc:dd:ee:01 and AA-BB-CC-DD-EE-02", "n": 5,
              "https://nas.example.org:8043/x": "key", "list": ["x", "version 5.14.26.1"], "nested": {"user": "bertvets"}}
    out = diagnose.scrub(report, manifest(), cfg)
    text = json.dumps(out)
    for private in ("nas.example.org", "bertvets", "S3cret-Pass", "aa:bb:cc", "AA-BB-CC"):
        assert private.lower() not in text.lower(), private
    assert "<setting pw>" in text and "<setting user>" in text and "<mac>" in text
    assert out["n"] == 5 and "5.14.26.1" in text  # numbers and version strings survive


def test_short_values_are_not_scrubbed_everywhere():
    out = diagnose.scrub({"a": "go to ab now"}, manifest(), {"url": "ab", "user": "", "pw": None})
    assert out == {"a": "go to ab now"}


def test_prepare_checks_type_and_size():
    with pytest.raises(diagnose.DiagnoseError, match="dictionary"):
        diagnose.prepare([1], manifest(), {})
    with pytest.raises(diagnose.DiagnoseError, match="too large"):
        diagnose.prepare({"x": "y" * 500_000}, manifest(), {})


def test_the_real_isolated_worker_runs_diagnose(tmp_path):
    folder = write_plugin(tmp_path, py=PY, manifest={"diagnose": True})
    plugin = registry.discover(tmp_path)["demo"]
    result = run_subprocess(plugin, "diagnose", {"url": "https://x.example", "user": "bob", "pw": "pw12345"})
    assert result["echo"] == "https://x.example bob pw12345" and result["shape"]["name"].startswith("<text")  # raw from the plugin: the scrub is Netlens' job


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    app.state.plugin_runner = make_runner(
        demo=SimpleNamespace(test=lambda c: {"message": "ok"}, fetch=lambda c: {"nodes": [], "clients": []},
                             diagnose=lambda c: {"shape": {"k": "<text 1 chars>"}, "echo": f"{c['url']} {c.get('user')} {c.get('pw')}"}),
        plain=SimpleNamespace(test=lambda c: {"message": "ok"}, fetch=lambda c: {"nodes": [], "clients": []}),
    )
    with TestClient(app, headers=ADMIN) as c:
        for plugin_id, flag in (("demo", True), ("plain", False)):
            m = {**MANIFEST, "id": plugin_id, "diagnose": flag}
            r = c.post("/api/plugins", content=make_zip({"plugin.json": json.dumps(m), "plugin.py": PY}), headers={**ADMIN, "Content-Type": "application/zip"})
            assert r.status_code == 200, r.text
        c.app_ = app
        yield c


def test_the_endpoint_returns_a_scrubbed_report(client):
    r = client.post("/api/plugins/demo/diagnose", json={"config": {"url": "https://nas.example.org", "user": "bertvets", "pw": "S3cret-Pass"}})
    assert r.status_code == 200
    body = r.json()
    assert body["plugin"] == "demo" and body["version"] == "1.0.0"
    text = json.dumps(body)
    for private in ("nas.example.org", "bertvets", "S3cret-Pass"):
        assert private not in text
    assert body["report"]["echo"] == "<setting url> <setting user> <setting pw>"


def test_saved_secrets_are_used_and_nothing_is_saved(client):
    client.put("/api/plugins/demo", json={"config": {"url": "https://nas.example.org", "user": "bertvets", "pw": "S3cret-Pass"}})
    r = client.post("/api/plugins/demo/diagnose", json={"config": {"pw": ""}})
    assert r.status_code == 200 and "S3cret-Pass" not in r.text and r.json()["report"]["echo"].endswith("<setting pw>")
    calls = [c for c in client.app_.state.plugin_runner.calls if c[1] == "diagnose"]
    assert calls[-1][2]["pw"] == "S3cret-Pass"  # the saved password reached the plugin


def test_a_plugin_without_a_diagnostic_and_missing_settings(client):
    assert client.post("/api/plugins/plain/diagnose", json={}).status_code == 404
    assert client.post("/api/plugins/nope/diagnose", json={}).status_code == 404
    r = client.post("/api/plugins/demo/diagnose", json={"config": {}})
    assert r.status_code == 422 and "URL" in r.json()["detail"]


def test_a_failing_plugin_is_a_clean_error(client):
    def boom(c):
        raise RuntimeError("controller said no")

    client.app_.state.plugin_runner = make_runner(demo=SimpleNamespace(diagnose=boom))
    r = client.post("/api/plugins/demo/diagnose", json={"config": {"url": "https://nas.example.org"}})
    assert r.status_code == 502 and "controller said no" in r.json()["detail"]


def test_only_administrators_may_run_it(client):
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    vera = TestClient(client.app_)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.post("/api/plugins/demo/diagnose", json={"config": {"url": "x" * 5}}).status_code == 403
    assert TestClient(client.app_).post("/api/plugins/demo/diagnose", json={}).status_code == 401
