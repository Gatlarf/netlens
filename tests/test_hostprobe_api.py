"""The host probe API: who may use it, what it validates, and that a partial save leaves the other settings alone."""
import pytest
from fastapi.testclient import TestClient

from app import tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def api(tmp_path):
    tsdb.forget_all()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield tc, app
    tsdb.forget_all()


def test_only_an_administrator_may_use_it(api):
    admin, app = api
    assert admin.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}).status_code == 201
    viewer = TestClient(app)
    assert viewer.post("/api/login", json={"username": "vera", "password": "longenough1"}).status_code == 200
    for method, path in (("get", "/api/hostprobe/settings"), ("put", "/api/hostprobe/settings"), ("post", "/api/hostprobe/ca"), ("get", "/api/hostprobe/setup"),
                         ("get", "/api/hostprobe/uninstall"), ("get", "/api/devices/1/hostprobe"), ("post", "/api/devices/1/hostprobe/run")):
        r = getattr(viewer, method)(path, **({"json": {}} if method == "put" else {}))
        assert r.status_code in (401, 403), (method, path, r.status_code)


def test_a_partial_save_leaves_the_other_settings_alone(api):
    c, _ = api
    c.put("/api/hostprobe/settings", json={"keep_days": 45, "names_to_llm": True, "analysis_auto": True, "analysis_words": "model", "base_url": "https://netlens.example.com"})
    c.put("/api/hostprobe/settings", json={"keep_days": 60})                                 # only this one
    s = c.get("/api/hostprobe/settings").json()
    assert (s["keep_days"], s["names_to_llm"], s["analysis_auto"], s["base_url"]) == (60, True, True, "https://netlens.example.com")
    assert c.put("/api/hostprobe/settings", json={"keep_days": "many"}).status_code == 422
    assert c.put("/api/hostprobe/settings", json={"keep_days": 90, "analysis_words": "poetry"}).status_code == 422       # refused as a whole
    assert c.put("/api/hostprobe/settings", json={"keep_days": 91, "base_url": "ftp://x"}).status_code == 422
    s = c.get("/api/hostprobe/settings").json()
    assert (s["keep_days"], s["analysis_words"]) == (60, "model")


def test_secrets_are_not_returned_and_the_log_names_only_the_fields(api):
    c, _ = api
    out = c.put("/api/hostprobe/settings", json={"providers": {"vault_ssh": {"url": "https://vault.lan", "token": "s.very-secret"}}}).json()
    assert out["providers"]["vault_ssh"]["has_token"] is True and "very-secret" not in str(out)
    audit = [r["action"] for r in connect(c.app.state.db_path).execute("SELECT action FROM audit_log")]
    assert any("providers" not in a and "vault_ssh.token" in a for a in audit) or any("vault_ssh.token" in a for a in audit)
    assert not any("very-secret" in a for a in audit)


def test_the_uninstaller_and_the_setup_check_their_input(api):
    c, _ = api
    r = c.get("/api/hostprobe/uninstall", params={"platform": "linux", "user": "netlens-ro"})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and "netlens-probe-uninstall.sh" in r.headers["content-disposition"]
    assert "Uninstall-NetlensProbe.ps1" in c.get("/api/hostprobe/uninstall", params={"platform": "windows"}).headers["content-disposition"]
    assert c.get("/api/hostprobe/uninstall", params={"platform": "amiga"}).status_code == 422
    assert c.get("/api/hostprobe/uninstall", params={"user": "x;y"}).status_code == 422
    assert c.get("/api/hostprobe/uninstall", params={"user": "a" * 40}).status_code == 422


def test_unknown_devices_and_probes(api):
    c, _ = api
    assert c.get("/api/devices/99/hostprobe/cpu").status_code == 404
    assert c.get("/api/devices/1/hostprobe/nonsense").status_code == 404
    assert c.post("/api/devices/1/hostprobe/run", params={"probe": "rm"}).status_code == 422
    assert c.post("/api/devices/99/hostprobe/run").status_code == 404
    assert c.put("/api/devices/1/hostprobe", json={"provider": "plain"}).status_code == 422
    assert c.put("/api/devices/99/hostprobe", json={"enabled": True}).status_code == 404
    r = c.get("/api/devices/1/hostprobe/cpu").json()
    assert r["probe"] == "cpu" and r["latest"] is None and r["findings"] == []


def test_a_diagnosis_from_the_snapshots_is_read_only_and_kept_under_an_id(api):
    c, _ = api
    r = c.post("/api/devices/1/hostprobe/diagnose", json={"symptom": "the server is slow"})
    assert r.status_code == 200
    body = r.json()
    assert body["read_only"] is True and body["report_id"] and body["report_ref"]
    assert c.post("/api/devices/99/hostprobe/diagnose", json={}).status_code == 404


def test_a_live_diagnosis_is_limited_to_one_a_minute(api, monkeypatch):
    from app.api import hostprobe
    from app.hostprobe import diagnose as engineer

    async def fake(db_path, device_id, symptom, actor=None):
        return {"summary": "x", "findings": [], "looked": []}

    monkeypatch.setattr(engineer, "diagnose_live", fake)
    monkeypatch.setattr(hostprobe.analysis, "create_for_diagnosis", lambda db, diag, how: {"report_id": 1, "report_ref": "R-1", "links": {}})
    hostprobe._LAST_LIVE.clear()
    c, _ = api
    assert c.post("/api/devices/1/hostprobe/diagnose", json={"live": True}).status_code == 200
    assert c.post("/api/devices/1/hostprobe/diagnose", json={"live": True}).status_code == 429
