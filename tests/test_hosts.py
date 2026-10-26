"""Hosts: set up or remove monitoring for many hosts in one go; one failing host never stops the others."""

import json

import pytest
from fastapi.testclient import TestClient

from app import hosts
from app.config import load_settings
from app.db import connect
from app.hostmetrics import service as hm
from app.hostprobe import installer, service as probes
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)

    async def fake_read(db_path, monitor_id, now_ts=None):
        return {"ok": True, "error": None, "events": []}

    monkeypatch.setattr(hm, "run_monitor", fake_read)
    looks = []

    async def fake_first_look(db_path, device_id, actor=None):
        looks.append(device_id)
        return {"ok": True, "data": {"script_version": 7}}

    monkeypatch.setattr(probes, "first_look", fake_first_look)
    with TestClient(app, headers=AUTH) as c:
        conn = connect(db)
        for i, ports in ((1, [22]), (2, [22]), (3, [5986]), (4, [])):
            conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, 'x', 'x')", (i, f"aa:bb:cc:dd:ee:0{i}", f"192.168.1.{i}", f"h{i}"))
            for p in ports:
                conn.execute("INSERT INTO ports (device_id, proto, port, state, updated) VALUES (?, 'tcp', ?, 'open', 'x')", (i, p))
        conn.commit()
        conn.close()
        c.db = db
        c.looks = looks
        yield c


def test_the_overview_says_how_each_host_can_be_reached(client):
    got = {h["name"]: h for h in client.get("/api/hosts").json()["hosts"]}
    assert [got[n]["can_monitor"] for n in ("h1", "h2", "h3", "h4")] == ["ssh", "ssh", "winrm", None]
    assert got["h1"]["monitor"] is None and got["h1"]["probes"]["enabled"] is False


def test_basic_monitoring_for_several_hosts_with_one_stored_login(client):
    cred = client.post("/api/credentials", json={"name": "Monitor", "kind": "login", "username": "mon", "password": "pw"}).json()
    r = client.post("/api/hosts/apply", json={"device_ids": [1, 2, 3, 4], "level": "basic", "credential_id": cred["id"]}).json()
    assert (r["done"], r["failed"]) == (3, 1)
    assert [x["error"] for x in r["results"] if not x["ok"]] == ["neither SSH nor WinRM is open on this host"]
    conn = connect(client.db)
    assert [hm.get_monitor(conn, i)["method"] for i in (1, 2, 3)] == ["ssh", "ssh", "winrm"]
    assert hm.load_secret(conn, hm.get_monitor(conn, 3))["password"] == "pw"
    conn.close()
    shown = {h["name"]: h for h in client.get("/api/hosts").json()["hosts"]}
    assert shown["h1"]["monitor"]["login"] == "Monitor"
    audit = client.get("/api/audit?limit=20")
    assert "pw" not in audit.text or audit.status_code != 200


def test_probes_are_installed_with_an_administrator_login_that_is_not_kept(client, monkeypatch):
    cred = client.post("/api/credentials", json={"name": "Monitor", "kind": "login", "username": "mon", "password": "pw"}).json()
    seen = []

    async def fake_administer(conn, device_id, action, admin, probe_user=None, enable_sshd=False, allow_from=""):
        seen.append((device_id, action, admin["username"], admin["password"]))
        if device_id == 2:
            return {"ok": False, "action": action, "log": ["Error: sudo asked for a password"], "error": "sudo asked for a password"}
        return {"ok": True, "action": action, "log": [f"Installed on {device_id}"], "verified": {"ok": True}}

    monkeypatch.setattr(installer, "administer", fake_administer)
    r = client.post("/api/hosts/apply", json={"device_ids": [1, 2], "level": "probes", "credential_id": cred["id"], "admin_username": "bert", "admin_password": "adminpw"}).json()
    assert (r["done"], r["failed"]) == (1, 1) and sorted(s[0] for s in seen) == [1, 2] and {s[1:] for s in seen} == {("install", "bert", "adminpw")}
    assert client.looks == [1]                                          # the host that was installed is looked at once, right away; the one that failed is not
    assert any("Looked at the host once: it runs script version 7" in step for step in r["results"][0]["steps"])
    conn = connect(client.db)
    assert probes.device_config(conn, 1)["enabled"] is True and probes.device_config(conn, 2)["enabled"] is False
    dump = json.dumps([dict(x) for x in conn.execute("SELECT action FROM audit_log")])
    assert "adminpw" not in dump
    lines = [x["action"] for x in conn.execute("SELECT action FROM audit_log WHERE path = '/api/hosts/apply' ORDER BY id")]
    assert any(l.startswith("Host setup, h1: installed the read-only probe") and "administrator login 'bert' (typed, used once, not stored)" in l and "Installed on 1" in l for l in lines)
    assert any(l.startswith("Host setup, h2:") and "FAILED (sudo asked for a password)" in l for l in lines)
    assert "adminpw" not in str(conn.execute("SELECT value FROM settings").fetchall())
    conn.close()


def test_remove_takes_the_probe_off_and_deletes_the_monitor(client, monkeypatch):
    cred = client.post("/api/credentials", json={"name": "Monitor", "kind": "login", "username": "mon", "password": "pw"}).json()
    client.post("/api/hosts/apply", json={"device_ids": [1], "level": "basic", "credential_id": cred["id"]})
    conn = connect(client.db)
    probes.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    conn.close()
    calls = []

    async def fake_administer(conn, device_id, action, admin, probe_user=None, enable_sshd=False, allow_from=""):
        calls.append(action)
        return {"ok": True, "action": action, "log": ["Removed"]}

    monkeypatch.setattr(installer, "administer", fake_administer)
    r = client.post("/api/hosts/apply", json={"device_ids": [1], "level": "remove", "admin_username": "bert", "admin_password": "x"}).json()
    assert r["done"] == 1 and calls == ["remove"]
    conn = connect(client.db)
    assert hm.get_monitor(conn, 1) is None and probes.device_config(conn, 1)["enabled"] is False
    conn.close()
    assert client.post("/api/hosts/apply", json={"device_ids": [], "level": "basic"}).status_code == 422
    assert client.post("/api/hosts/apply", json={"device_ids": [1], "level": "nope"}).status_code == 422


def test_the_assistant_and_the_built_in_answers_know_the_coverage(client):
    from app import ask, ask_extra

    ask_extra.register()
    conn = connect(client.db)
    got = ask.answer(conn, "Which hosts are not monitored yet?", mode="rules")
    assert got["tools"] and "h1" in got["answer"] and "can be monitored" in got["answer"]
    conn.close()
    from app import mcp

    assert mcp.TOOLS["get_monitoring_coverage"]["path"] == "/api/hosts"
