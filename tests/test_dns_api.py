"""The DNS feature through Netlens' API, with the real Technitium plugin (its own process) talking to a simulated server."""

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device
from app.main import create_app
from tests.fake_technitium import FakeTechnitium, a_record, ptr_record

Z, R = "home.example.com", "0.168.192.in-addr.arpa"
PLUGIN = Path(__file__).resolve().parents[1] / "plugins" / "technitium"
AUTH = {"Authorization": "Bearer t"}


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    shutil.copytree(PLUGIN, data / "plugins" / "technitium", ignore=shutil.ignore_patterns("__pycache__", "README.md"))
    zones = {
        Z: {"type": "Primary", "records": [a_record(f"nas.{Z}", "192.168.0.7", "managed by Netlens"), a_record(f"desktop-abc.{Z}", "192.168.0.20", "")]},
        R: {"type": "Primary", "records": [ptr_record(f"7.{R}", f"nas.{Z}", "managed by Netlens")]},
    }
    with FakeTechnitium(token="tok", zones=zones) as dnsserver:
        app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(data)}), db_path=tmp_path / "t.db")
        with TestClient(app, headers=AUTH) as client:
            conn = connect(tmp_path / "t.db")
            ids = {}
            for key, ip, host, extra in (
                ("nas", "192.168.0.7", "nas", {}), ("windows", "192.168.0.20", "desktop-abc", {"os_name": "Microsoft Windows 11"}),
                ("printer", "192.168.0.30", "printer", {}), ("stranger", "192.168.0.99", "evil", {"trusted": 0}),
            ):
                d = get_or_create_device(conn, f"02:00:00:00:00:{len(ids) + 1:02x}", ip)
                conn.execute("UPDATE devices SET hostname = ?, trusted = ?, os_name = ?, last_seen = ? WHERE id = ?", (host, extra.get("trusted", 1), extra.get("os_name"), "2026-10-10T11:00:00Z", d))
                ids[key] = d
            conn.commit()
            conn.close()
            client.ids, client.server, client.path, client.data = ids, dnsserver, tmp_path / "t.db", data
            r = client.put("/api/plugins/technitium", json={"enabled": True, "config": {"servers": dnsserver.url, "tokens": "tok", "timeout": 5}})
            assert r.status_code == 200, r.text
            yield client


def setup_dns(client, **extra):
    r = client.put("/api/dns/settings", json={"networks": f"192.168.0.0/24 = {Z}", "grace_hours": 0, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def states(view, client):
    return {name: next(i for i in view["plan"]["items"] if i["device_id"] == did)["state"] for name, did in client.ids.items()}


def test_no_zone_configured_shows_nothing_to_do(env):
    view = env.get("/api/dns").json()
    assert view["plugin"] == "technitium" and view["plugins"][0]["enabled"] is True and view["plan"] is None and view["needs_setup"] is True


def test_settings_are_validated(env):
    assert env.put("/api/dns/settings", json={"networks": "lan = x.example.com"}).status_code == 422
    assert env.put("/api/dns/settings", json={"template": "{evil}"}).status_code == 422
    assert env.put("/api/dns/settings", json={"grace_hours": -1}).status_code == 422
    assert env.put("/api/dns/settings", json={"max_changes": 0}).status_code == 422


def test_preview_then_approve_then_nothing_left(env):
    setup_dns(env)
    view = env.post("/api/dns/refresh").json()
    assert view["snapshot"]["writable"] == sorted([Z, R]) or set(view["snapshot"]["writable"]) == {Z, R}
    assert states(view, env) == {"nas": "ok", "windows": "self", "printer": "add", "stranger": "skip"}
    assert env.server.records(Z) and not any(r["name"] == f"printer.{Z}" for r in env.server.records(Z))      # nothing written by a preview
    ids = [c["id"] for i in view["plan"]["items"] if i["device_id"] == env.ids["printer"] for c in i["changes"]]
    done = env.post("/api/dns/apply", json={"ids": ids})
    assert done.status_code == 200, done.text
    body = done.json()
    assert all(r["ok"] for r in body["results"]) and body["counts"]["added"] == 1
    assert states(body, env)["printer"] == "ok"
    printer = next(r for r in env.server.records(Z) if r["name"] == f"printer.{Z}")
    assert printer["rData"]["ipAddress"] == "192.168.0.30" and printer["comments"] == "managed by Netlens"
    assert [r["rData"]["ipAddress"] for r in env.server.records(Z) if r["name"] == f"desktop-abc.{Z}"] == ["192.168.0.20"]   # the Windows machine's own record
    conn = connect(env.path)
    assert conn.execute("SELECT COUNT(*) FROM dns_records WHERE name = ?", (f"printer.{Z}",)).fetchone()[0] == 1
    assert conn.execute("SELECT kind FROM events WHERE kind = 'dns_registered'").fetchone() is not None
    conn.close()


def test_an_address_change_follows_and_a_foreign_record_is_never_replaced(env):
    setup_dns(env)
    env.post("/api/dns/refresh")
    assert env.post("/api/dns/apply", json={}).status_code == 200            # register the printer
    conn = connect(env.path)
    conn.execute("UPDATE devices SET primary_ip = '192.168.0.31' WHERE id = ?", (env.ids["printer"],))
    conn.commit()
    conn.close()
    view = env.post("/api/dns/refresh").json()
    item = next(i for i in view["plan"]["items"] if i["device_id"] == env.ids["printer"])
    assert item["state"] == "update" and item["changes"][0]["old_value"] == "192.168.0.30"
    assert env.post("/api/dns/apply", json={}).json()["counts"]["updated"] == 1
    assert [r["rData"]["ipAddress"] for r in env.server.records(Z) if r["name"] == f"printer.{Z}"] == ["192.168.0.31"]
    # someone else takes the name meanwhile: the plan says conflict and the server keeps their record
    for r in env.server.records(Z):
        if r["name"] == f"printer.{Z}":
            r["comments"] = ""              # as if the record were not ours any more
            r["rData"]["ipAddress"] = "192.168.0.77"
    conn = connect(env.path)
    conn.execute("DELETE FROM dns_records")      # and Netlens does not remember it either
    conn.commit()
    conn.close()
    view = env.post("/api/dns/refresh").json()
    assert states(view, env)["printer"] == "conflict"
    assert env.post("/api/dns/apply", json={}).status_code == 422             # nothing to apply: conflicts are never applied
    assert [r["rData"]["ipAddress"] for r in env.server.records(Z) if r["name"] == f"printer.{Z}"] == ["192.168.0.77"]


def test_the_limit_per_run_and_unknown_ids(env):
    setup_dns(env, max_changes=1)
    env.post("/api/dns/refresh")
    r = env.post("/api/dns/apply", json={})
    assert r.status_code == 422 and "limit" in r.json()["detail"]                 # the printer needs an A and a PTR change: 2 > 1
    assert env.post("/api/dns/apply", json={"ids": ["nope"]}).status_code == 422


def test_known_only_and_the_override_name(env):
    setup_dns(env)
    assert states(env.post("/api/dns/refresh").json(), env)["stranger"] == "skip"
    conn = connect(env.path)
    conn.execute("UPDATE devices SET dns_name = 'Print Server', dns_mode = 'auto' WHERE id = ?", (env.ids["printer"],))
    conn.commit()
    conn.close()
    view = env.get("/api/dns").json()
    assert next(i for i in view["plan"]["items"] if i["device_id"] == env.ids["printer"])["name"] == f"print-server.{Z}"


def test_viewers_cannot_use_it():
    from app.auth import VIEWER_READABLE

    assert not VIEWER_READABLE.match("/api/dns")      # administrators only (settings and approvals)


def test_a_server_that_is_down_gives_a_clear_error(env):
    setup_dns(env)
    env.server.stop()
    r = env.post("/api/dns/refresh")
    assert r.status_code == 502 and "cannot reach" in r.json()["detail"]


def test_automatic_mode_writes_after_a_scan_but_never_removes(env):
    import asyncio

    from app.plugins.service import PluginService

    setup_dns(env, auto_apply=True)
    asyncio.run(PluginService(str(env.path), env.data).after_scan())
    assert any(r["name"] == f"printer.{Z}" for r in env.server.records(Z))
    assert [r["rData"]["ipAddress"] for r in env.server.records(Z) if r["name"] == f"desktop-abc.{Z}"] == ["192.168.0.20"]
    # a record Netlens made for a device that is gone stays (removal is off)
    conn = connect(env.path)
    conn.execute("DELETE FROM devices WHERE id = ?", (env.ids["printer"],))
    conn.commit()
    conn.close()
    asyncio.run(PluginService(str(env.path), env.data).after_scan())
    assert any(r["name"] == f"printer.{Z}" for r in env.server.records(Z))


def test_device_fields_for_dns(env):
    d = env.ids["printer"]
    assert env.get(f"/api/devices/{d}").json()["dns_mode"] == "auto"
    r = env.patch(f"/api/devices/{d}", json={"dns_mode": "never", "dns_name": "Print Server"})
    assert r.status_code == 200 and r.json()["dns_mode"] == "never" and r.json()["dns_name"] == "Print Server"
    assert env.patch(f"/api/devices/{d}", json={"dns_mode": "sometimes"}).status_code == 422
    assert env.patch(f"/api/devices/{d}", json={"dns_name": "!!!"}).status_code == 422
    assert env.patch(f"/api/devices/{d}", json={"dns_name": ""}).json()["dns_name"] is None


def test_container_aliases_through_the_api(env):
    conn = connect(env.path)
    details = json.dumps({"network_driver": "bridge", "ports": [{"host_port": 8080, "container_port": 80, "proto": "tcp", "bind": "0.0.0.0"}]})
    for gid, name, status, device in (("h/web", "web", "running", None), ("h/idle", "idle", "running", None), ("h/off", "off", "exited", None), ("h/own", "own", "running", env.ids["printer"])):
        conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated, details, device_id, host_device_id) VALUES ('docker', ?, ?, 'container', 'nas', ?, 'now', ?, ?, ?)",
                     (gid, name, status, details if name != "idle" else json.dumps({"network_driver": "bridge"}), device, env.ids["nas"]))
    conn.commit()
    conn.close()
    setup_dns(env, register_containers=True)
    view = env.post("/api/dns/refresh").json()
    aliases = [i for i in view["plan"]["items"] if i["id"].startswith("c:")]
    assert [(i["name"], i["state"]) for i in aliases] == [(f"web.{Z}", "add")]          # not "idle" (no port), "off" (stopped) or "own" (a device itself)
    assert aliases[0]["device"] == "container web"
    r = env.post("/api/dns/apply", json={"ids": [aliases[0]["changes"][0]["id"]]})
    assert r.status_code == 200 and r.json()["counts"]["added"] == 1, r.text
    records = [x for x in env.server.zones[Z]["records"] if x["name"] == f"web.{Z}"]
    assert records and records[0]["type"] == "CNAME" and records[0]["rData"]["cname"] == f"nas.{Z}" and records[0]["comments"] == "managed by Netlens"
    again = env.post("/api/dns/refresh").json()["plan"]["items"]
    assert next(i for i in again if i["id"].startswith("c:"))["state"] == "ok"
