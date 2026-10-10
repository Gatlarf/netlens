import json

import pytest

from app.db import connect, get_or_create_device, get_setting, init_db, set_setting
from app.hierarchy import build_hierarchy
from app.plugins.registry import discover
from app.plugins.service import PluginService, apply_plugin, clear_plugin_data, get_state, get_status, merge_config, save_state
from app.scanner.relations import Edge
from app.scanner.relstore import add_manual, delete_relation, list_relations, replace_inferred
from tests.plugin_helpers import fake, make_runner, write_plugin

HV = {
    "hosts": [{"id": "pve1", "name": "pve1", "ip": "10.0.0.5"}],
    "guests": [
        {"id": "100", "name": "web", "kind": "lxc", "host_id": "pve1", "status": "running", "macs": ["02:00:00:00:00:64"], "ips": ["10.0.0.64"]},
        {"id": "101", "name": "db", "kind": "qemu", "host_id": "pve1", "status": "running", "macs": ["02:00:00:00:00:65"], "ips": []},
        {"id": "102", "name": "off", "kind": "lxc", "host_id": "pve1", "status": "stopped", "macs": ["02:00:00:00:00:99"], "ips": []},
    ],
}
MAIN, N1 = "aa:00:00:00:00:10", "aa:00:00:00:00:20"
TOPO = {
    "nodes": [
        {"mac": MAIN, "ip": "10.0.0.1", "name": "Main", "role": "gateway"},
        {"mac": N1, "ip": "10.0.0.50", "name": "Garden", "role": "node", "parent_mac": MAIN},
    ],
    "clients": [
        {"mac": "02:00:00:00:00:01", "ip": "10.0.0.11", "node_mac": MAIN, "medium": "wired"},
        {"mac": "02:00:00:00:00:02", "ip": "10.0.0.12", "node_mac": N1, "medium": "wifi", "band": "5 GHz"},
        {"mac": "02:00:00:00:00:77", "ip": "10.0.0.13", "node_mac": N1, "medium": "wired"},  # matched by IP below
    ],
}


class AuthRefused(Exception):
    auth_failed = True


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    ids = {
        "host": get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.5"),
        "web": get_or_create_device(conn, "02:00:00:00:00:64", "10.0.0.64"),
        "db": get_or_create_device(conn, "02:00:00:00:00:65", "10.0.0.65"),
        "other": get_or_create_device(conn, "aa:00:00:00:00:77", "10.0.0.77"),
        "main": get_or_create_device(conn, MAIN, "10.0.0.1"),
        "garden": get_or_create_device(conn, None, "10.0.0.50"),  # no MAC seen: matched by IP
        "wired": get_or_create_device(conn, "02:00:00:00:00:01", "10.0.0.11"),
        "wifi": get_or_create_device(conn, "02:00:00:00:00:02", "10.0.0.12"),
        "byip": get_or_create_device(conn, None, "10.0.0.13"),
    }
    conn.close()
    return path, ids


CONFIG = {"url": "https://pve.test:8006", "token_id": "a", "token_secret": "b"}
ASUS_CONFIG = {"url": "10.0.0.1", "username": "u", "password": "pw"}


def enable(path, plugin_id, config):
    conn = connect(path)
    save_state(conn, plugin_id, True, merge_config(discover(None)[plugin_id], {}, config))
    conn.close()


def service(path, tmp_path, **fakes):
    runner = make_runner(**fakes)
    svc = PluginService(str(path), tmp_path, runner)
    svc.runner_calls = runner.calls
    return svc


def edges(path):
    conn = connect(path)
    try:
        return {(r["src_id"], r["dst_id"], r["kind"], r["source"], r["manual"]) for r in list_relations(conn)}
    finally:
        conn.close()


# ------------------------------------------------------------------ hypervisor
@pytest.mark.asyncio
async def test_hypervisor_sync_stores_guests_and_links_and_survives_reinference(db, tmp_path):
    path, ids = db
    enable(path, "proxmox", CONFIG)
    svc = service(path, tmp_path, proxmox=fake(fetch=lambda cfg: HV))
    result = await svc.sync("proxmox")
    assert result == {"hosts": 1, "hosts_matched": 1, "guests": 3, "guests_matched": 2, "links": 2}
    assert edges(path) == {
        (ids["web"], ids["host"], "host-of", "plugin:proxmox", 0),
        (ids["db"], ids["host"], "host-of", "plugin:proxmox", 0),
    }
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM hypervisor_guests WHERE plugin_id='proxmox'").fetchone()[0] == 3
    assert get_status(conn, "proxmox")["ok"] is True
    # a scan re-infers relations (wiping every non-manual edge, with a wrong heuristic guess for 'web') ...
    replace_inferred(conn, [Edge(ids["web"], ids["other"], "host-of", "heuristic", 0.5)])
    conn.close()
    await svc.after_scan()  # ... and the hook puts the plugin's links back, dropping the guess
    assert edges(path) == {
        (ids["web"], ids["host"], "host-of", "plugin:proxmox", 0),
        (ids["db"], ids["host"], "host-of", "plugin:proxmox", 0),
    }


@pytest.mark.asyncio
async def test_user_deleted_link_stays_hidden_and_manual_links_are_untouched(db, tmp_path):
    path, ids = db
    enable(path, "proxmox", CONFIG)
    svc = service(path, tmp_path, proxmox=fake(fetch=lambda cfg: HV))
    await svc.sync("proxmox")
    conn = connect(path)
    rel = next(r for r in list_relations(conn) if r["src_id"] == ids["web"])
    assert delete_relation(conn, rel["id"]) is True
    add_manual(conn, ids["db"], ids["other"], "manual")
    conn.close()
    await svc.sync("proxmox")
    raw = connect(path).execute("SELECT src_id, dst_id, kind, manual FROM relations").fetchall()
    raw = {tuple(r) for r in raw}
    assert (ids["web"], ids["host"], "host-of", -1) in raw and (ids["web"], ids["host"], "host-of", 0) not in raw
    assert (ids["db"], ids["host"], "host-of", 0) in raw and (ids["db"], ids["other"], "manual", 1) in raw


@pytest.mark.asyncio
async def test_guest_moving_to_another_host_updates_the_link(db, tmp_path):
    path, ids = db
    enable(path, "proxmox", CONFIG)
    moved = json.loads(json.dumps(HV))
    moved["hosts"] = [{"id": "pve2", "name": "pve2", "ip": "10.0.0.77"}]
    for g in moved["guests"]:
        g["host_id"] = "pve2"
    data = {"v": HV}
    svc = service(path, tmp_path, proxmox=fake(fetch=lambda cfg: data["v"]))
    await svc.sync("proxmox")
    data["v"] = moved
    await svc.sync("proxmox")
    assert {(e[0], e[1]) for e in edges(path)} == {(ids["web"], ids["other"]), (ids["db"], ids["other"])}


@pytest.mark.asyncio
async def test_failure_keeps_last_data_and_invalid_output_is_rejected(db, tmp_path):
    path, ids = db
    enable(path, "proxmox", CONFIG)
    state = {"out": HV}

    def fetch(cfg):
        if isinstance(state["out"], Exception):
            raise state["out"]
        return state["out"]

    svc = service(path, tmp_path, proxmox=fake(fetch=fetch))
    await svc.sync("proxmox")
    before = edges(path)

    state["out"] = RuntimeError("timed out")
    assert await svc.sync("proxmox") == {"error": "timed out", "auth_failed": False}
    assert edges(path) == before
    state["out"] = {"hosts": [], "guests": [{"id": "1", "name": "x", "host_id": "ghost"}]}
    result = await svc.sync("proxmox")
    assert "does not follow the contract" in result["error"] and "host_id" in result["error"]
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM hypervisor_guests").fetchone()[0] == 3  # last good data kept
    assert get_status(conn, "proxmox")["ok"] is False
    conn.close()
    assert edges(path) == before


@pytest.mark.asyncio
async def test_not_configured_plugin_is_not_called(db, tmp_path):
    path, ids = db
    conn = connect(path)
    save_state(conn, "proxmox", True, {"url": ""})
    conn.close()
    svc = service(path, tmp_path, proxmox=fake())
    assert "not configured" in (await svc.sync("proxmox"))["error"]
    assert svc.runner_calls == []
    assert (await svc.sync("nope"))["error"] == "no such plugin"


# ------------------------------------------------------------------ topology
@pytest.mark.asyncio
async def test_topology_sync_creates_uplinks_with_the_plugin_as_source(db, tmp_path):
    path, ids = db
    enable(path, "asus", ASUS_CONFIG)
    svc = service(path, tmp_path, asus=fake(fetch=lambda cfg: TOPO))
    assert await svc.sync("asus") == {"nodes": 2, "clients": 3, "links": 4, "samples": 1, "roams": 0}  # one Wi-Fi client
    assert edges(path) == {
        (ids["garden"], ids["main"], "uplink", "plugin:asus", 0),
        (ids["wired"], ids["main"], "uplink", "plugin:asus", 0),
        (ids["wifi"], ids["garden"], "uplink", "plugin:asus", 0),
        (ids["byip"], ids["garden"], "uplink", "plugin:asus", 0),
    }


@pytest.mark.asyncio
async def test_hierarchy_ranks_hypervisor_over_uplink_over_gateway(db, tmp_path):
    path, ids = db
    enable(path, "asus", ASUS_CONFIG)
    enable(path, "proxmox", CONFIG)
    svc = service(path, tmp_path, asus=fake(fetch=lambda cfg: TOPO), proxmox=fake(fetch=lambda cfg: HV))
    conn = connect(path)
    replace_inferred(conn, [Edge(ids["wifi"], ids["other"], "gateway", "heuristic", 0.9), Edge(ids["web"], ids["other"], "gateway", "default-route", 1.0)])
    conn.close()
    await svc.after_scan()
    conn = connect(path)
    devices = [dict(r) for r in conn.execute("SELECT id, parent_mode, parent_device_id FROM devices")]
    rels = [dict(r) for r in conn.execute("SELECT src_id, dst_id, kind, source, confidence FROM relations WHERE manual >= 0")]
    conn.close()
    h = build_hierarchy(devices, rels)
    assert (h[ids["wifi"]].parent_id, h[ids["wifi"]].source) == (ids["garden"], "uplink") and "asus" in h[ids["wifi"]].reason
    assert (h[ids["web"]].parent_id, h[ids["web"]].source) == (ids["host"], "hypervisor") and "proxmox" in h[ids["web"]].reason


@pytest.mark.asyncio
async def test_refused_login_pauses_the_hook_but_links_stay(db, tmp_path):
    path, ids = db
    enable(path, "asus", ASUS_CONFIG)
    state = {"out": TOPO}

    def fetch(cfg):
        if isinstance(state["out"], Exception):
            raise state["out"]
        return state["out"]

    svc = service(path, tmp_path, asus=fake(fetch=fetch))
    await svc.sync("asus")
    before = edges(path)
    state["out"] = AuthRefused("login refused")
    await svc.sync("asus")
    conn = connect(path)
    assert get_status(conn, "asus")["auth_failed"] is True
    replace_inferred(conn, [])
    conn.close()
    n = len(svc.runner_calls)
    await svc.after_scan()
    assert len(svc.runner_calls) == n  # not asked again
    assert edges(path) == before  # but the last known links are back on the map
    # saving or syncing by hand is allowed to try again
    state["out"] = TOPO
    assert "error" not in await svc.sync("asus")
    assert get_status(connect(path), "asus")["ok"] is True


@pytest.mark.asyncio
async def test_one_failing_plugin_does_not_stop_the_others(db, tmp_path):
    path, ids = db
    enable(path, "asus", ASUS_CONFIG)
    enable(path, "proxmox", CONFIG)

    def boom(cfg):
        raise RuntimeError("down")

    svc = service(path, tmp_path, asus=fake(fetch=boom), proxmox=fake(fetch=lambda cfg: HV))
    await svc.after_scan()
    assert {e[3] for e in edges(path)} == {"plugin:proxmox"}


@pytest.mark.asyncio
async def test_disabled_plugins_are_not_called(db, tmp_path):
    path, ids = db
    conn = connect(path)
    save_state(conn, "asus", False, ASUS_CONFIG)
    conn.close()
    svc = service(path, tmp_path, asus=fake(fetch=lambda cfg: TOPO))
    await svc.after_scan()
    assert svc.runner_calls == [] and edges(path) == set()


@pytest.mark.asyncio
async def test_turning_a_plugin_off_removes_its_links_and_guests(db, tmp_path):
    path, ids = db
    enable(path, "proxmox", CONFIG)
    svc = service(path, tmp_path, proxmox=fake(fetch=lambda cfg: HV))
    await svc.sync("proxmox")
    conn = connect(path)
    clear_plugin_data(conn, "proxmox")
    assert conn.execute("SELECT COUNT(*) FROM hypervisor_guests").fetchone()[0] == 0
    conn.close()
    assert edges(path) == set()


@pytest.mark.asyncio
async def test_user_plugin_with_real_subprocess_end_to_end(db, tmp_path):
    path, ids = db
    write_plugin(tmp_path, "demo", py=f"def test(config):\n    return {{}}\ndef fetch(config):\n    return {json.dumps(TOPO)}\n")
    conn = connect(path)
    save_state(conn, "demo", True, {"host": "h", "secret": ""})
    conn.close()
    svc = PluginService(str(path), tmp_path)  # the real runner
    assert (await svc.sync("demo"))["links"] == 4


# ------------------------------------------------------------------ state
def test_state_defaults_and_secret_handling(tmp_path):
    path = tmp_path / "s.db"
    conn = connect(path)
    init_db(conn)
    plugin = discover(None)["asus"]
    assert get_state(conn, plugin) == {"enabled": False, "config": {"url": "", "verify_tls": False, "username": "", "password": ""}}
    cfg = merge_config(plugin, {}, {"url": "10.0.0.1", "username": "u", "password": "pw", "junk": 1})
    save_state(conn, "asus", True, cfg)
    again = merge_config(plugin, get_state(conn, plugin)["config"], {"username": "v", "password": ""})  # empty secret keeps the old one
    assert again["password"] == "pw" and again["username"] == "v" and "junk" not in again
    conn.close()


# ------------------------------------------------------------------ migration from schema v4
def test_v4_database_is_migrated_to_plugins(tmp_path):
    path = tmp_path / "v4.db"
    conn = connect(path)
    init_db(conn)
    host = get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.5")
    web = get_or_create_device(conn, "02:00:00:00:00:64", "10.0.0.64")
    conn.execute("DROP TABLE hypervisor_guests")
    conn.execute(
        "CREATE TABLE proxmox_guests (vmid INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, node TEXT NOT NULL, "
        "status TEXT NOT NULL, macs TEXT NOT NULL DEFAULT '[]', ips TEXT NOT NULL DEFAULT '[]', device_id INTEGER, host_device_id INTEGER, updated TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO proxmox_guests VALUES (100, 'web', 'lxc', 'pve1', 'running', '[]', '[]', ?, ?, '2026-01-01T00:00:00Z')", (web, host))
    set_setting(conn, "proxmox", json.dumps({"enabled": True, "url": "https://pve:8006", "verify_tls": False, "username": "", "password": "", "token_id": "t", "token_secret": "s"}))
    set_setting(conn, "proxmox_status", json.dumps({"ts": "x", "ok": True, "guests": 1}))
    set_setting(conn, "asus", json.dumps({"enabled": True, "url": "https://r:8443", "verify_tls": False, "username": "u", "password": "p"}))
    set_setting(conn, "asus_snapshot", json.dumps({
        "nodes": [{"mac": MAIN, "macs": [MAIN], "ip": "10.0.0.1", "name": "Main", "model": None, "main": True, "wired_macs": []}],
        "clients": [{"mac": "02:00:00:00:00:01", "ip": "10.0.0.11", "name": None, "wired": True, "band": None, "node_mac": None}],
    }))
    conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'host-of', 'proxmox', 1.0, 0)", (web, host))
    conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'uplink', 'asus-mesh', 1.0, 0)", (host, web))
    conn.execute("UPDATE schema_version SET version = 4")
    conn.commit()
    conn.close()

    conn = connect(path)
    init_db(conn)
    init_db(conn)  # idempotent
    assert "proxmox_guests" not in {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    row = conn.execute("SELECT plugin_id, guest_id, host_name, device_id FROM hypervisor_guests").fetchone()
    assert tuple(row) == ("proxmox", "100", "pve1", web)
    pm = discover(None)["proxmox"]
    state = get_state(conn, pm)
    assert state["enabled"] is True and state["config"]["servers"][0]["token_id"] == "t" and state["config"]["verify_tls"] is False
    assert get_status(conn, "proxmox")["guests"] == 1
    assert get_state(conn, discover(None)["asus"])["config"]["username"] == "u"
    data = json.loads(get_setting(conn, "plugin.asus.data"))
    assert data["nodes"][0]["role"] == "gateway" and data["clients"][0]["node_mac"] == MAIN
    for old in ("proxmox", "proxmox_status", "asus", "asus_status", "asus_snapshot"):
        assert get_setting(conn, old) is None
    assert {r["source"] for r in conn.execute("SELECT source FROM relations")} == {"plugin:proxmox", "plugin:asus"}
    # applying a plugin that has no stored output yet changes nothing (data from the old version stays until the first sync)
    apply_plugin(conn, pm)
    assert conn.execute("SELECT COUNT(*) FROM hypervisor_guests").fetchone()[0] == 1
    conn.close()
