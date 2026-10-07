import json

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.integrations.proxmox_client import ProxmoxError
from app.integrations.proxmox_config import ProxmoxConfig, save_config
from app.integrations.proxmox_sync import apply_proxmox_relations, proxmox_after_scan, store_inventory, sync_now
from app.main import create_app
from app.scanner.relations import Edge
from app.scanner.relstore import add_manual, delete_relation, list_relations, replace_inferred

AUTH = {"Authorization": "Bearer secret"}

INVENTORY = {
    "nodes": [{"name": "pve1", "ip": "10.0.0.5", "online": True}],
    "guests": [
        {"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["02:00:00:00:00:64"], "ips": ["10.0.0.64"]},
        {"vmid": 101, "name": "db", "kind": "qemu", "node": "pve1", "status": "running", "macs": ["02:00:00:00:00:65"], "ips": []},
        {"vmid": 102, "name": "off", "kind": "lxc", "node": "pve1", "status": "stopped", "macs": ["02:00:00:00:00:99"], "ips": []},
    ],
}


class FakeClient:
    inventory_data = INVENTORY
    error = None

    def __init__(self, cfg):
        self.cfg = cfg

    def version(self):
        if FakeClient.error:
            raise ProxmoxError(FakeClient.error)
        return "9.2.11"

    def inventory(self):
        if FakeClient.error:
            raise ProxmoxError(FakeClient.error)
        return FakeClient.inventory_data


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeClient.inventory_data, FakeClient.error = INVENTORY, None


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
    }
    conn.close()
    return path, ids


def _edges(path):
    conn = connect(path)
    try:
        return {(r["src_id"], r["dst_id"], r["kind"], r["source"], r["manual"]) for r in list_relations(conn)}
    finally:
        conn.close()


def test_store_and_relations_survive_reinference(db):
    path, ids = db
    conn = connect(path)
    summary = store_inventory(conn, INVENTORY)
    assert summary == {"nodes": 1, "hosts_matched": 1, "guests": 3, "guests_matched": 2}
    assert apply_proxmox_relations(conn) == 2
    conn.close()
    assert _edges(path) == {
        (ids["web"], ids["host"], "host-of", "proxmox", 0),
        (ids["db"], ids["host"], "host-of", "proxmox", 0),
    }

    # a scan re-infers relations, wiping every non-manual edge, with a wrong heuristic guess for 'web'
    conn = connect(path)
    replace_inferred(conn, [Edge(ids["web"], ids["other"], "host-of", "heuristic", 0.5)])
    assert (ids["web"], ids["other"], "host-of", "heuristic", 0) in _edges(path)
    apply_proxmox_relations(conn)
    conn.close()
    edges = _edges(path)
    assert (ids["web"], ids["host"], "host-of", "proxmox", 0) in edges
    assert not any(e[3] == "heuristic" for e in edges)  # the wrong guess is gone


def test_user_deleted_edge_stays_hidden_and_manual_edge_untouched(db):
    path, ids = db
    conn = connect(path)
    store_inventory(conn, INVENTORY)
    apply_proxmox_relations(conn)
    rel = next(r for r in list_relations(conn) if r["src_id"] == ids["web"])
    assert delete_relation(conn, rel["id"]) is True  # user removes it from the map
    add_manual(conn, ids["db"], ids["other"], "manual")
    apply_proxmox_relations(conn)
    raw = {
        (r["src_id"], r["dst_id"], r["kind"], r["manual"])
        for r in conn.execute("SELECT src_id, dst_id, kind, manual FROM relations")
    }
    conn.close()
    assert (ids["web"], ids["host"], "host-of", -1) in raw  # deletion marker kept, edge not resurrected
    assert (ids["web"], ids["host"], "host-of", 0) not in raw
    assert (ids["db"], ids["host"], "host-of", 0) in raw  # other guest unaffected
    assert (ids["db"], ids["other"], "manual", 1) in raw  # manual edge untouched
    assert not any(e[0] == ids["web"] for e in _edges(path))  # and it stays hidden from the map


def test_guest_moving_to_another_host_updates_edge(db):
    path, ids = db
    conn = connect(path)
    store_inventory(conn, INVENTORY)
    apply_proxmox_relations(conn)
    moved = json.loads(json.dumps(INVENTORY))
    moved["nodes"] = [{"name": "pve2", "ip": "10.0.0.77", "online": True}]
    for g in moved["guests"]:
        g["node"] = "pve2"
    store_inventory(conn, moved)
    apply_proxmox_relations(conn)
    conn.close()
    assert {(e[0], e[1]) for e in _edges(path)} == {(ids["web"], ids["other"]), (ids["db"], ids["other"])}


@pytest.mark.asyncio
async def test_sync_now_and_failure_keeps_last_data(db):
    path, ids = db
    conn = connect(path)
    save_config(conn, ProxmoxConfig(enabled=True, url="https://pve.test:8006", token_id="a", token_secret="b"))
    conn.close()

    result = await sync_now(str(path), client_factory=FakeClient)
    assert result["guests"] == 3 and result["links"] == 2

    FakeClient.error = "authentication failed"
    result = await sync_now(str(path), client_factory=FakeClient)
    assert result == {"error": "authentication failed"}
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM proxmox_guests").fetchone()[0] == 3  # last good data kept
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key = 'proxmox_status'").fetchone()[0])["ok"] is False
    conn.close()


@pytest.mark.asyncio
async def test_hook_does_nothing_when_disabled(db):
    path, ids = db
    conn = connect(path)
    save_config(conn, ProxmoxConfig(enabled=False, url="https://pve.test:8006", token_id="a", token_secret="b"))
    conn.close()
    await proxmox_after_scan(str(path))
    conn = connect(path)
    assert conn.execute("SELECT COUNT(*) FROM proxmox_guests").fetchone()[0] == 0
    conn.close()


def _client(path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    app.state.proxmox_factory = FakeClient
    return TestClient(app, headers=AUTH)


def test_api_flow_masks_secrets_and_syncs_on_enable(db):
    path, ids = db
    with _client(path) as c:
        body = {"url": "10.0.0.5", "token_id": "u@pam!nl", "token_secret": "TOPSECRET", "verify_tls": False, "enabled": True}
        r = c.put("/api/proxmox", json=body)
        assert r.status_code == 200
        out = r.json()
        assert out["url"] == "https://10.0.0.5:8006" and out["enabled"] is True and out["auth_method"] == "token"
        assert out["token_secret_set"] is True and "TOPSECRET" not in r.text
        assert out["status"]["ok"] is True and out["status"]["guests"] == 3  # synced immediately

        # partial update keeps the secret; the stored value is intact
        c.put("/api/proxmox", json={"verify_tls": True})
        conn = connect(path)
        assert json.loads(conn.execute("SELECT value FROM settings WHERE key='proxmox'").fetchone()[0])["token_secret"] == "TOPSECRET"
        conn.close()

        edges = {(e["from"], e["to"], e["kind"]) for e in c.get("/api/map").json()["edges"]}
        assert (ids["web"], ids["host"], "host-of") in edges and (ids["db"], ids["host"], "host-of") in edges
        # disabling removes the connector's edges but keeps stored guests
        c.put("/api/proxmox", json={"enabled": False})
        assert not any(e[3] == "proxmox" for e in _edges(path))


@pytest.mark.parametrize("payload", [
    {"enabled": True},
    {"url": "ftp://x"},
    {"enabled": True, "url": "10.0.0.5"},  # no credentials
])
def test_api_validation(db, payload):
    path, ids = db
    with _client(path) as c:
        assert c.put("/api/proxmox", json=payload).status_code == 422


def test_api_test_and_sync_endpoints(db):
    path, ids = db
    with _client(path) as c:
        r = c.post("/api/proxmox/test", json={"url": "10.0.0.5", "username": "root@pam", "password": "pw"})
        assert r.json() == {"ok": True, "version": "9.2.11", "nodes": 1, "guests": 3}
        assert c.get("/api/proxmox").json()["configured"] is False  # test saves nothing
        assert c.post("/api/proxmox/test", json={}).status_code == 422

        FakeClient.error = "the TLS certificate could not be verified"
        r = c.post("/api/proxmox/test", json={"url": "10.0.0.5", "username": "root@pam", "password": "pw"})
        assert r.status_code == 502 and "TLS" in r.json()["detail"]

        assert c.post("/api/proxmox/sync").status_code == 502  # not configured
        assert c.post("/api/proxmox/sync", headers={"Authorization": "Bearer no"}).status_code == 401


def test_device_detail_shows_proxmox_role(db):
    path, ids = db
    conn = connect(path)
    store_inventory(conn, INVENTORY)
    conn.close()
    with _client(path) as c:
        guest = c.get(f"/api/devices/{ids['web']}").json()["proxmox"]
        assert guest["guest"]["vmid"] == 100 and guest["guest"]["kind"] == "lxc"
        assert guest["guest"]["host_name"] == "10.0.0.5" and guest["guests"] == []

        host = c.get(f"/api/devices/{ids['host']}").json()["proxmox"]
        assert host["guest"] is None
        assert [g["vmid"] for g in host["guests"]] == [100, 101, 102]
        assert host["guests"][0]["device_name"] == "10.0.0.64"
        assert host["guests"][2]["device_id"] is None  # stopped guest never seen on the LAN

        assert c.get(f"/api/devices/{ids['other']}").json()["proxmox"] is None
