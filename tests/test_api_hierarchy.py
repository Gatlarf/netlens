import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import SCHEMA_VERSION, connect, init_db
from app.hierarchy import hierarchy_payload
from app.db import set_setting
from app.plugins.registry import discover
from app.plugins.service import apply_plugin
from app.main import create_app
from app.scanner.relations import Edge
from app.scanner.relstore import replace_inferred

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T10:00:00Z"


def _seed(db: Path) -> None:
    """1 gateway, 2 Proxmox host, 3 and 4 guests, 5 an unrelated PC."""
    conn = connect(db)
    init_db(conn)
    rows = [(1, "10.0.0.1", "router"), (2, "10.0.0.5", "pve"), (3, "10.0.0.6", "web"), (4, "10.0.0.7", "db"), (5, "10.0.0.50", None)]
    for i, ip, name in rows:
        conn.execute(
            "INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (i, f"aa:00:00:00:00:0{i}", ip, name, NOW, NOW),
        )
    conn.executemany(
        "INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, ?, ?, 1.0, 0)",
        [(2, 1, "gateway", "default-route"), (3, 1, "gateway", "default-route"), (4, 1, "gateway", "default-route"),
         (5, 1, "gateway", "default-route"), (3, 2, "host-of", "plugin:proxmox"), (4, 2, "host-of", "plugin:proxmox")],
    )
    conn.commit()
    conn.close()


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    _seed(db)
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers=AUTH) as c:
        c.db = db
        yield c


def _parents(c):
    return {n["id"]: (n["parent_id"], n["source"]) for n in c.get("/api/hierarchy").json()["nodes"]}


def test_hierarchy_endpoint(client):
    body = client.get("/api/hierarchy").json()
    assert _parents(client) == {1: (None, "none"), 2: (1, "gateway"), 3: (2, "hypervisor"), 4: (2, "hypervisor"), 5: (1, "gateway")}
    by_id = {n["id"]: n for n in body["nodes"]}
    assert body["roots"] == [1]
    assert (by_id[1]["children"], by_id[1]["descendants"], by_id[3]["depth"]) == (2, 4, 2)
    assert by_id[3]["name"] == "web" and by_id[5]["name"] == "10.0.0.50"
    assert body["stats"]["max_depth"] == 2 and "hypervisor" in body["sources"]
    assert client.get("/api/hierarchy", headers={"Authorization": "Bearer no"}).status_code == 401


def test_guests_are_below_the_proxmox_host_on_the_map(client):
    data = client.get("/api/map").json()
    parent_edges = {e["to"]: e for e in data["edges"] if e["kind"] == "parent"}
    assert {k: v["from"] for k, v in parent_edges.items()} == {2: 1, 3: 2, 4: 2, 5: 1}
    assert parent_edges[3]["id"] == "p3" and parent_edges[3]["source"] == "hypervisor" and parent_edges[3]["manual"] is False
    nodes = {n["id"]: n for n in data["nodes"]}
    assert (nodes[3]["parent_id"], nodes[3]["parent_source"]) == (2, "hypervisor") and nodes[1]["parent_id"] is None
    assert any(e["kind"] == "gateway" and e["from"] == 3 for e in data["edges"])  # the raw links are still there


def test_choose_a_parent_manually(client):
    r = client.patch("/api/devices/5", json={"parent_mode": "device", "parent_device_id": 2})
    assert r.status_code == 200
    parent = r.json()["parent"]
    assert (parent["mode"], parent["device_id"], parent["source"]) == ("device", 2, "manual")
    assert parent["effective"] == {"id": 2, "name": "pve"}
    assert _parents(client)[5] == (2, "manual")
    kids = {c["id"] for c in client.get("/api/devices/2").json()["parent"]["children"]}
    assert kids == {3, 4, 5}
    edge = next(e for e in client.get("/api/map").json()["edges"] if e["id"] == "p5")
    assert (edge["from"], edge["manual"]) == (2, True)


def test_none_and_auto(client):
    client.patch("/api/devices/3", json={"parent_mode": "none"})
    assert _parents(client)[3] == (None, "manual")
    assert client.get("/api/devices/3").json()["parent"]["mode"] == "none"
    client.patch("/api/devices/3", json={"parent_mode": "auto"})
    assert _parents(client)[3] == (2, "hypervisor")
    # a bare parent_device_id means "this device"
    client.patch("/api/devices/3", json={"parent_device_id": 5})
    assert client.get("/api/devices/3").json()["parent"]["mode"] == "device" and _parents(client)[3] == (5, "manual")


@pytest.mark.parametrize("device, payload, text", [
    (1, {"parent_mode": "device", "parent_device_id": 3}, "loop"),         # 3 is below 1
    (2, {"parent_mode": "device", "parent_device_id": 4}, "loop"),         # 4 is below 2
    (3, {"parent_mode": "device", "parent_device_id": 3}, "own parent"),
    (3, {"parent_mode": "device", "parent_device_id": 999}, "not found"),
    (3, {"parent_mode": "device"}, "required"),
    (3, {"parent_mode": "sideways"}, "parent_mode"),
])
def test_invalid_parents_are_rejected_and_change_nothing(client, device, payload, text):
    before = _parents(client)
    r = client.patch(f"/api/devices/{device}", json=payload)
    assert r.status_code == 422 and text in r.json()["detail"]
    assert _parents(client) == before


def test_parent_choice_persists_and_other_edits_keep_it(client):
    client.patch("/api/devices/5", json={"parent_mode": "device", "parent_device_id": 2})
    client.patch("/api/devices/5", json={"notes": "just a note"})  # unrelated edit must not reset the parent
    assert _parents(client)[5] == (2, "manual")
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=client.db), headers=AUTH) as again:
        assert _parents(again)[5] == (2, "manual")


def test_deleting_the_chosen_parent_falls_back_to_automatic(client):
    client.patch("/api/devices/5", json={"parent_mode": "device", "parent_device_id": 2})
    conn = connect(client.db)
    conn.execute("DELETE FROM devices WHERE id = 2")
    conn.commit()
    conn.close()
    assert _parents(client)[5] == (1, "gateway")


def test_detail_lists_descendants_so_the_ui_can_hide_loop_choices(client):
    parent = client.get("/api/devices/2").json()["parent"]
    assert parent["descendants"] == [3, 4] and parent["effective"]["id"] == 1
    assert client.get("/api/devices/1").json()["parent"]["effective"] is None


def test_real_proxmox_sync_puts_guests_under_their_host(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    for i, (mac, ip) in enumerate([("aa:00:00:00:00:01", "10.0.0.1"), ("aa:00:00:00:00:02", "10.0.0.5"),
                                   ("02:00:00:00:00:64", "10.0.0.64"), ("02:00:00:00:00:65", "10.0.0.65")], 1):
        conn.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (?, ?, ?, 1, ?, ?)", (i, mac, ip, NOW, NOW))
    conn.commit()
    # what a scan infers: everything hangs off the gateway ...
    replace_inferred(conn, [Edge(i, 1, "gateway", "default-route", 1.0) for i in (2, 3, 4)])
    # ... then the Proxmox connector says devices 3 and 4 are guests of device 2
    set_setting(conn, "plugin.proxmox.data", json.dumps({
        "hosts": [{"id": "pve1", "name": "pve1", "ip": "10.0.0.5", "mac": None, "online": True}],
        "guests": [
            {"id": "100", "name": "web", "kind": "lxc", "host_id": "pve1", "status": "running", "macs": ["02:00:00:00:00:64"], "ips": []},
            {"id": "101", "name": "db", "kind": "qemu", "host_id": "pve1", "status": "running", "macs": ["02:00:00:00:00:65"], "ips": []},
        ],
    }))
    apply_plugin(conn, discover(None)["proxmox"])
    payload = hierarchy_payload(conn)
    conn.close()
    parents = {n["id"]: (n["parent_id"], n["source"]) for n in payload["nodes"]}
    assert parents == {1: (None, "none"), 2: (1, "gateway"), 3: (2, "hypervisor"), 4: (2, "hypervisor")}


def test_v2_database_gets_the_parent_columns(tmp_path):
    path = tmp_path / "v2.db"
    old = sqlite3.connect(path)
    old.execute(
        """CREATE TABLE devices (id INTEGER PRIMARY KEY, mac TEXT UNIQUE, primary_ip TEXT, hostname TEXT, vendor TEXT,
           os_name TEXT, os_confidence INTEGER, device_type TEXT, type_override TEXT, custom_name TEXT, notes TEXT,
           tags TEXT, online INTEGER NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
           pos_x REAL, pos_y REAL, raw_xml TEXT, notify_offline INTEGER NOT NULL DEFAULT 1)"""
    )
    old.execute("INSERT INTO devices (id, mac, primary_ip, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.1', ?, ?)", (NOW, NOW))
    old.execute("CREATE TABLE schema_version (version INTEGER)")
    old.execute("INSERT INTO schema_version VALUES (2)")
    old.commit()
    old.close()

    conn = connect(path)
    init_db(conn)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
    row = conn.execute("SELECT parent_mode, parent_device_id FROM devices WHERE id = 1").fetchone()
    assert (row["parent_mode"], row["parent_device_id"]) == ("auto", None)
    init_db(conn)  # idempotent
    conn.close()
