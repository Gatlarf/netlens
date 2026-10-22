"""Which device sits behind which port: links from a plugin, links set by hand, a second switch behind a port."""

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.contract import validate_output
from app.plugins.enrich import record_client_links, record_switch_ports

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T10:00:00Z"
# 1 gateway, 2 TP-Link core switch (ports from its plugin), 3 second switch, 4 NAS, 5 PC behind switch 3, 6 camera
DEVICES = [(1, "10.0.0.1", "router", "switch"), (2, "10.0.0.250", "core", "switch"), (3, "10.0.0.251", "office", "switch"),
           (4, "10.0.0.20", "nas", "nas"), (5, "10.0.0.30", "pc", "pc"), (6, "10.0.0.40", "cam", "camera")]


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    for i, ip, name, kind in DEVICES:
        conn.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, device_type, online, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                     (i, f"aa:00:00:00:00:0{i}", ip, name, kind, NOW, NOW))
    conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (2, 1, 'gateway', 'default-route', 1.0, 0)")
    conn.commit()
    data = {"nodes": [{"mac": "aa:00:00:00:00:02", "name": "core", "role": "switch", "ip": "10.0.0.250",
                       "ports": [{"port": n, "up": n in (1, 2, 3), "enabled": n != 9, "speed_mbps": 1000, "duplex": "full"} for n in range(1, 17)]}], "clients": []}
    record_switch_ports(conn, "tplink-easysmart", validate_output("topology", data))
    conn.close()
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers=AUTH) as c:
        c.db = db
        yield c


def port_map(c, device=2):
    return {p["port"]: p for p in c.get(f"/api/devices/{device}/port-map").json()["ports"]}


def test_a_switch_without_clients_lists_its_ports_and_nothing_on_them(client):
    ports = port_map(client)
    assert len(ports) == 16 and not any(p["devices"] for p in ports.values())
    assert [p["port"] for p in client.get("/api/devices/2/port-map").json()["ports"]][:3] == ["1", "2", "3"]       # 10 comes after 9


def test_set_by_hand_makes_it_the_parent_and_shows_on_the_port(client):
    r = client.put("/api/devices/4/connection", json={"node_device_id": 2, "port": "3"})
    assert r.status_code == 200 and r.json()["port"] == "3"
    assert [d["name"] for d in port_map(client)["3"]["devices"]] == ["nas"] and port_map(client)["3"]["devices"][0]["manual"] is True
    detail = client.get("/api/devices/4").json()
    assert detail["parent"]["effective"]["name"] == "core" and detail["connection"]["port"] == "3" and detail["connection"]["source"] == "manual"
    assert client.get("/api/map").json()["nodes"][3]["parent_port"] == "3"
    several = client.put("/api/devices/6/connection", json={"node_device_id": 2, "port": "3"})     # several devices on one port
    assert several.status_code == 200 and len(port_map(client)["3"]["devices"]) == 2


def test_a_device_behind_a_second_switch_is_listed_under_the_port_that_leads_there(client):
    client.put("/api/devices/3/connection", json={"node_device_id": 2, "port": "12"})
    client.put("/api/devices/5/connection", json={"node_device_id": 3, "port": "4"})
    uplink = port_map(client)["12"]["devices"][0]
    assert uplink["name"] == "office" and [b["name"] for b in uplink["behind"]] == ["pc"]
    assert client.get("/api/devices/3/port-map").json()["uplink"] == {"id": 2, "name": "core", "port": "12", "manual": True}


def test_a_port_can_be_given_by_the_name_the_switch_uses(client):
    conn = connect(client.db)
    conn.execute("UPDATE switch_ports SET name = 'NAS' WHERE port = 5")
    conn.commit()
    conn.close()
    client.put("/api/devices/4/connection", json={"node_device_id": 2, "port": "nas"})
    assert [d["name"] for d in port_map(client)["5"]["devices"]] == ["nas"]


def test_below_the_switch_with_no_port_is_listed_apart(client):
    client.put("/api/devices/4/connection", json={"node_device_id": 2})
    body = client.get("/api/devices/2/port-map").json()
    assert [d["name"] for d in body["no_port"]] == ["nas"]


def test_removing_it_gives_the_parent_back_to_automatic(client):
    client.put("/api/devices/4/connection", json={"node_device_id": 2, "port": "3"})
    assert client.delete("/api/devices/4/connection").json() == {"removed": True}
    assert client.get("/api/devices/4").json()["parent"]["mode"] == "auto" and not port_map(client)["3"]["devices"]
    assert client.delete("/api/devices/4/connection").json() == {"removed": False}


def test_a_loop_and_unknown_devices_are_refused(client):
    client.put("/api/devices/3/connection", json={"node_device_id": 2, "port": "1"})
    assert client.put("/api/devices/2/connection", json={"node_device_id": 3}).status_code == 409       # core cannot hang below office without turning it around
    assert client.put("/api/devices/2/connection", json={"node_device_id": 2}).status_code == 422
    assert client.put("/api/devices/2/connection", json={"node_device_id": 99}).status_code == 422
    assert client.put("/api/devices/99/connection", json={"node_device_id": 2}).status_code == 404


def test_a_plugin_never_overwrites_a_link_set_by_hand_but_notes_what_it_sees(client):
    client.put("/api/devices/4/connection", json={"node_device_id": 2, "port": "3"})
    conn = connect(client.db)
    data = validate_output("topology", {"nodes": [{"mac": "aa:00:00:00:00:01", "name": "gw", "role": "switch"}],
                                         "clients": [{"mac": "aa:00:00:00:00:04", "node_mac": "aa:00:00:00:00:01", "port": "Gi0/7", "medium": "wired"}]})
    record_client_links(conn, "snmp", data)
    row = conn.execute("SELECT source, port, node_device_id, seen_node, seen_port FROM client_links WHERE device_id = 4").fetchone()
    assert (row["source"], row["port"], row["node_device_id"], row["seen_node"], row["seen_port"]) == ("manual", "3", 2, "gw", "Gi0/7")
    record_client_links(conn, "snmp", {"nodes": [], "clients": []})
    assert conn.execute("SELECT COUNT(*) FROM client_links WHERE device_id = 4").fetchone()[0] == 1
    conn.close()
    assert port_map(client)["3"]["devices"][0]["differs"] == {"node": "gw", "port": "Gi0/7"}


def test_links_from_a_plugin_find_the_switch_as_a_device(client):
    conn = connect(client.db)
    data = validate_output("topology", {"nodes": [{"mac": "aa:00:00:00:00:03", "name": "office", "role": "switch"}],
                                         "clients": [{"mac": "aa:00:00:00:00:05", "node_mac": "aa:00:00:00:00:03", "port": "Gi1/0/5", "medium": "wired"}]})
    record_client_links(conn, "snmp", data)
    conn.close()
    ports = client.get("/api/devices/3/port-map").json()["ports"]
    assert [(p["port"], [d["name"] for d in p["devices"]], d["manual"]) for p in ports for d in p["devices"]] == [("Gi1/0/5", ["pc"], False)]


def test_connecting_a_device_to_a_switch_that_sits_below_it_asks_first_and_then_turns_it_around(client):
    client.put("/api/devices/4/connection", json={"node_device_id": 2, "port": "3"})                # nas below core, set by hand
    client.patch("/api/devices/2", json={"parent_mode": "device", "parent_device_id": 5})            # core below pc (a parent you set)
    asked = client.put("/api/devices/5/connection", json={"node_device_id": 2, "port": "14"})
    assert asked.status_code == 409 and "core sits below pc" in asked.json()["detail"] and "removed" in asked.json()["detail"]
    assert client.get("/api/devices/2").json()["parent"]["effective"]["name"] == "pc"                # nothing changed yet
    done = client.put("/api/devices/5/connection", json={"node_device_id": 2, "port": "14", "replace": True})
    assert done.status_code == 200
    assert [d["name"] for d in port_map(client)["14"]["devices"]] == ["pc"]
    assert client.get("/api/devices/2").json()["parent"]["effective"]["name"] != "pc"
    assert client.get("/api/devices/5").json()["parent"]["effective"]["name"] == "core"
