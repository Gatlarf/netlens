import json

import pytest

from app.db import connect, get_or_create_device, init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_router_names, record_wifi, refresh_hostname

NOW = "2026-03-10T12:00:00Z"
LATER = "2026-03-10T12:15:00Z"
NODES = [
    {"mac": "aa:00:00:00:00:10", "macs": ["aa:00:00:00:00:10"], "name": "Basement", "role": "gateway"},
    {"mac": "aa:00:00:00:00:20", "macs": ["aa:00:00:00:00:20", "aa:00:00:00:00:21"], "name": "Garden", "role": "node"},
]


def data(node_mac, rssi=-60, name="Bert's iPad", ip="10.0.0.12"):
    return {"nodes": NODES, "clients": [
        {"mac": "02:00:00:00:00:02", "ip": ip, "name": name, "node_mac": node_mac, "medium": "wifi", "band": "5 GHz", "rssi": rssi, "tx_mbps": 72.2, "rx_mbps": 1.0},
        {"mac": "02:00:00:00:00:01", "ip": "10.0.0.11", "name": "Printer", "node_mac": None, "medium": "wired"},
    ]}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (1, '02:00:00:00:00:02', '10.0.0.12', 1, ?, ?)", (NOW, NOW))
    c.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (2, '02:00:00:00:00:01', '10.0.0.11', 1, ?, ?)", (NOW, NOW))
    c.commit()
    return c


def test_router_names_become_aliases_and_the_hostname_when_there_is_none(conn):
    assert record_router_names(conn, data("aa:00:00:00:00:20"), NOW) == 2
    assert [tuple(r) for r in conn.execute("SELECT name, source FROM device_names WHERE device_id = 1")] == [("Bert's iPad", "router")]
    assert conn.execute("SELECT hostname FROM devices WHERE id = 1").fetchone()[0] == "Bert's iPad"
    record_router_names(conn, data("aa:00:00:00:00:20", name="Renamed"), LATER)  # a new name is another alias; the hostname stays
    assert conn.execute("SELECT COUNT(*) FROM device_names WHERE device_id = 1").fetchone()[0] == 2
    assert conn.execute("SELECT hostname FROM devices WHERE id = 1").fetchone()[0] == "Bert's iPad"


def test_a_real_hostname_is_not_replaced_and_alias_priority_is_ptr_upnp_mdns_router(conn):
    conn.execute("UPDATE devices SET hostname = 'ipad.lan' WHERE id = 1")
    record_router_names(conn, data("aa:00:00:00:00:20"), NOW)
    assert conn.execute("SELECT hostname FROM devices WHERE id = 1").fetchone()[0] == "ipad.lan"
    conn.execute("UPDATE devices SET hostname = NULL WHERE id = 2")
    for name, source in (("router-name", "router"), ("mdns-name", "mdns"), ("upnp-name", "upnp")):
        conn.execute("INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (2, ?, ?, ?, ?)", (name, source, NOW, NOW))
    refresh_hostname(conn, 2)
    assert conn.execute("SELECT hostname FROM devices WHERE id = 2").fetchone()[0] == "upnp-name"
    conn.execute("UPDATE devices SET hostname = NULL WHERE id = 2")
    conn.execute("DELETE FROM device_names WHERE source = 'upnp'")
    refresh_hostname(conn, 2)
    assert conn.execute("SELECT hostname FROM devices WHERE id = 2").fetchone()[0] == "mdns-name"


def test_wifi_samples_only_for_wifi_clients(conn):
    assert record_wifi(conn, data("aa:00:00:00:00:20"), NOW) == {"samples": 1, "roams": 0}
    row = conn.execute("SELECT device_id, node, band, rssi, tx_mbps FROM wifi_samples").fetchone()
    assert tuple(row) == (1, "Garden", "5 GHz", -60, 72.2)  # matched through the node's second MAC


def test_a_client_without_node_is_on_the_gateway(conn):
    d = data(None)
    record_wifi(conn, d, NOW)
    assert conn.execute("SELECT node FROM wifi_samples").fetchone()[0] == "Basement"


def test_roaming_is_logged_once_per_move(conn):
    record_wifi(conn, data("aa:00:00:00:00:20"), NOW)
    assert record_wifi(conn, data("aa:00:00:00:00:20", rssi=-70), "2026-03-10T12:05:00Z")["roams"] == 0  # same node
    assert record_wifi(conn, data("aa:00:00:00:00:10"), LATER)["roams"] == 1
    events = [tuple(r) for r in conn.execute("SELECT kind, detail, device_id FROM events")]
    assert events == [("wifi_roamed", "Garden -> Basement (5 GHz)", 1)]
    assert record_wifi(conn, data("aa:00:00:00:00:10"), "2026-03-10T12:30:00Z")["roams"] == 0


def test_an_old_previous_sample_is_not_a_roam_and_old_samples_are_pruned(conn):
    record_wifi(conn, data("aa:00:00:00:00:20"), "2026-03-01T12:00:00Z")
    assert record_wifi(conn, data("aa:00:00:00:00:10"), NOW)["roams"] == 0  # nine days apart: just a different place
    assert conn.execute("SELECT COUNT(*) FROM wifi_samples").fetchone()[0] == 2
    record_wifi(conn, data("aa:00:00:00:00:10"), "2026-03-20T12:00:00Z")
    assert conn.execute("SELECT COUNT(*) FROM wifi_samples WHERE ts < '2026-03-07'").fetchone()[0] == 0


def test_contract_accepts_and_checks_the_wifi_fields():
    out = validate_output("topology", data("aa:00:00:00:00:20"))
    assert out["clients"][0]["rssi"] == -60 and out["clients"][0]["tx_mbps"] == 72.2 and out["clients"][1]["rssi"] is None
    for field, value in (("rssi", 5), ("rssi", "strong"), ("rssi", True), ("tx_mbps", -1)):
        bad = data("aa:00:00:00:00:20")
        bad["clients"][0][field] = value
        with pytest.raises(ContractError, match=field):
            validate_output("topology", bad)
