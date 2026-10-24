import time

import pytest
from fastapi.testclient import TestClient

from app import traffic, tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


def test_which_interfaces_count():
    assert traffic.interfaces_to_count({"eth0", "lo", "docker0", "veth12ab"}) == {"eth0"}
    assert traffic.interfaces_to_count({"nic0", "vmbr0", "fwbr102i0", "fwln102i0", "tap102i0"}) == {"vmbr0"}        # a Proxmox host: its bridge is its own traffic
    assert traffic.interfaces_to_count({"Hyper-V Virtual Ethernet Adapter", "Hyper-V Virtual Ethernet Adapter #2"}) == {"Hyper-V Virtual Ethernet Adapter", "Hyper-V Virtual Ethernet Adapter #2"}   # nothing else: all


@pytest.fixture
def setup(tmp_path):
    tsdb.forget_all()
    db = tmp_path / "netlens.db"
    conn = connect(db)
    init_db(conn)
    for i, (ip, kind) in enumerate((("10.0.0.1", "router"), ("10.0.0.2", "switch"), ("10.0.0.3", "server"), ("10.0.0.4", "nas")), 1):
        conn.execute("INSERT INTO devices (id, primary_ip, mac, device_type, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')", (i, ip, f"aa:00:00:00:00:0{i}", kind))
    conn.commit()
    store = tsdb.for_conn(conn)
    now = int(time.time()) // 60 * 60
    for minutes in range(30, -1, -1):
        ts = now - minutes * 60
        store.record([("device", 1, "net_rx_bps", 50e6, "WAN", "bps"), ("device", 1, "net_tx_bps", 5e6, "WAN", "bps"), ("device", 1, "net_rx_bps", 900e6, "LAN", "bps"),     # the router: WAN and LAN
                      ("device", 2, "net_rx_bps", 800e6, "Port 1", "bps"), ("device", 2, "net_tx_bps", 800e6, "Port 1", "bps"),                                             # a switch: left out
                      ("device", 3, "net_rx_bps", 10e6, "eth0", "bps"), ("device", 3, "net_tx_bps", 2e6, "eth0", "bps"), ("device", 3, "net_rx_bps", 99e6, "docker0", "bps"),
                      ("device", 4, "net_rx_bps", 5e6, "eth0", "bps"), ("device", 4, "net_tx_bps", 1e6, "eth0", "bps")], ts=ts)
    yield conn, now
    conn.close()
    tsdb.forget_all()


def test_every_interface_of_every_device_is_added_up_by_default(setup):
    conn, now = setup
    out = traffic.build(conn, "1h", now=now)
    assert out["mode"] == "all" and out["devices"]["count"] == 4
    assert out["devices"]["now"]["rx"] == 50e6 + 900e6 + 800e6 + 10e6 + 99e6 + 5e6          # the router (both), the switch, the server (docker0 too), the NAS


def test_devices_are_added_up_and_the_wan_has_its_own_line(setup):
    conn, now = setup
    out = traffic.build(conn, "1h", now=now, mode="endpoints")
    assert out["devices"]["count"] == 2                                            # the server and the NAS: not the switch, not the router
    assert out["devices"]["now"] == {"rx": 15e6, "tx": 3e6}                        # docker0 left out
    assert out["wan"]["device_id"] == 1 and out["wan"]["label"] == "WAN" and out["wan"]["now"] == {"rx": 50e6, "tx": 5e6}
    assert {c["label"] for c in out["candidates"]} == {"WAN", "LAN"}


def test_a_chosen_wan_interface_wins(setup):
    conn, now = setup
    out = traffic.build(conn, "1h", wan=(1, "LAN"), now=now, mode="endpoints")
    assert out["wan"]["label"] == "LAN" and out["wan"]["now"]["rx"] == 900e6


def test_no_wan_source_is_said_plainly(tmp_path):
    tsdb.forget_all()
    conn = connect(tmp_path / "netlens.db")
    init_db(conn)
    out = traffic.build(conn, "1h")
    assert out["wan"] is None and out["devices"]["count"] == 0
    conn.close()
    tsdb.forget_all()


def test_api(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        assert client.get("/api/traffic?range=6h", headers=h).json()["range"] == "6h"
        assert client.get("/api/traffic?range=2y", headers=h).status_code == 422
        assert client.get("/api/traffic?mode=nope", headers=h).status_code == 422
        assert client.put("/api/interface", json={"wan": "1|WAN"}, headers=h).json()["settings"]["wan"] == "1|WAN"
        assert client.put("/api/interface", json={"wan": "nonsense"}, headers=h).status_code == 422
    tsdb.forget_all()
