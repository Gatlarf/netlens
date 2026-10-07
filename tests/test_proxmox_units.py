import pytest
from app.db import connect, init_db
from app.integrations.proxmox_config import ProxmoxConfig, load_config, save_config, normalize_url, public_dict, is_configured, uses_token
from app.integrations.proxmox_match import norm_mac, match_inventory


@pytest.fixture
def conn():
    c = connect(":memory:")
    init_db(c)
    yield c
    c.close()


def test_config_roundtrip(conn):
    # Defaults on empty db
    cfg = load_config(conn)
    assert cfg.enabled is False
    assert cfg.url == ""
    assert cfg.verify_tls is True
    assert cfg.username == ""
    assert cfg.password == ""
    assert cfg.token_id == ""
    assert cfg.token_secret == ""

    # Save and reload
    cfg.enabled = True
    cfg.url = "https://pve.lan:8006"
    cfg.username = "user"
    cfg.password = "pass"
    save_config(conn, cfg)
    loaded = load_config(conn)
    assert loaded.enabled is True
    assert loaded.url == "https://pve.lan:8006"
    assert loaded.username == "user"
    assert loaded.password == "pass"

    # Garbage JSON
    from app.db import set_setting
    set_setting(conn, "proxmox", "oops")
    loaded = load_config(conn)
    assert loaded.enabled is False
    assert loaded.url == ""


def test_normalize_url():
    assert normalize_url("192.168.0.180") == "https://192.168.0.180:8006"
    assert normalize_url(" https://pve.lan:8006/ ") == "https://pve.lan:8006"
    assert normalize_url("http://pve.lan") == "http://pve.lan:8006"
    assert normalize_url("") == ""
    with pytest.raises(ValueError):
        normalize_url("ftp://x")


def test_config_helpers(conn):
    cfg = ProxmoxConfig(enabled=True, url="https://pve.lan:8006", username="user", password="s3cret")
    assert is_configured(cfg)
    assert uses_token(cfg) is False
    pd = public_dict(cfg)
    assert "password" not in pd
    assert "token_secret" not in pd
    assert pd["password_set"] is True
    assert pd["token_secret_set"] is False
    assert pd["auth_method"] == "password"
    assert pd["configured"] is True
    assert "s3cret" not in str(pd)

    cfg2 = ProxmoxConfig(enabled=True, url="https://pve.lan:8006", token_id="tid", token_secret="s3cret")
    assert is_configured(cfg2)
    assert uses_token(cfg2) is True
    pd2 = public_dict(cfg2)
    assert pd2["auth_method"] == "token"
    assert pd2["token_secret_set"] is True
    assert "s3cret" not in str(pd2)

    cfg3 = ProxmoxConfig(enabled=True, url="", username="user", password="pass")
    assert not is_configured(cfg3)
    assert uses_token(cfg3) is False
    pd3 = public_dict(cfg3)
    assert pd3["auth_method"] == "password"  # auth method reflects credentials, not the URL
    assert pd3["configured"] is False
    assert pd3["configured"] is False


def test_norm_mac():
    assert norm_mac("BC-24-11-AA-BB-CC") == "bc:24:11:aa:bb:cc"
    assert norm_mac(None) is None
    assert norm_mac("") is None


def test_match_by_mac():
    inventory = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [{"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": ["192.168.0.50"]}]
    }
    devices = [
        {"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]},
        {"id": 2, "mac": "BC:24:11:AA:BB:CC", "ips": ["192.168.0.50"]}
    ]
    # Copy to check mutation
    guest_copy = dict(inventory["guests"][0])
    result = match_inventory(inventory, devices)
    assert result["hosts"] == {"pve1": 1}
    assert len(result["guests"]) == 1
    g = result["guests"][0]
    assert g["device_id"] == 2
    assert g["host_device_id"] == 1
    # Original guest dict should not have device_id key
    assert "device_id" not in guest_copy


def test_match_by_ip_fallback():
    inventory = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [{"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": [], "ips": ["192.168.0.50"]}]
    }
    devices = [
        {"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]},
        {"id": 2, "mac": None, "ips": ["192.168.0.50"]}
    ]
    result = match_inventory(inventory, devices)
    assert result["hosts"] == {"pve1": 1}
    assert result["guests"][0]["device_id"] == 2
    assert result["guests"][0]["host_device_id"] == 1


def test_no_match():
    inventory = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [{"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["unknown"], "ips": ["unknown"]}]
    }
    devices = [
        {"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]},
    ]
    result = match_inventory(inventory, devices)
    assert result["hosts"] == {"pve1": 1}
    assert result["guests"][0]["device_id"] is None
    assert result["guests"][0]["host_device_id"] == 1

    # Node without matching device
    inventory2 = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": []
    }
    devices2 = []
    result2 = match_inventory(inventory2, devices2)
    assert result2["hosts"] == {"pve1": None}
    assert len(result2["guests"]) == 0


def test_lowest_vmid_claim():
    inventory = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [
            {"vmid": 101, "name": "b", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": []},
            {"vmid": 100, "name": "a", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": []}
        ]
    }
    devices = [
        {"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]},
        {"id": 2, "mac": "BC:24:11:AA:BB:CC", "ips": []}
    ]
    result = match_inventory(inventory, devices)
    assert result["hosts"] == {"pve1": 1}
    # Guest with vmid 100 should claim device 2
    guest_100 = next(g for g in result["guests"] if g["vmid"] == 100)
    guest_101 = next(g for g in result["guests"] if g["vmid"] == 101)
    assert guest_100["device_id"] == 2
    assert guest_101["device_id"] is None
    assert guest_100["host_device_id"] == 1
    assert guest_101["host_device_id"] == 1

    # Host device never matched to guest
    inventory2 = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [{"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": [], "ips": ["192.168.0.180"]}]
    }
    devices2 = [{"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]}]
    result2 = match_inventory(inventory2, devices2)
    assert result2["hosts"] == {"pve1": 1}
    assert result2["guests"][0]["device_id"] is None
    assert result2["guests"][0]["host_device_id"] == 1


def test_mac_wins_over_ip():
    inventory = {
        "nodes": [{"name": "pve1", "ip": "192.168.0.180"}],
        "guests": [
            {"vmid": 100, "name": "A", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": ["192.168.0.50"]},
            {"vmid": 101, "name": "B", "kind": "lxc", "node": "pve1", "status": "running", "macs": [], "ips": ["192.168.0.60"]}
        ]
    }
    devices = [
        {"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]},
        {"id": 2, "mac": "00:11:22:33:44:56", "ips": ["192.168.0.50"]},
        {"id": 3, "mac": "BC:24:11:AA:BB:CC", "ips": ["192.168.0.60"]}
    ]
    result = match_inventory(inventory, devices)
    assert result["hosts"] == {"pve1": 1}
    guest_a = next(g for g in result["guests"] if g["vmid"] == 100)
    guest_b = next(g for g in result["guests"] if g["vmid"] == 101)
    assert guest_a["device_id"] == 3  # MAC match wins
    assert guest_b["device_id"] is None  # IP belongs to device 3, already claimed
    assert guest_a["host_device_id"] == 1
    assert guest_b["host_device_id"] == 1