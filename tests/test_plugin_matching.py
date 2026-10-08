import pytest

from app.plugins.builtin.proxmox.config import ProxmoxConfig, has_credentials, normalize_url, uses_token
from app.plugins.matching import match_hypervisor, norm_mac, topology_links


def match_inventory(inventory, devices):
    """The tests below describe a Proxmox-like inventory; convert it to the plugin contract."""
    output = {
        "hosts": [{"id": n["name"], "name": n["name"], "ip": n.get("ip"), "mac": None, "online": True} for n in inventory["nodes"]],
        "guests": [
            {"id": str(g["vmid"]), "name": g["name"], "kind": g["kind"], "host_id": g["node"], "status": g["status"],
             "macs": g["macs"], "ips": g["ips"]}
            for g in inventory["guests"]
        ],
    }
    return match_hypervisor(output, devices)


def test_normalize_url():
    assert normalize_url("192.168.0.180") == "https://192.168.0.180:8006"
    assert normalize_url(" https://pve.lan:8006/ ") == "https://pve.lan:8006"
    assert normalize_url("http://pve.lan") == "http://pve.lan:8006"
    assert normalize_url("") == ""
    with pytest.raises(ValueError):
        normalize_url("ftp://x")


def test_credentials_helpers():
    assert has_credentials(ProxmoxConfig(username="u", password="p"))
    assert has_credentials(ProxmoxConfig(token_id="t", token_secret="s"))
    assert not has_credentials(ProxmoxConfig(username="u"))
    assert not has_credentials(ProxmoxConfig(token_id="t"))
    assert uses_token(ProxmoxConfig(token_id="t", token_secret="s")) and not uses_token(ProxmoxConfig(username="u", password="p"))


def test_host_found_by_mac_when_it_has_no_ip():
    out = {"hosts": [{"id": "h", "name": "h", "ip": None, "mac": "AA-00-00-00-00-01", "online": True}], "guests": []}
    assert match_hypervisor(out, [{"id": 7, "mac": "aa:00:00:00:00:01", "ips": ["10.0.0.9"]}])["hosts"] == {"h": 7}


def test_guest_without_host_has_no_host_device():
    out = {"hosts": [], "guests": [{"id": "1", "name": "g", "kind": "vm", "host_id": None, "status": "running", "macs": [], "ips": ["10.0.0.4"]}]}
    g = match_hypervisor(out, [{"id": 3, "mac": None, "ips": ["10.0.0.4"]}])["guests"][0]
    assert g["device_id"] == 3 and g["host_device_id"] is None


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
    guest_100 = next(g for g in result["guests"] if g["id"] == "100")
    guest_101 = next(g for g in result["guests"] if g["id"] == "101")
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
    guest_a = next(g for g in result["guests"] if g["id"] == "100")
    guest_b = next(g for g in result["guests"] if g["id"] == "101")
    assert guest_a["device_id"] == 3  # MAC match wins
    assert guest_b["device_id"] is None  # IP belongs to device 3, already claimed
    assert guest_a["host_device_id"] == 1
    assert guest_b["host_device_id"] == 1