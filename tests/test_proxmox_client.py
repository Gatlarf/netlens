import json
import urllib.parse

import pytest

from app.integrations.proxmox_client import ProxmoxClient, ProxmoxError, parse_net
from app.integrations.proxmox_config import ProxmoxConfig

# Synthetic data shaped like real Proxmox VE 9 responses (documentation addresses only).
DATA = {
    "/version": {"version": "9.2.11", "release": "9.2"},
    "/cluster/status": [
        {"type": "cluster", "name": "lab", "nodes": 1},
        {"type": "node", "name": "pve1", "ip": "10.0.0.5", "online": 1, "local": 1},
    ],
    "/cluster/resources?type=vm": [
        {"vmid": 100, "name": "winvm", "node": "pve1", "type": "qemu", "status": "running", "template": 0},
        {"vmid": 101, "name": "agentvm", "node": "pve1", "type": "qemu", "status": "running", "template": 0},
        {"vmid": 102, "name": "web", "node": "pve1", "type": "lxc", "status": "running", "template": 0},
        {"vmid": 103, "name": "stopped", "node": "pve1", "type": "lxc", "status": "stopped", "template": 0},
        {"vmid": 900, "name": "tmpl", "node": "pve1", "type": "qemu", "status": "stopped", "template": 1},
    ],
    "/nodes/pve1/qemu/100/config": {"name": "winvm", "net0": "virtio=02:00:00:00:00:64,bridge=vmbr0"},
    "/nodes/pve1/qemu/101/config": {"name": "agentvm", "net0": "e1000=02:00:00:00:00:65,bridge=vmbr0", "ipconfig0": "ip=10.0.0.65/24,gw=10.0.0.1"},
    "/nodes/pve1/qemu/101/agent/network-get-interfaces": {"result": [
        {"name": "lo", "hardware-address": "00:00:00:00:00:00", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
        {"name": "eth0", "hardware-address": "02:00:00:00:00:65", "ip-addresses": [
            {"ip-address": "10.0.0.66", "ip-address-type": "ipv4"}, {"ip-address": "fe80::1", "ip-address-type": "ipv6"}]},
        {"name": "docker0", "hardware-address": "02:42:00:00:00:01", "ip-addresses": [{"ip-address": "172.17.0.1", "ip-address-type": "ipv4"}]},
    ]},
    "/nodes/pve1/lxc/102/config": {"hostname": "web", "net0": "name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:66,ip=10.0.0.66/24,type=veth"},
    "/nodes/pve1/lxc/102/interfaces": [
        {"name": "lo", "inet": "127.0.0.1/8"},
        {"name": "eth0", "inet": "10.0.0.66/24", "hwaddr": "02:00:00:00:00:66"},
        {"name": "docker0", "inet": "172.17.0.1/16"},
        {"name": "br-1234", "inet": "172.18.0.1/16"},
    ],
    "/nodes/pve1/lxc/103/config": {"hostname": "stopped", "net0": "name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:67,ip=dhcp,type=veth"},
}


class FakeTransport:
    def __init__(self, data=None, status_for=None):
        self.data, self.status_for, self.calls = data or DATA, status_for or {}, []

    def __call__(self, method, url, headers, body):
        path = url.split("/api2/json", 1)[1]
        self.calls.append((method, path, dict(headers), body))
        if path == "/access/ticket":
            return 200, json.dumps({"data": {"ticket": "PVE:ticket", "CSRFPreventionToken": "x"}}).encode()
        if path in self.status_for:
            return self.status_for[path], b'{"data":null}'
        if path in self.data:
            return 200, json.dumps({"data": self.data[path]}).encode()
        return 500, b'{"data":null,"message":"no such thing"}'


def _token_cfg(**kw):
    return ProxmoxConfig(enabled=True, url="https://pve.test:8006", token_id="u@pam!nl", token_secret="SEKRET", **kw)


def test_parse_net_formats():
    assert parse_net("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0") == ("bc:24:11:aa:bb:cc", None)
    assert parse_net("name=eth0,hwaddr=02:00:00:00:00:66,ip=10.0.0.66/24,type=veth") == ("02:00:00:00:00:66", "10.0.0.66")
    assert parse_net("name=eth0,hwaddr=02:00:00:00:00:67,ip=dhcp") == ("02:00:00:00:00:67", None)
    assert parse_net("ip=169.254.1.1/16") == (None, None)  # link-local is ignored


def test_inventory_shape_and_filtering():
    inv = ProxmoxClient(_token_cfg(), transport=FakeTransport()).inventory()
    assert inv["nodes"] == [{"name": "pve1", "ip": "10.0.0.5", "online": True}]
    by = {g["vmid"]: g for g in inv["guests"]}
    assert sorted(by) == [100, 101, 102, 103]  # template 900 skipped
    assert by[100]["macs"] == ["02:00:00:00:00:64"] and by[100]["ips"] == []  # no agent configured -> MAC only
    # agent: lo/docker0 ignored, ipv6 ignored, cloud-init ip kept
    assert by[101]["ips"] == ["10.0.0.65", "10.0.0.66"] and by[101]["macs"] == ["02:00:00:00:00:65"]
    # lxc: static ip + live interfaces, internal docker/bridge networks ignored
    assert by[102]["ips"] == ["10.0.0.66"] and by[102]["kind"] == "lxc"
    # stopped guests: config only
    assert by[103]["macs"] == ["02:00:00:00:00:67"] and by[103]["ips"] == [] and by[103]["status"] == "stopped"


def test_token_auth_header_and_password_login_flow():
    t = FakeTransport()
    ProxmoxClient(_token_cfg(), transport=t).version()
    assert t.calls[0][2]["Authorization"] == "PVEAPIToken=u@pam!nl=SEKRET"

    t = FakeTransport()
    cfg = ProxmoxConfig(url="https://pve.test:8006", username="root@pam", password="pw")
    client = ProxmoxClient(cfg, transport=t)
    assert client.version() == "9.2.11"
    client.version()
    methods = [(c[0], c[1]) for c in t.calls]
    assert methods == [("POST", "/access/ticket"), ("GET", "/version"), ("GET", "/version")]  # ticket fetched once
    assert urllib.parse.parse_qs(t.calls[0][3].decode()) == {"username": ["root@pam"], "password": ["pw"]}
    assert t.calls[1][2]["Cookie"] == "PVEAuthCookie=PVE:ticket"


def test_node_fallback_without_cluster_status():
    data = {
        **DATA,
        "/nodes": [{"node": "solo", "status": "online"}],
        "/nodes/solo/network": [{"iface": "nic0", "address": None}, {"iface": "vmbr0", "address": "10.0.0.9"}],
    }
    t = FakeTransport(data, status_for={"/cluster/status": 403})
    assert ProxmoxClient(_token_cfg(), transport=t).nodes() == [{"name": "solo", "ip": "10.0.0.9", "online": True}]


@pytest.mark.parametrize("status, text", [(401, "authentication failed"), (403, "PVEAuditor")])
def test_http_errors_are_explained(status, text):
    t = FakeTransport(status_for={"/version": status})
    with pytest.raises(ProxmoxError, match=text):
        ProxmoxClient(_token_cfg(), transport=t).version()


def test_password_login_rejected_and_non_proxmox_response():
    class Reject(FakeTransport):
        def __call__(self, method, url, headers, body):
            return 401, b"{}"

    cfg = ProxmoxConfig(url="https://pve.test:8006", username="root@pam", password="bad")
    with pytest.raises(ProxmoxError, match="authentication failed"):
        ProxmoxClient(cfg, transport=Reject()).version()

    class Html(FakeTransport):
        def __call__(self, method, url, headers, body):
            return 200, b"<html>router login</html>"

    with pytest.raises(ProxmoxError, match="Proxmox VE address"):
        ProxmoxClient(_token_cfg(), transport=Html()).version()


def test_per_guest_failures_do_not_break_the_inventory():
    t = FakeTransport(status_for={"/nodes/pve1/lxc/102/interfaces": 500, "/nodes/pve1/qemu/101/config": 403})
    inv = ProxmoxClient(_token_cfg(), transport=t).inventory()
    assert len(inv["guests"]) == 4
