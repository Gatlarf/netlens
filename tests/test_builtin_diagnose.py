"""The diagnostic reports of the built-in Proxmox and ASUS plugins: shapes and counts, nothing private."""

import json

import pytest

from app.plugins.builtin import diag
from app.plugins.builtin.asus import plugin as asus_plugin
from app.plugins.builtin.asus.client import AsusAuthError, AsusClient
from app.plugins.builtin.proxmox import plugin as proxmox_plugin
from app.plugins.builtin.proxmox.client import ProxmoxClient
from app.plugins.contract import validate_manifest
from tests import test_asus, test_proxmox_client
from tests.test_asus import FakeTransport as AsusTransport
from tests.test_proxmox_client import DATA as _DATA, FakeTransport as _ProxmoxTransport

DATA = {**_DATA, "/nodes": [{"node": "pve1", "status": "online"}], "/nodes/pve1/network": [{"iface": "vmbr0", "address": "10.0.0.5"}]}


def ProxmoxTransport(**kw):
    return _ProxmoxTransport(DATA, **kw)


def test_describe_keeps_shapes_and_hides_content():
    out = diag.describe({"name": "Alice's NAS", "mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.0.5", "n": -5, "ok": True, "type": "qemu",
                         "list": [1, 2, 3, 4], "nested": {"x": "y"}})
    assert out["name"] == "<text 11 chars>" and out["mac"] == "<mac colons, UPPER>" and out["ip"] == "<ipv4>" and out["n"] == "<number negative, 1 digits>"
    assert out["ok"] is True and out["type"] == "qemu" and out["list"][-1] == "... 4 items" and out["nested"] == {"x": "<text 1 chars>"}
    table = {f"aa:bb:cc:dd:ee:0{i}": {"name": "x" * i} for i in range(1, 6)}
    assert list(diag.describe(table)) == ["<mac> x 5"]  # a table keyed by MAC addresses becomes one example row
    assert diag.mask("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,ip=192.168.0.5/24") == "virtio=<mac>,bridge=vmbr0,ip=<ipv4>"


@pytest.fixture
def proxmox(monkeypatch):
    monkeypatch.setattr(proxmox_plugin, "CLIENT_FACTORY", lambda cfg: ProxmoxClient(cfg, transport=ProxmoxTransport()))
    return {"url": "https://pve.example.org:8006", "token_id": "root@pam!netlens", "token_secret": "SECRETSECRET", "verify_tls": False}


def test_proxmox_diagnose(proxmox):
    report = proxmox_plugin.diagnose(proxmox)
    text = json.dumps(report)
    for private in ("winvm", "agentvm", "10.0.0.5", "02:00:00:00:00", "SECRETSECRET", "pve1", "pve.example.org"):
        assert private not in text, private
    assert all(s["ok"] for s in report["steps"].values()) and set(report["steps"]) >= {"version", "cluster_status", "nodes", "resources", "qemu_config", "lxc_config"}
    assert report["steps"]["version"]["shape"]["version"] == "9.2.11"
    assert report["steps"]["qemu_config"]["shape"]["net0"] == "virtio=<mac>,bridge=vmbr0"  # structure kept, addresses hidden
    assert report["steps"]["lxc_config"]["shape"]["net0"] == "name=eth0,bridge=vmbr0,hwaddr=<mac>,ip=<ipv4>,type=veth"
    assert report["result"] == {"nodes": 1, "nodes_with_ip": 1, "guests": 4, "by_kind": {"qemu": 2, "lxc": 2}, "guests_with_mac": 4, "guests_with_ip": 2}


def test_proxmox_diagnose_records_a_failing_step_and_continues(monkeypatch, proxmox):
    monkeypatch.setattr(proxmox_plugin, "CLIENT_FACTORY", lambda cfg: ProxmoxClient(cfg, transport=ProxmoxTransport(status_for={"/cluster/status": 403})))
    report = proxmox_plugin.diagnose(proxmox)
    assert report["steps"]["cluster_status"]["ok"] is False and "PVEAuditor" in report["steps"]["cluster_status"]["error"]
    assert report["steps"]["resources"]["ok"] is True and "result" in report


@pytest.fixture
def asus(monkeypatch):
    monkeypatch.setattr(asus_plugin, "CLIENT_FACTORY", lambda cfg: AsusClient(cfg, transport=AsusTransport()))
    return {"url": "https://10.0.0.1:8443", "username": "admin", "password": "hunter22", "verify_tls": False}


def test_asus_diagnose(asus):
    report = asus_plugin.diagnose(asus)
    text = json.dumps(report)
    for private in ("Garden", "Attic", "wired on main", "10.0.0.", "aa:00:00", "hunter22", "02:00:00:00"):
        assert private.lower() not in text.lower(), private
    assert report["steps"]["clientlist"]["ok"] and report["steps"]["onboarding"]["nodes_parsed"] == 3
    assert report["steps"]["onboarding"]["first_node"][0]["mac"] == "<mac colons, UPPER>"
    assert report["result"] == {"nodes": 3, "main_nodes": 1, "clients": 3, "wired": 2, "with_rssi": 1, "with_rates": 1, "with_node": 2}


def test_asus_diagnose_logs_out_even_when_a_step_fails(monkeypatch, asus):
    transport = AsusTransport(fail_on="ajax_onboarding")
    monkeypatch.setattr(asus_plugin, "CLIENT_FACTORY", lambda cfg: AsusClient(cfg, transport=transport))
    report = asus_plugin.diagnose(asus)
    assert report["steps"]["onboarding"]["ok"] is False and "boom" in report["steps"]["onboarding"]["error"]
    assert [c[1] for c in transport.calls][-1] == "/Logout.asp"


def test_asus_diagnose_refused_login_is_auth_failed(monkeypatch, asus):
    monkeypatch.setattr(asus_plugin, "CLIENT_FACTORY", lambda cfg: AsusClient(cfg, transport=AsusTransport(login={"error_status": "2"})))
    with pytest.raises(AsusAuthError) as err:
        asus_plugin.diagnose(asus)
    assert err.value.auth_failed is True


def test_both_manifests_announce_the_diagnostic():
    for pid in ("proxmox", "asus"):
        path = __import__("pathlib").Path(__file__).resolve().parents[1] / "app" / "plugins" / "builtin" / pid / "plugin.json"
        assert validate_manifest(json.loads(path.read_text()))["diagnose"] is True


def test_proxmox_reads_every_server_in_the_list_and_keeps_clashing_vm_numbers_apart(monkeypatch):
    from app.plugins.builtin.proxmox import plugin as px

    class Client:
        def __init__(self, cfg):
            self.url = cfg.url

        def version(self):
            return "8.2"

        def inventory(self):
            node = "pve-" + self.url[-1]
            return {"nodes": [{"name": node, "ip": None, "online": True}],
                    "guests": [{"vmid": 100, "name": "vm" + self.url[-1], "kind": "qemu", "node": node, "status": "running", "macs": [], "ips": []}]}

    monkeypatch.setattr(px, "CLIENT_FACTORY", Client)
    rows = {"servers": [{"id": "a", "host": "https://pve1", "token_id": "u@pam!n", "token_secret": "s"},
                        {"id": "b", "host": "https://pve2", "token_id": "u@pam!n", "token_secret": "s"}], "verify_tls": True}
    out = px.fetch(rows)
    assert [h["name"] for h in out["hosts"]] == ["pve-1", "pve-2"] and [g["id"] for g in out["guests"]] == ["100", "pve-2/100"]
    assert px.test(rows)["message"].startswith("2 Proxmox servers answered")
    with pytest.raises(ValueError, match="at least one"):
        px.fetch({"servers": []})
    assert px.test({"url": "https://old", "token_id": "a", "token_secret": "b"})["message"].startswith("Connected: Proxmox VE 8.2")
