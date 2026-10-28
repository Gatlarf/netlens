"""The XCP-ng / XenServer / Xen Orchestra plugin against simulated servers that replay answers recorded from a real XCP-ng 8.3 pool and
Xen Orchestra 6 (tests/fake_xen.py). Both ways in (Xen Orchestra REST and the XAPI of a pool master) must give the same picture."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_xen import FakeXen

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "xcpng"
spec = importlib.util.spec_from_file_location("xcpng_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

HOST_ID = "792dad78-f5db-4b35-bf1d-3634774d080a"
VM1, VM2 = "d2377fad-e72f-a3bc-2e00-dc4823a80efd", "b35fce12-befd-a53c-1fd1-55c62eb4abb2"


def xo_config(fake, **row):
    return {"servers": [{"host": fake.url, "username": "admin@admin.net", "password": "admin", **row}], "verify_tls": False, "allow_http": True}


def xapi_config(fake, **row):
    return {"servers": [{"host": fake.url, "username": "root", "password": "secret", **row}], "verify_tls": False, "allow_http": True}


def by_name(out):
    return {g["name"]: g for g in out["guests"]}


def test_manifest_is_valid():
    manifest = json.loads((ROOT / "plugin.json").read_text())
    assert validate_manifest(manifest)["kind"] == "hypervisor"
    assert manifest["power"] == ["reset", "reboot", "shutdown", "start"]


@pytest.mark.parametrize("mode", ["xo", "xapi"])
def test_both_ways_give_the_same_picture(mode):
    with FakeXen(xo=mode == "xo", xapi=mode == "xapi") as fake:
        out = plugin.fetch(xo_config(fake) if mode == "xo" else xapi_config(fake))
    validate_output("hypervisor", out)
    assert [h["name"] for h in out["hosts"]] == ["xcp-lab"]
    host = out["hosts"][0]
    assert host["id"] == HOST_ID and host["ip"] == "10.0.2.15" and host["mac"] == "52:54:00:12:34:56" and host["online"] is True
    guests = by_name(out)
    assert sorted(guests) == ["lab-vm1", "lab-vm2"]            # the control domain and the templates are no guests
    one, two = guests["lab-vm1"], guests["lab-vm2"]
    assert (one["id"], one["status"], one["host_id"], one["kind"]) == (VM1, "running", HOST_ID, "hvm")
    assert one["macs"] == ["aa:70:d3:eb:5b:99"] and two["macs"] == ["5e:a9:c0:1e:1a:bf"]
    assert (two["status"], two["host_id"]) == ("stopped", HOST_ID)   # a halted VM of a one-host pool belongs to that host
    assert two["details"]["disk_gb"] == 1 and two["details"]["memory_mb"] == 256 and two["details"]["cpus"] == 1
    assert one["details"]["started"].startswith("2026-10-28T17:2")
    system, pool = out["storage"]["systems"][0], out["storage"]["pools"][0]
    assert system["name"] == "xcp-lab" and system["vendor"] == "XCP-ng" and system["version"] == "8.3.0"
    assert pool["name"] == "Local storage" and pool["total"] == 8861896704 and pool["system_id"] == system["id"] and pool["raid"] == "ext"


def test_the_address_decides_which_way_is_used():
    with FakeXen(xo=True, xapi=False) as fake:
        assert plugin._client(xo_config(fake), xo_config(fake)["servers"][0]).mode == "xo"
    with FakeXen(xo=False, xapi=True) as fake:
        assert plugin._client(xapi_config(fake), xapi_config(fake)["servers"][0]).mode == "xapi"
        assert "pool master" in plugin.test(xapi_config(fake))["message"]


def test_xapi_session_is_closed_again():
    with FakeXen(xo=False, xapi=True) as fake:
        plugin.fetch(xapi_config(fake))
        assert fake.sessions_open == 0


def test_xo_token_login():
    with FakeXen() as fake:
        out = plugin.fetch({"servers": [{"host": fake.url, "token": "tok"}], "verify_tls": False, "allow_http": True})
    assert len(out["guests"]) == 2


@pytest.mark.parametrize("mode", ["xo", "xapi"])
def test_refused_login_stops_the_plugin(mode):
    with FakeXen(xo=mode == "xo", xapi=mode == "xapi") as fake:
        cfg = xo_config(fake, password="wrong") if mode == "xo" else xapi_config(fake, password="wrong")
        with pytest.raises(plugin.XenAuthError) as exc:
            plugin.test(cfg)
    assert exc.value.auth_failed is True


def test_an_address_that_is_neither_is_explained():
    with FakeXen(xo=False, xapi=False) as fake:
        with pytest.raises(plugin.XenError, match="neither a Xen Orchestra nor"):
            plugin.test(xapi_config(fake))


def test_missing_login_is_explained():
    with FakeXen() as fake:
        with pytest.raises(ValueError, match="token, or a user name and password"):
            plugin.test({"servers": [{"host": fake.url}], "verify_tls": False, "allow_http": True})
    with pytest.raises(ValueError, match="at least one"):
        plugin.test({"servers": []})


def test_addresses_of_running_vms_come_from_the_guest_agent():
    with FakeXen(xo=True, xapi=False) as fake:
        fake.xo["vms"][0]["addresses"] = {"0/ipv4/0": "192.168.0.77", "0/ipv6/0": "fe80::1", "0/ipv4/1": "169.254.1.1"}
        fake.xo["vms"][0]["mainIpAddress"] = "192.168.0.77"
        out = plugin.fetch(xo_config(fake))
    assert [g["ips"] for g in out["guests"] if g["ips"]] == [["192.168.0.77"]]
    with FakeXen(xo=False, xapi=True) as fake:
        gm = next(iter(fake.xapi["VM_guest_metrics"].values()))
        gm["networks"] = {"0/ip": "192.168.0.78", "0/ipv6/0": "fe80::2"}
        gm["os_version"] = {"name": "Debian GNU/Linux 12"}
        out = plugin.fetch(xapi_config(fake))
    guest = next(g for g in out["guests"] if g["ips"])
    assert guest["ips"] == ["192.168.0.78"] and guest["details"]["os"] == "Debian GNU/Linux 12"


def test_a_stopped_vm_in_a_bigger_pool_has_no_guessed_host():
    with FakeXen(xo=False, xapi=True) as fake:
        extra = dict(next(iter(fake.xapi["host"].values())), uuid="11111111-1111-1111-1111-111111111111", name_label="xcp-two")
        fake.xapi["host"]["OpaqueRef:second"] = extra
        out = plugin.fetch(xapi_config(fake))
    assert by_name(out)["lab-vm2"]["host_id"] is None and by_name(out)["lab-vm1"]["host_id"] == HOST_ID
    assert {h["name"] for h in out["hosts"]} == {"xcp-lab", "xcp-two"}


def test_a_vm_without_a_nic_or_a_paused_vm():
    with FakeXen(xo=True, xapi=False) as fake:
        fake.xo["vms"][1]["power_state"] = "Suspended"
        fake.xo["vifs"] = []
        out = plugin.fetch(xo_config(fake))
    assert by_name(out)["lab-vm2"]["status"] == "paused" and all(g["macs"] == [] for g in out["guests"])


def test_two_servers_that_show_the_same_pool_are_merged():
    with FakeXen(xo=True, xapi=False) as xo, FakeXen(xo=False, xapi=True) as master:
        cfg = {"servers": [{"host": xo.url, "username": "admin@admin.net", "password": "admin"}, {"host": master.url, "username": "root", "password": "secret"}], "verify_tls": False, "allow_http": True}
        out = plugin.fetch(cfg)
    validate_output("hypervisor", out)
    assert len(out["hosts"]) == 1 and len(out["guests"]) == 2


@pytest.mark.parametrize("mode", ["xo", "xapi"])
def test_power_actions(mode):
    with FakeXen(xo=mode == "xo", xapi=mode == "xapi") as fake:
        cfg = xo_config(fake) if mode == "xo" else xapi_config(fake)
        assert "hard_reboot sent to lab-vm1" in plugin.power(cfg, {"guest_id": VM1, "action": "reset"})["message"]
        assert "clean_shutdown" in plugin.power(cfg, {"guest_id": VM1, "action": "shutdown"})["message"]
        assert "start sent to lab-vm2" in plugin.power(cfg, {"guest_id": VM2, "action": "start"})["message"]
        assert "already running" in plugin.power(cfg, {"guest_id": VM1, "action": "start"})["message"]
        verbs = [a[-1] if mode == "xo" else a[0] for a in fake.actions]
        assert verbs == (["hard_reboot", "clean_shutdown", "start"] if mode == "xo" else ["VM.hard_reboot", "VM.clean_shutdown", "VM.start"])
        with pytest.raises(plugin.XenError, match="not found"):
            plugin.power(cfg, {"guest_id": "00000000-0000-0000-0000-000000000000", "action": "reset"})


def test_power_rejects_bad_input():
    with FakeXen() as fake:
        with pytest.raises(ValueError, match="unknown action"):
            plugin.power(xo_config(fake), {"guest_id": VM1, "action": "format"})
        with pytest.raises(ValueError, match="no Xen identifier"):
            plugin.power(xo_config(fake), {"guest_id": "101", "action": "reset"})


def test_clean_reboot_without_guest_tools_is_explained():
    with FakeXen(xo=False, xapi=True) as fake:
        fake.no_tools = True
        with pytest.raises(plugin.XenError, match="no Xen guest tools"):
            plugin.power(xapi_config(fake), {"guest_id": VM1, "action": "reboot"})


@pytest.mark.parametrize("mode", ["xo", "xapi"])
def test_diagnostic_report_has_no_names_or_addresses(mode):
    with FakeXen(xo=mode == "xo", xapi=mode == "xapi") as fake:
        report = plugin.diagnose(xo_config(fake) if mode == "xo" else xapi_config(fake))
    text = json.dumps(report)
    assert report["result"]["guests"] == 2 and report["result"]["hosts"] == 1 and report["result"]["guests_without_host"] == 0
    for leak in ("lab-vm", "xcp-lab", "10.0.2.15", "127.0.0.1", "52:54:00", "aa:70:d3", "Local storage"):
        assert leak not in text, leak


def test_problem_text_hides_the_server():
    out = plugin._problem(Exception("cannot connect to https://xo.example.com:8443: refused; 10.1.2.3:443 down; xo.example.com"), ["xo.example.com:8443"])
    assert "example.com" not in out and "10.1.2.3" not in out


def test_fingerprint_must_be_a_sha256():
    with pytest.raises(ValueError, match="64 hexadecimal"):
        plugin.make_transport(True, 5, "x", "B7:5B")
    plugin.make_transport(True, 5, "x", ":".join(["ab"] * 32))


def test_plain_http_is_refused_unless_allowed():
    with FakeXen() as fake:
        cfg = xo_config(fake)
        cfg["allow_http"] = False
        with pytest.raises(ValueError, match="unencrypted"):
            plugin.test(cfg)
        assert fake.seen == []                      # nothing was sent, not even the probe
        assert plugin.normalize_base("http://10.0.0.5", True) == "http://10.0.0.5"


def test_addresses_are_normalised():
    assert plugin.normalize_base("xo.example.com") == "https://xo.example.com"
    assert plugin.normalize_base("http://10.0.0.5:8080/foo/", True) == "http://10.0.0.5:8080"
    with pytest.raises(ValueError):
        plugin.normalize_base("ftp://x")
