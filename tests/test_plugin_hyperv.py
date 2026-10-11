"""The Hyper-V plugin: the NTLM login against the published test vectors and a simulated WinRM service, the shell protocol, the VMs."""

import importlib.util
import json
import shutil
import struct
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from app.plugins.matching import match_hypervisor
from tests.fake_winrm import FakeWinRM, vm

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "hyperv"
spec = importlib.util.spec_from_file_location("hyperv_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is needed to make a test certificate")

VMS = {"Host": "ILLUSION-265K", "Vms": [
    vm("11111111-0000-0000-0000-000000000001", "web", nics=[("00155D010203", ["192.168.0.60", "fe80::1", "169.254.5.5"], "External")], up=7200, auto="StartIfRunning"),
    vm("11111111-0000-0000-0000-000000000002", "db", state="Off", mem=4096, nics=[("000000000000", [], "External"), ("00155D010204", [], "Internal")]),
    vm("11111111-0000-0000-0000-000000000003", "lab", state="Paused", nics=[]),
]}


def config(server, **extra):
    return {"servers": [{"host": server.url, "username": server.user, "password": server.password, "lan": "192.168.0.115"}], "verify_tls": False, "timeout": 10, **extra}


# ---------------------------------------------------------------- the cryptography, against the published values
def test_md4_matches_the_rfc_vectors():
    assert plugin.md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert plugin.md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert plugin.md4(b"1234567890" * 8).hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"
    assert plugin.md4(b"a" * 55).hex() == plugin.md4(b"a" * 55).hex() and len(plugin.md4(b"a" * 64)) == 16      # block-boundary lengths run


def test_ntlmv2_matches_the_ms_nlmp_example():
    key = plugin.nt_hash_v2("User", "Password", "Domain")                      # MS-NLMP 4.2.4.1.1
    assert key.hex() == "0c868a403bfd7a93a3001ef22ef02e3f"
    info = struct.pack("<HH", 2, 12) + "Domain".encode("utf-16-le") + struct.pack("<HH", 1, 12) + "Server".encode("utf-16-le") + b"\x00" * 4
    blob = b"\x01\x01" + b"\x00" * 6 + b"\x00" * 8 + b"\xaa" * 8 + b"\x00" * 4 + info + b"\x00" * 4
    assert plugin._hmac_md5(key, bytes.fromhex("0123456789abcdef") + blob).hex() == "68cd0ab851e51c96aabc927bebef6a1c"      # 4.2.4.2.2


# ---------------------------------------------------------------- the plugin
def test_the_manifest_follows_the_contract():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "hypervisor" and manifest["diagnose"] and "Hyper-V" in manifest["info"]["title"]
    assert [c["key"] for c in manifest["config"][0]["columns"]] == ["host", "username", "password", "lan"]


@needs_openssl
def test_fetch_logs_in_with_ntlm_runs_one_read_only_script_and_reads_the_vms(tmp_path):
    with FakeWinRM(tmp_path, output=VMS) as server:
        out = plugin.fetch(config(server))
        assert server.logins == 1 and server.actions == ["Create", "Command", "Receive", "Delete"] and server.shells_open == 0
        assert len(server.scripts) == 1 and server.scripts[0] == plugin.SCRIPT
    script = plugin.SCRIPT
    assert "Get-VM" in script and not any(w in script for w in ("Start-VM", "Stop-VM", "Set-", "Remove-", "New-", "Invoke-", "Restart"))
    checked = validate_output("hypervisor", out)
    host = checked["hosts"][0]
    assert host["name"] == "ILLUSION-265K" and host["ip"] == "192.168.0.115"
    web, db, lab = checked["guests"]
    assert web["status"] == "running" and web["macs"] == ["00:15:5d:01:02:03"] and web["ips"] == ["192.168.0.60"]           # no IPv6, no link-local
    assert web["details"]["cpus"] == 2 and web["details"]["memory_mb"] == 2048 and web["details"]["autostart"] is True and web["details"]["network"] == "External"
    assert web["details"]["started"].endswith("Z") and web["details"]["version"] == "generation 2"
    assert db["status"] == "stopped" and db["macs"] == ["00:15:5d:01:02:04"] and db["details"]["memory_mb"] == 4096 and "started" not in db["details"]   # the unassigned address is dropped
    assert lab["status"] == "paused" and lab["macs"] == []
    matched = match_hypervisor(checked, [{"id": 1, "mac": "00:15:5d:01:02:03", "ips": ["192.168.0.60"]}, {"id": 2, "mac": None, "ips": ["192.168.0.115"]}])
    assert matched["hosts"] == {host["id"]: 2} and matched["guests"][0]["device_id"] == 1


@needs_openssl
def test_a_single_vm_and_no_vms_are_both_fine(tmp_path):
    one = {"Host": "H", "Vms": vm("a", "only", nics=[("00155D000001", "192.168.0.9", "S")])}       # PowerShell prints a one-item list as a plain object
    with FakeWinRM(tmp_path, output=one) as server:
        assert plugin.fetch(config(server))["guests"][0]["ips"] == ["192.168.0.9"]
    with FakeWinRM(tmp_path, output={"Host": "H", "Vms": []}) as server:
        assert plugin.fetch(config(server))["guests"] == []


@needs_openssl
def test_a_wrong_password_pauses_the_plugin(tmp_path):
    with FakeWinRM(tmp_path, output=VMS) as server:
        bad = config(server)
        bad["servers"][0]["password"] = "nope"
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.fetch(bad)
        assert caught.value.auth_failed and "Remote Management Users" in str(caught.value)
        assert server.actions == []


@needs_openssl
def test_basic_login_works_too(tmp_path):
    with FakeWinRM(tmp_path, auth="basic", output=VMS) as server:
        assert len(plugin.fetch(config(server, auth="basic"))["guests"]) == 3
        with pytest.raises(plugin.HyperVError, match="does not offer NTLM"):
            plugin.fetch(config(server, auth="ntlm"))


@needs_openssl
def test_a_domain_user_is_split(tmp_path):
    with FakeWinRM(tmp_path, domain="CORP", output=VMS) as server:
        cfg = config(server)
        cfg["servers"][0]["username"] = "CORP\\netlens"
        assert len(plugin.fetch(cfg)["guests"]) == 3


@needs_openssl
def test_a_receive_that_times_out_is_asked_again(tmp_path):
    with FakeWinRM(tmp_path, output=VMS, slow_first_receive=True) as server:
        assert len(plugin.fetch(config(server))["guests"]) == 3
        assert server.actions.count("Receive") == 2


@needs_openssl
def test_missing_permission_and_missing_role_are_explained(tmp_path):
    clixml = '#< CLIXML <Objs><S S="Error">Get-VM : You do not have the required permission to complete this task._x000D__x000A_</S></Objs>'
    with FakeWinRM(tmp_path, output="", stderr=clixml, exit_code=1) as server:
        with pytest.raises(plugin.AuthRefused, match="Hyper-V Administrators"):
            plugin.fetch(config(server))
    clixml = '<Objs><S S="Error">Get-VM : The term \'Get-VM\' is not recognized as the name of a cmdlet_x000D__x000A_</S></Objs>'
    with FakeWinRM(tmp_path, output="", stderr=clixml, exit_code=1) as server:
        with pytest.raises(plugin.HyperVError, match="not installed"):
            plugin.fetch(config(server))
    with FakeWinRM(tmp_path, output="", stderr="<Objs><S S=\"Error\">boom_x000D__x000A_</S></Objs>", exit_code=1) as server:
        with pytest.raises(plugin.HyperVError, match="script failed: boom"):
            plugin.fetch(config(server))


def test_ntlm_over_plain_http_is_refused_with_advice():
    session = plugin.Session("127.0.0.1", 5985, False, "u", "p")
    with pytest.raises(plugin.HyperVError, match="needs https"):
        session._post_once(b"x") if session.conn else (session._connect(), session._post_once(b"x"))


def test_addresses_are_understood_and_unreachable_hosts_reported():
    assert plugin.parse_target({"host": "192.168.0.115"}, {}) == ("192.168.0.115", 5986, True)
    assert plugin.parse_target({"host": "http://h:5985"}, {}) == ("h", 5985, False)
    assert plugin.parse_target({"host": "https://h"}, {}) == ("h", 5986, True)
    with pytest.raises(plugin.HyperVError):
        plugin.parse_target({"host": "ftp://h"}, {})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(plugin.AuthRefused):
        plugin.parse_servers({"servers": [{"host": "h", "username": "", "password": ""}]})
    with pytest.raises(plugin.HyperVError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "https://127.0.0.1:1", "username": "u", "password": "p"}], "timeout": 3})


@needs_openssl
def test_test_message_and_diagnose_are_plain(tmp_path):
    with FakeWinRM(tmp_path, output=VMS) as server:
        assert "3 virtual machine(s), 1 running" in plugin.test(config(server))["message"]
    with FakeWinRM(tmp_path, output=VMS) as server:
        text = json.dumps(plugin.diagnose(config(server)))
    steps = json.loads(text)["servers"][0]["steps"]
    assert steps["get_vm"] == {"ok": True, "vms": 3, "states": {"running": 1, "stopped": 1, "paused": 1}, "with_mac": 2, "with_ip": 1}
    assert "192.168" not in text and "web" not in text and "ILLUSION" not in text and "netlens" not in text.replace("netlens-", "")
