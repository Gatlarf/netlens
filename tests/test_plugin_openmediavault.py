"""The OpenMediaVault plugin against a fake OMV: a small HTTP server that answers /rpc.php the way a real OpenMediaVault 8.5 does.
The login, System.getInformation, Network.enumerateDevices and Compose.getContainerList answers were recorded from a real OMV 8.5.12
(addresses and names changed); the openmediavault-kvm answers follow that plugin's source code (not recorded from a real one)."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "openmediavault"
spec = importlib.util.spec_from_file_location("omv_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

INFO = {"ts": 1792772105, "hostname": "nas-omv", "version": "8.5.12-1 (Synchrony)", "kernel": "Linux 6.12.111+deb13-amd64", "uptime": 281084.7, "cpuCores": "4", "memTotal": "16776454144"}
DEVICES = [
    {"devicename": "lo", "address": "", "ether": "00:00:00:00:00:00", "type": "loopback", "state": "UNKNOWN"},
    {"devicename": "veth0a6f13c", "address": "", "ether": "06:2d:e2:b9:84:80", "type": "virtual", "state": "UP"},
    {"devicename": "enp2s0", "address": "192.168.0.60", "ether": "bc:24:11:db:66:a4", "type": "ethernet", "state": "UP", "link": True},
]
CONTAINERS = {"total": 4, "data": [
    {"id": "d593", "name": "nl-snmpd", "image": "nl-snmpd", "execurl": "disabled", "created": "2026-10-21 22:30:38 +0200 CEST", "state": "running", "status": "Up 44 hours", "network": "bridge",
     "ports": "<a href=\"http://openmediavault:1161\" target=\"_blank\">0.0.0.0:1161->161/udp</a><br/><a href=\"http://openmediavault:1161\" target=\"_blank\">:1161->161/udp</a>"},
    {"id": "6124", "name": "dsm", "image": "vdsm/virtual-dsm:latest", "state": "running", "status": "Up 3 days (healthy)", "network": "vdsm_lan", "ports": ""},
    {"id": "cc8a", "name": "greenbone-nginx-1", "image": "community/nginx:latest", "state": "running", "status": "Up 3 days", "network": "greenbone_default",
     "ports": "<a href=\"http://openmediavault:443\" target=\"_blank\">127.0.0.1:443->443/tcp</a><br/>80/tcp<br/><a href=\"http://x:9392\" target=\"_blank\">127.0.0.1:9392->9392/tcp</a>"},
    {"id": "e0e0", "name": "old", "image": "alpine", "state": "exited", "status": "Exited (0) 2 days ago", "network": "bridge", "ports": "<a href=\"http://x:8000\">0.0.0.0:8000-8002->80-82/tcp</a>"},
]}
VMS = {"total": 2, "data": [
    {"vmname": "win11", "virttype": "vm", "mem": 8589934592, "cpu": 4, "state": "running", "autostart": True},
    {"vmname": "box", "virttype": "lxc", "mem": 1073741824, "cpu": 1, "state": "shutoff", "autostart": False}]}
NICS = {"win11": [{"mac": "52:54:00:aa:bb:cc", "description": "network - default (52:54:00:aa:bb:cc)"}], "box": []}


STORAGE_CALLS = {
    ("FileSystemMgmt", "getList"): {"total": 2, "data": [
        {"uuid": "u1", "devicefile": "/dev/sda1", "label": "data", "type": "ext4", "size": "4000000000000", "used": "3800000000000", "available": "200000000000", "percentage": 95, "mounted": True, "status": 1},
        {"uuid": "u2", "devicefile": "/dev/sdb1", "label": "", "type": "btrfs", "size": 1000, "used": 10, "available": 990, "mounted": False, "status": 1}]},
    ("DiskMgmt", "enumerateDevices"): [{"devicefile": "/dev/sda", "model": "WDC WD40", "size": "4000787030016"}, {"devicefile": "/dev/sdb", "model": "ST1000", "size": 1000204886016}],
    ("Smart", "getList"): {"total": 2, "data": [{"devicefile": "/dev/sda", "overallstatus": "GOOD", "temperature": 35}, {"devicefile": "/dev/sdb", "overallstatus": "BAD_SECTOR", "temperature": 40}]},
    ("Smb", "getShareList"): {"total": 1, "data": [{"uuid": "s1", "name": "media", "comment": ""}]},
    ("Nfs", "getShareList"): {"total": 1, "data": [{"uuid": "n1", "client": "192.168.0.0/24", "mntentref": "u1"}]},
}


class FakeOmv:
    def __init__(self, kvm=True, compose=True, broken_compose=False):
        self.kvm, self.compose, self.broken_compose = kvm, compose, broken_compose
        self.calls = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, response=None, error=None, cookie=None):
                raw = json.dumps({"response": response, "error": error}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                service, method, params = body["service"], body["method"], body.get("params")
                fake.calls.append((service, method))
                if self.path != "/rpc.php":
                    return self._send(404)
                if (service, method) == ("Session", "login"):
                    if params == {"username": "netlens", "password": "good-pass"}:
                        return self._send(200, {"username": "netlens", "status": "authenticated", "permissions": {"role": "admin"}, "sessionid": "SID9"}, cookie="OPENMEDIAVAULT-SESSIONID=SID9; path=/; HttpOnly")
                    return self._send(400, None, {"code": 5000, "message": "Incorrect username or password."})
                if "OPENMEDIAVAULT-SESSIONID=SID9" not in (self.headers.get("Cookie") or "") or self.headers.get("X-OPENMEDIAVAULT-SESSIONID") != "SID9":
                    return self._send(401, None, {"code": 0, "message": "Session not authenticated."})
                if (service, method) == ("Session", "logout"):
                    return self._send(200, None)
                if (service, method) == ("System", "getInformation"):
                    return self._send(200, INFO)
                if (service, method) == ("Network", "enumerateDevices"):
                    return self._send(200, DEVICES)
                if service == "Compose" and (not fake.compose):
                    return self._send(404, None, {"code": 0, "message": "RPC service 'Compose' not found."})
                if (service, method) == ("Compose", "getContainerList"):
                    if fake.broken_compose:
                        return self._send(500, None, {"code": 0, "message": "docker: command failed"})
                    return self._send(200, CONTAINERS)
                if service == "Kvm" and not fake.kvm:
                    return self._send(404, None, {"code": 0, "message": "RPC service 'Kvm' not found."})
                if (service, method) == ("Kvm", "getVmList"):
                    return self._send(200, VMS)
                if (service, method) == ("Kvm", "enumerateVmNic"):
                    return self._send(200, NICS[params["vmname"]])
                if (service, method) in STORAGE_CALLS:
                    return self._send(200, STORAGE_CALLS[(service, method)])
                self._send(500, None, {"code": 0, "message": f"unknown {service}.{method}"})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def config(self, password="good-pass"):
        return {"servers": [{"host": self.url, "username": "netlens", "password": password}], "timeout": 5}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def omv():
    fake = FakeOmv()
    yield fake
    fake.close()


def test_manifest_is_valid():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"


def test_fetch_gives_host_containers_and_machines(omv):
    out = validate_output("hypervisor", plugin.fetch(omv.config()))
    host = out["hosts"][0]
    assert host["name"] == "nas-omv" and host["ip"] == "192.168.0.60" and host["mac"] == "bc:24:11:db:66:a4"      # connected by 127.0.0.1: taken from the first real card
    guests = {g["name"]: g for g in out["guests"]}
    assert set(guests) == {"nl-snmpd", "dsm", "greenbone-nginx-1", "old", "win11", "box"}
    snmp = guests["nl-snmpd"]
    assert snmp["status"] == "running" and snmp["kind"] == "container"
    assert snmp["details"]["ports"] == [{"container_port": 161, "host_port": 1161, "proto": "udp", "bind": "0.0.0.0"}]       # the IPv6 twin is dropped
    assert snmp["details"]["exposed"] is True
    assert guests["dsm"]["details"]["health"] == "healthy" and "ports" not in guests["dsm"]["details"]
    assert [p["host_port"] for p in guests["greenbone-nginx-1"]["details"]["ports"]] == [443, 9392]      # the unpublished 80/tcp is left out
    assert guests["greenbone-nginx-1"]["details"]["exposed"] is False
    assert guests["old"]["status"] == "stopped" and guests["old"]["details"]["ports"][0]["host_port"] == 8000
    assert guests["win11"]["kind"] == "qemu" and guests["win11"]["macs"] == ["52:54:00:aa:bb:cc"] and guests["win11"]["details"]["memory_mb"] == 8192
    assert guests["box"]["kind"] == "lxc" and guests["box"]["status"] == "stopped" and guests["box"]["macs"] == []


def test_the_session_is_closed(omv):
    plugin.fetch(omv.config())
    assert omv.calls[0] == ("Session", "login") and omv.calls[-1] == ("Session", "logout")


def test_wrong_password_stops_retries(omv):
    with pytest.raises(Exception) as err:
        plugin.fetch(omv.config("bad"))
    assert getattr(err.value, "auth_failed", False) is True and "Incorrect" in str(err.value)


def test_missing_plugins_are_notes_not_failures():
    fake = FakeOmv(kvm=False, compose=False)
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert out["guests"] == [] and out["hosts"][0]["name"] == "nas-omv"
        message = plugin.test(fake.config())["message"]
        assert "openmediavault-compose" in message and "openmediavault-kvm" in message
    finally:
        fake.close()


def test_a_failing_docker_is_a_note():
    fake = FakeOmv(broken_compose=True)
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert {g["kind"] for g in out["guests"]} == {"qemu", "lxc"}
        assert "docker: command failed" in plugin.test(fake.config())["message"]
    finally:
        fake.close()


def test_test_message(omv):
    message = plugin.test(omv.config())["message"]
    assert "nas-omv" in message and "OpenMediaVault 8.5.12-1" in message and "4 container(s)" in message and "2 virtual machine(s)" in message


def test_port_parser():
    assert plugin._ports("<a href=\"x\">[::]:8080->80/tcp</a><br/>0.0.0.0:8080->80/tcp<br/>53/udp") == [{"container_port": 80, "host_port": 8080, "proto": "tcp", "bind": "::"}]
    assert plugin._ports("") == [] and plugin._ports(None) == []


def test_not_an_omv_is_a_connection_problem():
    with pytest.raises(plugin.ConnectError):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 2})


def test_address_forms():
    assert plugin.normalize("192.168.0.60")[0] == "http://192.168.0.60"
    assert plugin.normalize("https://nas.lan:8443/")[0] == "https://nas.lan:8443"
    with pytest.raises(ValueError):
        plugin.normalize("")


def test_diagnostic_never_contains_names_or_addresses(omv):
    report = json.dumps(plugin.diagnose(omv.config()))
    for leak in ("nl-snmpd", "dsm", "nas-omv", "win11", "192.168", "bc:24", "52:54", "127.0.0.1", "good-pass"):
        assert leak not in report, leak
    assert '"ok": true' in report


def test_storage_part_has_file_systems_disks_and_shares(omv):
    st = validate_output("hypervisor", plugin.fetch(omv.config()))["storage"]
    pools = {p["name"]: p for p in st["pools"]}
    assert pools["data"]["total"] == 4000000000000 and pools["data"]["avail"] == 200000000000 and pools["data"]["raid"] == "ext4" and pools["data"]["health"] == "ok"
    assert pools["/dev/sdb1"]["health"] == "warning"                                  # not mounted
    disks = {d["name"]: d for d in st["disks"]}
    assert disks["/dev/sda"]["state"] == "ok" and disks["/dev/sdb"]["state"] == "degraded" and disks["/dev/sda"]["size"] == 4000787030016
    assert {v["name"] for v in st["volumes"]} == {"media", "192.168.0.0/24"}
    assert st["systems"][0]["vendor"] == "OpenMediaVault" and st["systems"][0]["health"] == "warning"
    assert any("S.M.A.R.T." in a["text"] for a in st["alerts"])


def test_storage_part_is_left_out_when_there_is_nothing():
    fake = FakeOmv()
    try:
        saved = dict(STORAGE_CALLS)
        for key in STORAGE_CALLS:
            STORAGE_CALLS[key] = {"total": 0, "data": []} if key[0] != "DiskMgmt" else []
        assert "storage" not in plugin.fetch(fake.config())
    finally:
        STORAGE_CALLS.update(saved)
        fake.close()
