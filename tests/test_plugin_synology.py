"""The Synology plugin against a fake DSM: a small HTTP server that answers the web API the way DSM does
(the shapes follow the public DSM Login Web API and Container Manager / Virtual Machine Manager responses)."""

import importlib.util
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "synology"
spec = importlib.util.spec_from_file_location("synology_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

INFO = {"model": "DS923+", "ram": 4096, "serial": "2260ABC123", "temperature": 41, "uptime": 123456, "version_string": "DSM 7.2.1-69057 Update 5", "hostname": "diskstation"}
NETWORK = {"server_name": "nas-kelder", "gateway": "192.168.0.1", "dns_primary": "192.168.0.1"}
INTERFACES = {"ifaces": [{"ifname": "eth0", "ip": "192.168.0.20", "mask": "255.255.255.0", "mac": "00:11:32:AA:BB:CC", "status": "connected"},
                         {"ifname": "eth1", "ip": "", "mac": "00:11:32:AA:BB:CD"}]}
CONTAINERS = {"containers": [
    {"name": "/pihole", "id": "abc", "image": "pihole/pihole:latest", "status": "running", "up_time": "2026-10-01T10:00:00Z",
     "ports": [{"container_port": 53, "host_port": 53, "type": "udp", "host_ip": "0.0.0.0"}, {"container_port": 80, "host_port": 8081, "type": "tcp"}]},
    {"name": "grafana", "id": "def", "image": "grafana/grafana", "status": "exited"}], "total": 2}
MACHINES = {"guests": [{"guest_id": "g-1", "guest_name": "Windows 11", "status": "running", "vcpu_num": 4, "vram_size": 8388608,
                        "vnics": [{"mac": "00:11:32:11:22:33", "network_name": "Default VM Network"}]},
                       {"guest_id": "g-2", "guest_name": "Ubuntu", "status": "shutdown", "vcpu_num": 2, "vram_size": 2097152, "vnics": []}]}
PACKAGES = {"packages": [{"id": "ContainerManager", "name": "Container Manager", "version": "20.10.23-1437", "additional": {"status": "running"}},
                         {"id": "SynologyDrive", "name": "Synology Drive Server", "version": "3.4.0", "additional": {"status": "stop"}}], "total": 2}


class FakeDSM:
    def __init__(self, **options):
        self.options = {"user": "netlens", "password": "good-pass", "missing": set(), "denied": set(), "otp": False, **options}
        self.calls = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, payload):
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _params(self):
                url = urllib.parse.urlsplit(self.path)
                params = dict(urllib.parse.parse_qsl(url.query))
                if self.command == "POST":
                    body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                    params.update(dict(urllib.parse.parse_qsl(body)))
                return url.path, params

            def do_GET(self):
                self.handle_it()

            def do_POST(self):
                self.handle_it()

            def handle_it(self):
                path, p = self._params()
                api, method = p.get("api"), p.get("method")
                fake.calls.append((api, method, self.command, "passwd" in self.path))
                if api == "SYNO.API.Info":
                    names = p.get("query", "").split(",")
                    known = {"SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 7}}
                    for n in names:
                        if n != "SYNO.API.Auth" and n not in fake.options["missing"]:
                            known[n] = {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2}
                    return self._answer({"success": True, "data": known})
                if api == "SYNO.API.Auth" and method == "login":
                    if fake.options["otp"]:
                        return self._answer({"success": False, "error": {"code": 403}})
                    if p.get("account") != fake.options["user"] or p.get("passwd") != fake.options["password"]:
                        return self._answer({"success": False, "error": {"code": 400}})
                    return self._answer({"success": True, "data": {"sid": "SID123"}})
                if api == "SYNO.API.Auth" and method == "logout":
                    fake.calls.append(("logout", p.get("_sid")))
                    return self._answer({"success": True})
                if p.get("_sid") != "SID123":
                    return self._answer({"success": False, "error": {"code": 119}})
                if api in fake.options["denied"]:
                    return self._answer({"success": False, "error": {"code": 105}})
                data = {"SYNO.DSM.Info": INFO, "SYNO.Core.Network": NETWORK, "SYNO.Core.Network.Interface": INTERFACES, "SYNO.Docker.Container": CONTAINERS,
                        "SYNO.Virtualization.API.Guest": MACHINES, "SYNO.Core.Package": PACKAGES}.get(api)
                if data is None:
                    return self._answer({"success": False, "error": {"code": 102}})
                return self._answer({"success": True, "data": data})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def config(self, **extra):
        return {"servers": [{"host": self.url, "username": self.options["user"], "password": self.options["password"]}], "timeout": 5, **extra}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def dsm():
    server = FakeDSM()
    yield server
    server.close()


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["id"] == "synology" and manifest["kind"] == "hypervisor"


def test_fetch_gives_host_and_guests(dsm):
    out = validate_output("hypervisor", plugin.fetch(dsm.config()))
    host = out["hosts"][0]
    assert host["name"] == "nas-kelder" and host["ip"] == "127.0.0.1" and host["id"] == "2260abc123"
    by_id = {g["id"]: g for g in out["guests"]}
    assert by_id["container:pihole"]["kind"] == "container" and by_id["container:pihole"]["status"] == "running"
    assert by_id["container:pihole"]["details"]["image"] == "pihole/pihole:latest"
    assert by_id["container:pihole"]["details"]["exposed"] is True                 # port 53 is bound to all interfaces
    assert by_id["container:grafana"]["status"] == "stopped"
    assert by_id["vm:g-1"]["kind"] == "qemu" and by_id["vm:g-1"]["macs"] == ["00:11:32:11:22:33"] and by_id["vm:g-1"]["details"]["cpus"] == 4
    assert by_id["vm:g-2"]["status"] == "stopped"
    assert by_id["pkg:ContainerManager"]["kind"] == "app" and by_id["pkg:SynologyDrive"]["status"] == "stopped"


def test_the_password_goes_in_a_post_body_and_the_session_is_closed(dsm):
    plugin.fetch(dsm.config())
    login = next(c for c in dsm.calls if c[:2] == ("SYNO.API.Auth", "login"))
    assert login[2] == "POST" and login[3] is False                               # not in the URL
    assert ("logout", "SID123") in dsm.calls


def test_the_host_mac_comes_from_the_card_with_the_address():
    server = FakeDSM()
    try:
        interfaces = json.loads(json.dumps(INTERFACES))
        interfaces["ifaces"][0]["ip"] = "127.0.0.1"
        snapshot = {"info": INFO, "network": NETWORK, "interfaces": interfaces, "containers": None, "machines": None, "packages": None, "notes": []}
        host = plugin.to_hypervisor(snapshot, "127.0.0.1")["hosts"][0]
        assert host["mac"] == "00:11:32:aa:bb:cc"
    finally:
        server.close()


def test_test_message_counts(dsm):
    message = plugin.test(dsm.config())["message"]
    assert "DS923+" in message and "2 container(s)" in message and "2 virtual machine(s)" in message and "2 package(s)" in message


def test_wrong_password_stops_retries(dsm):
    config = dsm.config()
    config["servers"][0]["password"] = "nope"
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(config)
    assert err.value.auth_failed is True and "password is wrong" in str(err.value)


def test_two_step_verification_is_explained():
    server = FakeDSM(otp=True)
    try:
        with pytest.raises(plugin.LoginRefused, match="two-step"):
            plugin.test(server.config())
    finally:
        server.close()


def test_a_missing_feature_is_a_note_not_a_failure():
    server = FakeDSM(missing={"SYNO.Virtualization.API.Guest", "SYNO.Core.Package"}, denied={"SYNO.Core.Network"})
    try:
        out = validate_output("hypervisor", plugin.fetch(server.config()))
        assert not [g for g in out["guests"] if g["kind"] in ("qemu", "app")] and len(out["guests"]) == 2
        message = plugin.test(server.config())["message"]
        assert "virtual machines" in message and "network name" in message and "no permission" in message
    finally:
        server.close()


def test_not_a_synology_is_a_connection_problem():
    from http.server import BaseHTTPRequestHandler

    class Plain(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>router</html>")

        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Plain)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(plugin.ConnectError, match="does not look like a Synology"):
            plugin.test({"servers": [{"host": f"http://127.0.0.1:{srv.server_address[1]}", "username": "u", "password": "p"}]})
    finally:
        srv.shutdown()


def test_address_forms():
    assert plugin.normalize("192.168.0.5") == ("https://192.168.0.5:5001", "192.168.0.5")
    assert plugin.normalize("https://nas.lan:5555/") == ("https://nas.lan:5555", "nas.lan")
    assert plugin.normalize("http://nas.lan")[0] == "http://nas.lan:5000"
    for bad in ("", "ftp://x", "https://"):
        with pytest.raises(ValueError):
            plugin.normalize(bad)


def test_two_systems_keep_their_guests_apart(dsm):
    other = FakeDSM()
    try:
        config = dsm.config()
        config["servers"].append({"host": other.url, "username": "netlens", "password": "good-pass"})
        out = plugin.fetch(config)
        ids = [g["id"] for g in out["guests"]]
        assert len(ids) == len(set(ids)) == 12 and len(out["hosts"]) == 2
    finally:
        other.close()


def test_diagnostic_never_contains_names_or_addresses(dsm):
    report = plugin.diagnose(dsm.config())
    text = json.dumps(report)
    for secret in ("pihole", "nas-kelder", "00:11:32", "Windows 11", "192.168.0.20", "good-pass", "2260ABC123"):
        assert secret not in text
    assert report["steps"]["containers"]["ok"] and report["result"]["by_kind"] == {"container": 2, "qemu": 2, "app": 2}
