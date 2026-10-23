"""The Unraid plugin against a fake Unraid API: a small HTTP server that answers GraphQL the way Unraid 7.2 does
(field names follow the published schema, unraid/api generated-schema.graphql; not recorded from a real server)."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "unraid"
spec = importlib.util.spec_from_file_location("unraid_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

KEY = "k-good"
NET = {"name": "br0", "macAddress": "AA:BB:CC:00:11:22", "ipAddress": "192.168.0.10", "virtual": False, "internal": False}
CONTAINERS = [
    {"id": "srv:1", "names": ["/plex"], "image": "linuxserver/plex", "state": "RUNNING", "status": "Up 3 days", "autoStart": True,
     "ports": [{"ip": "0.0.0.0", "privatePort": 32400, "publicPort": 32400, "type": "TCP"}, {"ip": "::", "privatePort": 32400, "publicPort": 32400, "type": "TCP"}],
     "hostConfig": {"networkMode": "bridge"}, "networkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2", "MacAddress": "02:42:ac:11:00:02"}}}},
    {"id": "srv:2", "names": ["/pihole"], "image": "pihole/pihole", "state": "EXITED", "status": "Exited (0) 1 hour ago", "autoStart": False, "ports": [],
     "hostConfig": {"networkMode": "br0"}, "networkSettings": {"Networks": {"br0": {"IPAddress": "192.168.0.53", "MacAddress": "02:00:c0:a8:00:35"}}}},
]
DOMAINS = [{"id": "srv:uuid-1", "name": "Windows 11", "state": "RUNNING"}, {"id": "srv:uuid-2", "name": "Debian", "state": "SHUTOFF"}]


ARRAY = {"state": "STARTED", "capacity": {"kilobytes": {"free": "1000", "used": "9000", "total": "10000"}},
         "parities": [{"id": "p0", "idx": 0, "name": "parity", "device": "sdb", "size": "4000", "status": "DISK_OK", "type": "PARITY", "numErrors": "0"}],
         "disks": [{"id": "d1", "idx": 1, "name": "disk1", "device": "sdc", "size": "4000", "status": "DISK_OK", "type": "DATA", "numErrors": "0"},
                   {"id": "d2", "idx": 2, "name": "disk2", "device": "sdd", "size": "4000", "status": "DISK_DSBL", "type": "DATA", "numErrors": "12"},
                   {"id": "d3", "idx": 3, "name": "disk3", "device": "sde", "size": "4000", "status": "DISK_OK", "type": "DATA", "numErrors": "3"},
                   {"id": "d4", "idx": 4, "name": "disk4", "device": None, "size": None, "status": "DISK_NP", "type": "DATA"}],
         "caches": [{"id": "c1", "idx": 30, "name": "cache", "device": "nvme0n1", "size": "500", "status": "DISK_OK", "type": "CACHE", "fsSize": "480", "fsUsed": "100", "fsFree": "380", "fsType": "btrfs", "numErrors": "0"}]}
SHARES = [{"name": "media", "free": "500", "used": "1500", "size": "0"}, {"name": "appdata", "free": "380", "used": "20"}]


class FakeUnraid:
    def __init__(self, **options):
        self.options = {"old": False, "no_vms": False, "redirect": False, **options}
        self.seen = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, payload, headers=None):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                query = body.get("query", "")
                fake.seen.append((self.path, self.headers.get("x-api-key"), query))
                if fake.options["redirect"] and self.headers.get("Host") == fake.host_header:
                    return self._send(307, {}, {"Location": f"http://localhost:{fake.port}/graphql"})
                if self.headers.get("x-api-key") != KEY:
                    return self._send(401, {"errors": [{"message": "Invalid API key", "extensions": {"code": "UNAUTHENTICATED"}}]})
                if "primaryNetwork" in query:
                    return self._send(200, {"data": {"info": {"primaryNetwork": NET, "networkInterfaces": [NET, {"name": "virbr0", "macAddress": "52:54:00:aa:bb:cc", "ipAddress": "192.168.122.1", "virtual": True}]}}})
                if "array {" in query:
                    return self._send(200, {"data": {"array": ARRAY}}) if not fake.options.get("no_array") else self._send(200, {"errors": [{"message": "array is not available"}], "data": None})
                if "shares {" in query:
                    return self._send(200, {"data": {"shares": SHARES}})
                if "os {" in query:
                    return self._send(200, {"data": {"info": {"os": {"hostname": "Tower", "distro": "Unraid OS", "release": "7.2.0", "uptime": "2026-10-01T00:00:00Z"}}}})
                if "server {" in query:
                    return self._send(200, {"data": {"server": {"name": "Tower", "lanip": "192.168.0.10"}}})
                if "docker {" in query and not fake.options["old"]:
                    return self._send(200, {"data": {"docker": {"containers": CONTAINERS}}})
                if "dockerContainers" in query and fake.options["old"]:
                    return self._send(200, {"data": {"dockerContainers": CONTAINERS}})
                if "docker" in query.lower():
                    return self._send(200, {"errors": [{"message": "Cannot query field \"docker\" on type \"Query\"."}]})
                if "vms {" in query:
                    if fake.options["no_vms"]:
                        return self._send(200, {"errors": [{"message": "VMs are not available"}], "data": None})
                    return self._send(200, {"data": {"vms": {"domains": DOMAINS}}})
                return self._send(200, {"errors": [{"message": "unknown"}]})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.host_header = f"127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def config(self, key=KEY, **extra):
        return {"servers": [{"host": self.url, "api_key": key}], "timeout": 5, **extra}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def unraid():
    fake = FakeUnraid()
    yield fake
    fake.close()


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "hypervisor"


def test_fetch_gives_host_and_guests(unraid):
    out = validate_output("hypervisor", plugin.fetch(unraid.config()))
    host = out["hosts"][0]
    assert host["name"] == "Tower" and host["ip"] == "192.168.0.10" and host["mac"] == "aa:bb:cc:00:11:22"      # connected by 127.0.0.1: the address comes from Unraid
    guests = {g["name"]: g for g in out["guests"]}
    assert set(guests) == {"plex", "pihole", "Windows 11", "Debian"}
    plex = guests["plex"]
    assert plex["kind"] == "container" and plex["status"] == "running" and plex["macs"] == []
    assert plex["details"]["ports"] == [{"container_port": 32400, "host_port": 32400, "proto": "tcp", "bind": "0.0.0.0"}]      # IPv6 twin dropped
    assert plex["details"]["exposed"] is True and plex["details"]["autostart"] is True
    assert guests["pihole"]["macs"] == ["02:00:c0:a8:00:35"] and guests["pihole"]["ips"] == ["192.168.0.53"] and guests["pihole"]["status"] == "stopped"
    assert guests["Windows 11"]["kind"] == "qemu" and guests["Windows 11"]["status"] == "running" and guests["Debian"]["status"] == "stopped"
    assert guests["Debian"]["id"] == "vm:uuid-2"


def test_the_host_takes_its_mac_from_the_card_with_the_address():
    snapshot = {"info": {"info": {"os": {"hostname": "Tower"}}}, "server": {"server": {"lanip": "192.168.0.10"}},
                "network": {"info": {"primaryNetwork": NET, "networkInterfaces": [NET]}}, "containers": {}, "machines": {}, "notes": []}
    host = plugin.to_hypervisor(snapshot, "192.168.0.10")["hosts"][0]
    assert host["mac"] == "aa:bb:cc:00:11:22" and host["ip"] == "192.168.0.10"
    named = plugin.to_hypervisor(snapshot, "tower.local")["hosts"][0]            # connected by name: the address comes from Unraid
    assert named["ip"] == "192.168.0.10" and named["mac"] == "aa:bb:cc:00:11:22"


def test_the_key_goes_in_the_header_only(unraid):
    plugin.fetch(unraid.config())
    assert all(path == "/graphql" and key == KEY for path, key, _ in unraid.seen)


def test_older_api_names_work():
    fake = FakeUnraid(old=True)
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert {g["name"] for g in out["guests"]} >= {"plex", "pihole"}
    finally:
        fake.close()


def test_wrong_key_stops_retries(unraid):
    with pytest.raises(Exception) as err:
        plugin.fetch(unraid.config(key="wrong"))
    assert getattr(err.value, "auth_failed", False) is True


def test_a_missing_feature_is_a_note_not_a_failure():
    fake = FakeUnraid(no_vms=True)
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert {g["kind"] for g in out["guests"]} == {"container"}
        assert "virtual machines" in plugin.test(fake.config())["message"]
    finally:
        fake.close()


def test_test_message_counts(unraid):
    message = plugin.test(unraid.config())["message"]
    assert "Tower" in message and "Unraid 7.2.0" in message and "2 container(s)" in message and "2 virtual machine(s)" in message


def test_an_http_redirect_is_followed_for_the_post():
    fake = FakeUnraid(redirect=True)
    try:
        cfg = fake.config()
        out = plugin.fetch(cfg)
        assert out["guests"]
        assert any(path == "/graphql" for path, _, _ in fake.seen)
    finally:
        fake.close()


def test_not_unraid_is_a_connection_problem():
    with pytest.raises(plugin.ConnectError):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "api_key": "x"}], "timeout": 2})


def test_address_forms():
    assert plugin.normalize("tower")[0] == "http://tower"
    assert plugin.normalize("https://192.168.0.10:8443/")[0] == "https://192.168.0.10:8443"
    with pytest.raises(ValueError):
        plugin.normalize("ftp://x")
    with pytest.raises(ValueError):
        plugin.normalize("")


def test_diagnostic_never_contains_names_or_addresses(unraid):
    report = json.dumps(plugin.diagnose(unraid.config()))
    for leak in ("plex", "pihole", "Tower", "192.168", "aa:bb:cc", "Windows 11", "127.0.0.1", KEY):
        assert leak not in report
    assert '"ok": true' in report


def test_storage_part_has_array_cache_disks_and_shares(unraid):
    st = validate_output("hypervisor", plugin.fetch(unraid.config()))["storage"]
    pools = {p["name"]: p for p in st["pools"]}
    assert pools["Array"]["total"] == 10000 * 1024 and pools["Array"]["avail"] == 1000 * 1024 and pools["Array"]["raid"] == "parity"
    assert pools["cache"]["total"] == 480 * 1024 and pools["cache"]["raid"] == "btrfs"
    disks = {d["name"]: d for d in st["disks"]}
    assert set(disks) == {"parity", "disk1", "disk2", "disk3", "cache"}                      # the empty slot is left out
    assert disks["disk1"]["state"] == "ok" and disks["disk2"]["state"] == "failed" and disks["disk3"]["state"] == "degraded"
    shares = {v["name"]: v for v in st["volumes"]}
    assert shares["media"]["size"] == 2000 * 1024 and shares["media"]["used"] == 1500 * 1024 and shares["media"]["pool_id"] == "array"
    assert st["systems"][0]["vendor"] == "Unraid" and st["systems"][0]["health"] == "critical"


def test_a_stopped_array_is_a_warning_and_no_array_means_no_storage_part():
    server = FakeUnraid()
    try:
        ARRAY["state"] = "STOPPED"
        assert plugin.fetch(server.config())["storage"]["systems"][0]["health"] in ("warning", "critical")
    finally:
        ARRAY["state"] = "STARTED"
        server.close()
    server = FakeUnraid(no_array=True)
    try:
        assert "storage" not in plugin.fetch(server.config())
    finally:
        server.close()
