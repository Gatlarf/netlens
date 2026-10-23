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
# the real DSM 7.2.2 container list has no ports or networks (checked on a virtual DSM): they come from `get`, a full docker inspect
CONTAINERS = {"containers": [
    {"name": "/pihole", "id": "abc", "image": "pihole/pihole:latest", "status": "running", "up_time": "2026-10-01T10:00:00Z"},
    {"name": "grafana", "id": "def", "image": "grafana/grafana", "status": "exited"},
    {"name": "unifi", "id": "ghi", "image": "jacobalberty/unifi", "status": "running"}], "total": 3}
INSPECT = {
    "pihole": {"HostConfig": {"PortBindings": {"53/udp": [{"HostIp": "0.0.0.0", "HostPort": "53"}], "80/tcp": [{"HostIp": "", "HostPort": "8081"}]}},
               "NetworkSettings": {"Ports": {}, "Networks": {"bridge": {"IPAddress": "172.17.0.2", "MacAddress": "02:42:ac:11:00:02"}}}},
    "grafana": {"HostConfig": {"PortBindings": {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]}}, "NetworkSettings": {"Ports": {}, "Networks": {"bridge": {"IPAddress": "", "MacAddress": ""}}}},
    "unifi": {"HostConfig": {"PortBindings": {}}, "NetworkSettings": {"Networks": {"lan": {"IPAddress": "192.168.0.45", "MacAddress": "02:00:C0:A8:00:2D"}}}},
}
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
                if api == "SYNO.Docker.Container" and method == "get":
                    if "get" in fake.options["missing"]:
                        return self._answer({"success": False, "error": {"code": 105}})
                    return self._answer({"success": True, "data": {"details": INSPECT[p.get("name")]}})
                data = {"SYNO.DSM.Info": INFO, "SYNO.Core.Network": NETWORK, "SYNO.Core.Network.Interface": INTERFACES, "SYNO.Docker.Container": CONTAINERS,
                        "SYNO.Virtualization.API.Guest": MACHINES, "SYNO.Core.Package": PACKAGES, "SYNO.Storage.CGI.Storage": fake.options.get("storage"),
                        "SYNO.Core.Share": fake.options.get("shares"), "SYNO.Core.ISCSI.LUN": fake.options.get("luns"),
                        "SYNO.Core.ISCSI.Target": fake.options.get("targets")}.get(api)
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
    assert {(p["host_port"], p["proto"]) for p in by_id["container:pihole"]["details"]["ports"]} == {(53, "udp"), (8081, "tcp")}
    assert by_id["container:pihole"]["macs"] == [] and by_id["container:pihole"]["ips"] == []        # Docker's own bridge (02:42:..) is not a device on the network
    assert by_id["container:grafana"]["status"] == "stopped" and by_id["container:grafana"]["details"]["exposed"] is False        # published on 127.0.0.1 only: also for a stopped container
    assert by_id["container:unifi"]["macs"] == ["02:00:c0:a8:00:2d"] and by_id["container:unifi"]["ips"] == ["192.168.0.45"]        # a macvlan container is a device of its own
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
    assert "DS923+" in message and "3 container(s)" in message and "2 virtual machine(s)" in message and "2 package(s)" in message


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
        assert not [g for g in out["guests"] if g["kind"] in ("qemu", "app")] and len(out["guests"]) == 3
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
        assert len(ids) == len(set(ids)) == 14 and len(out["hosts"]) == 2
    finally:
        other.close()


def test_diagnostic_never_contains_names_or_addresses(dsm):
    report = plugin.diagnose(dsm.config())
    text = json.dumps(report)
    for secret in ("pihole", "nas-kelder", "00:11:32", "Windows 11", "192.168.0.20", "good-pass", "2260ABC123"):
        assert secret not in text
    assert report["steps"]["containers"]["ok"] and report["result"]["by_kind"] == {"container": 3, "qemu": 2, "app": 2}


def test_without_permission_to_read_container_details_the_list_still_works(dsm_missing_get):
    out = plugin.fetch(dsm_missing_get.config())
    assert {g["name"] for g in out["guests"] if g["kind"] == "container"} == {"pihole", "grafana", "unifi"}
    assert plugin.test(dsm_missing_get.config())["message"].count("container details") == 1


@pytest.fixture
def dsm_missing_get():
    fake = FakeDSM(missing={"get"})
    yield fake
    fake.close()


STORAGE = {
    "storagePools": [{"id": "reuse_1", "num_id": 1, "desc": "Storage Pool 1", "status": "degraded", "raidType": "raid_5", "pool_path": "reuse_1", "size": {"total": "8000000000000", "used": "6000000000000"}},
                     {"id": "reuse_2", "desc": "Pool 2", "status": "normal", "pool_path": "reuse_2", "size": {"total": "1000", "used": "10"}}],
    "volumes": [{"id": "volume_1", "vol_path": "/volume1", "fs_type": "btrfs", "status": "normal", "pool_path": "reuse_1", "size": {"total": "7000000000000", "used": "6000000000000"}},
                {"id": "volume_2", "vol_path": "/volume2", "fs_type": "ext4", "status": "crashed", "pool_path": "reuse_2", "size": {"total": "1000", "used": "10"}}],
    "disks": [{"id": "sata1", "name": "Drive 1", "vendor": "WDC", "model": "WD40EFRX", "size_total": "4000787030016", "status": "normal", "smart_status": "normal", "slot_id": 1},
              {"id": "sata2", "name": "Drive 2", "model": "ST4000", "size_total": "4000787030016", "status": "crashed", "smart_status": "normal"},
              {"id": "sata3", "name": "Drive 3", "model": "ST4000", "size_total": "4000787030016", "status": "normal", "smart_status": "failing"}]}
SHARES = {"shares": [{"name": "docker", "vol_path": "/volume1"}, {"name": "media"}], "total": 2}


def test_storage_part_has_pools_volumes_disks_and_shares():
    server = FakeDSM(storage=STORAGE, shares=SHARES)
    try:
        out = validate_output("hypervisor", plugin.fetch(server.config()))
    finally:
        server.close()
    st = out["storage"]
    pools = {p["name"]: p for p in st["pools"]}
    assert pools["Storage Pool 1"]["health"] == "warning" and pools["Storage Pool 1"]["avail"] == 2000000000000 and pools["Storage Pool 1"]["raid"] == "raid_5"
    volumes = {v["name"]: v for v in st["volumes"]}
    assert volumes["/volume1"]["pool_id"] == "pool:reuse_1" and volumes["/volume1"]["protocol"] == "btrfs" and volumes["/volume2"]["health"] == "critical"
    assert volumes["docker"]["kind"] == "share" and "media" in volumes
    disks = {d["name"]: d for d in st["disks"]}
    assert disks["Drive 1"]["state"] == "ok" and disks["Drive 1"]["model"] == "WDC WD40EFRX" and disks["Drive 2"]["state"] == "failed" and disks["Drive 3"]["state"] == "degraded"
    assert st["systems"][0]["vendor"] == "Synology" and st["systems"][0]["health"] == "critical"
    texts = {a["text"] for a in st["alerts"]}
    assert {"Storage pool Storage Pool 1 is degraded", "Volume /volume2 is crashed", "Disk Drive 2: failed"} <= texts


def test_a_nas_without_storage_answers_reports_no_storage_part():
    server = FakeDSM()
    try:
        assert "storage" not in plugin.fetch(server.config())
    finally:
        server.close()


LUNS = {"luns": [{"name": "netlens-lun", "uuid": "u1", "lun_id": 1, "size": 2147483648, "allocated_size": 1000, "location": "/volume1", "type_str": "BLUN"},
                 {"name": "idle", "uuid": "u2", "lun_id": 2, "size": 5, "location": "/volume9"}]}
TARGETS = {"targets": [{"name": "t1", "iqn": "iqn.x:t1", "mapped_luns": [{"lun_uuid": "u1", "mapping_index": 1}],
                        "connected_sessions": [{"ip": "192.168.0.232", "iqn": "iqn.2026:pc"}, {"ip": "192.168.0.232", "iqn": "iqn.2026:pc"}]},
                       {"name": "t2", "mapped_luns": [{"lun_uuid": "u2"}], "connected_sessions": []}]}


def test_iscsi_luns_with_their_clients():
    server = FakeDSM(storage=STORAGE, shares=SHARES, luns=LUNS, targets=TARGETS)
    try:
        st = validate_output("hypervisor", plugin.fetch(server.config()))["storage"]
    finally:
        server.close()
    luns = {v["name"]: v for v in st["volumes"] if v["kind"] == "lun"}
    assert luns["netlens-lun"]["size"] == 2147483648 and luns["netlens-lun"]["used"] == 1000 and luns["netlens-lun"]["clients"] == ["192.168.0.232"] and luns["netlens-lun"]["protocol"] == "iscsi"
    assert luns["netlens-lun"]["pool_id"] == "pool:reuse_1" and luns["idle"]["clients"] == [] and luns["idle"]["pool_id"] is None
