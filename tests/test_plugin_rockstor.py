"""The Rockstor plugin against a fake Rockstor: a small HTTP server that answers the REST API the way Rockstor's code does
(field names follow the Rockstor source, storageadmin/models and serializers; not recorded from a real NAS)."""

import base64
import importlib.util
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "rockstor"
spec = importlib.util.spec_from_file_location("rockstor_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Basic " + base64.b64encode(b"netlens:good-pass").decode()
ROUTES = {
    "/api/appliances": [{"id": 1, "uuid": "u", "ip": "192.168.0.30", "current_appliance": True, "hostname": "rockstor", "mgmt_port": 443}],
    "/api/network/devices": [{"id": 1, "name": "enp1s0", "dtype": "ethernet", "mac": "AA:BB:CC:01:02:03", "connection": 7, "state": "100 (connected)", "mtu": 1500},
                             {"id": 2, "name": "docker0", "dtype": "bridge", "mac": "02:42:AA:BB:CC:DD", "connection": 8, "state": "100 (connected)", "mtu": 1500}],
    "/api/network/connections": [{"id": 7, "name": "enp1s0", "ipv4_method": "manual", "ipv4_addresses": "192.168.0.30/24"},
                                 {"id": 8, "name": "docker0", "ipv4_method": "manual", "ipv4_addresses": "172.17.0.1/16"}],
    "/api/rockons": [
        {"id": 1, "name": "Plex", "version": "1.0", "state": "installed", "status": "started", "ui": True},
        {"id": 2, "name": "Syncthing", "version": "2.1", "state": "installed", "status": "stopped"},
        {"id": 3, "name": "Nextcloud", "version": "1.0", "state": "available", "status": "stopped"}],
    "/api/rockons/docker/containers/1": [{"id": 11, "rockon": 1, "dimage": 1, "name": "plex", "launch_order": 1}],
    "/api/rockons/ports/1": [{"id": 21, "hostp": 32400, "containerp": 32400, "container": 11, "container_name": "plex", "protocol": "tcp", "uiport": True, "publish": True},
                             {"id": 22, "hostp": 1900, "containerp": 1900, "container": 11, "container_name": "plex", "protocol": "udp", "publish": False}],
    "/api/rockons/docker/containers/2": [{"id": 12, "rockon": 2, "dimage": 2, "name": "syncthing", "launch_order": 1}],
    "/api/rockons/ports/2": [],
}


class FakeRockstor:
    def __init__(self, paged=True, broken=()):
        self.paged, self.broken, self.seen = paged, set(broken), []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                fake.seen.append((url.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != AUTH:
                    code, body = 403, {"detail": "Authentication credentials were not provided."}
                elif url.path in fake.broken:
                    code, body = 500, {}
                elif url.path in ROUTES:
                    rows = ROUTES[url.path]
                    code, body = 200, ({"count": len(rows), "next": None, "previous": None, "results": rows} if fake.paged else rows)
                else:
                    code, body = 404, {}
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

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
def rockstor():
    fake = FakeRockstor()
    yield fake
    fake.close()


def test_manifest_is_valid():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"


def test_fetch_gives_host_and_containers(rockstor):
    out = validate_output("hypervisor", plugin.fetch(rockstor.config()))
    host = out["hosts"][0]
    assert host["name"] == "rockstor" and host["ip"] == "192.168.0.30" and host["mac"] == "aa:bb:cc:01:02:03"
    guests = {g["name"]: g for g in out["guests"]}
    assert set(guests) == {"plex", "syncthing"}                    # Nextcloud is only available, not installed
    assert guests["plex"]["status"] == "running" and guests["syncthing"]["status"] == "stopped"
    assert guests["plex"]["details"]["ports"] == [{"container_port": 32400, "host_port": 32400, "proto": "tcp", "bind": ""}]     # the unpublished port is left out
    assert guests["plex"]["details"]["project"] == "Plex"


def test_an_unpaged_list_works_too():
    fake = FakeRockstor(paged=False)
    try:
        assert len(plugin.fetch(fake.config())["guests"]) == 2
    finally:
        fake.close()


def test_credentials_are_sent_as_basic_auth(rockstor):
    plugin.fetch(rockstor.config())
    assert rockstor.seen and all(auth == AUTH for _, auth in rockstor.seen)


def test_wrong_password_stops_retries(rockstor):
    with pytest.raises(Exception) as err:
        plugin.fetch(rockstor.config("bad"))
    assert getattr(err.value, "auth_failed", False) is True


def test_a_failing_optional_list_is_a_note():
    fake = FakeRockstor(broken={"/api/network/devices"})
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert not out["hosts"][0].get("mac") and len(out["guests"]) == 2
        assert "network cards" in plugin.test(fake.config())["message"]
    finally:
        fake.close()


def test_test_message_counts(rockstor):
    message = plugin.test(rockstor.config())["message"]
    assert "rockstor" in message and "2 installed Rock-on(s)" in message and "2 container(s)" in message


def test_not_rockstor_is_a_connection_problem():
    with pytest.raises(plugin.ConnectError):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 2})


def test_address_forms():
    assert plugin.normalize("192.168.0.30")[0] == "https://192.168.0.30"
    assert plugin.normalize("http://nas.local:8080/")[0] == "http://nas.local:8080"
    with pytest.raises(ValueError):
        plugin.normalize("")


def test_diagnostic_never_contains_names_or_addresses(rockstor):
    report = json.dumps(plugin.diagnose(rockstor.config()))
    for leak in ("plex", "Plex", "syncthing", "rockstor", "192.168", "AA:BB", "127.0.0.1", "good-pass"):
        assert leak not in report, leak
    assert '"ok": true' in report
