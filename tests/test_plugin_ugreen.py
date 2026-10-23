"""The UGREEN plugin against a fake UGOS: a small HTTP server that does the RSA-encrypted login and answers the endpoints the way the community
documentation (gitlab.com/K-22/nas-monitor-interface docs/API.md) describes them. Not recorded from a real NAS."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "ugreen"
spec = importlib.util.spec_from_file_location("ugreen_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SPKI = KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
PKCS1 = KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
MACHINE = {"model": "DH4300 Plus", "hostname": "Nyx", "serial_number": "H43001J56H304889", "firmware_version": "1.13.1.0105",
           "network_interfaces": [{"name": "eth0", "ip": "192.168.0.50", "mac": "AA:BB:CC:11:22:33", "speed": 1000}, {"name": "eth1", "ip": "", "mac": "AA:BB:CC:11:22:34"}]}
CONTAINERS = [{"container_id": "a1", "name": "pihole", "image": "pihole/pihole", "status": "running", "ports": [{"host_port": 8081, "container_port": 80, "protocol": "tcp"}]},
              {"container_id": "b2", "name": "grafana", "image": "grafana/grafana", "status": "exited", "ports": ["0.0.0.0:3000->3000/tcp"]},
              {"container_id": "c3", "name": "bare", "image": "alpine", "status": "running", "ports": []}]


class FakeUgos:
    def __init__(self, legacy=False, lock=False):
        self.legacy, self.lock, self.calls = legacy, lock, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, payload, headers=None, code=200):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")

            def do_POST(self):
                path, body = self.path, self._body()
                fake.calls.append((path, self.headers.get("App-Id")))
                if path.startswith("/ugreen/v1/verify/check"):
                    if fake.legacy:
                        return self._send({"code": 404})
                    return self._send({"code": 200}, {"x-rsa-token": base64.b64encode(SPKI).decode()})
                if path == "/ugreen/v1/verify/login":
                    if fake.lock:
                        return self._send({"code": 1120, "message": "locked"})
                    password = KEY.decrypt(base64.b64decode(body["password"]), padding.PKCS1v15()).decode()
                    if body["username"] != "netlens" or password != "good-pass":
                        return self._send({"code": 1003, "message": "wrong"})
                    return self._send({"code": 200, "data": {"token": "TOKEN1", "expire_time": 86400}})
                self._send({}, code=404)

            def do_GET(self):
                fake.calls.append((self.path, self.headers.get("App-Id")))
                if self.path == "/ugreen/v1/verify/rsa_public_key":
                    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                    return self._send({"code": 200, "data": {"public_key": pem}})
                if self.headers.get("Authorization") != "Bearer TOKEN1" or self.headers.get("App-Id") != "com.ugreen.nas":
                    return self._send({"code": 9404}, code=200)
                if self.path == "/ugreen/v1/sysinfo/machine":
                    return self._send({"code": 200, "data": MACHINE})
                if self.path == "/ugreen/v1/ShowContainerDetailListV2":
                    return self._send({"code": 200, "data": CONTAINERS})
                if self.path == "/ugreen/v1/storage/disks":
                    return self._send({"code": 200, "data": [{"slot": 1, "name": "Hard Drive 1", "model": "WDC WD100", "serial": "S1", "capacity": 9771050598400, "health": "Good"},
                                                              {"slot": 2, "name": "Hard Drive 2", "model": "ST4000", "serial": "S2", "capacity": 4000, "health": "Failed"},
                                                              {"slot": 3, "name": "Hard Drive 3", "serial": "S3", "capacity": 4000, "health": "Warning"}]})
                if self.path == "/ugreen/v1/storage/volumes":
                    return self._send({"code": 200, "data": [{"name": "VOLUME1", "raid_level": "RAID5", "total": 26321794252800, "used": 2555053056000, "status": "healthy"},
                                                              {"name": "VOLUME2", "raid_level": "RAID1", "total": 1000, "used": 10, "status": "degraded"}]})
                self._send({"code": 200, "data": []})

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
def ugos():
    fake = FakeUgos()
    yield fake
    fake.close()


def test_manifest_is_valid():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"


def test_rsa_encryption_round_trips_for_both_key_formats():
    for blob in (SPKI, PKCS1, KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)):
        secret = plugin.rsa_encrypt(blob, "pässword with spaces!")
        assert KEY.decrypt(base64.b64decode(secret), padding.PKCS1v15()).decode() == "pässword with spaces!"


def test_fetch_gives_host_and_containers(ugos):
    out = validate_output("hypervisor", plugin.fetch(ugos.config()))
    host = out["hosts"][0]
    assert host["name"] == "Nyx" and host["ip"] == "192.168.0.50" and host["mac"] == "aa:bb:cc:11:22:33"
    guests = {g["name"]: g for g in out["guests"]}
    assert set(guests) == {"pihole", "grafana", "bare"}
    assert guests["pihole"]["status"] == "running" and guests["grafana"]["status"] == "stopped"
    assert guests["pihole"]["details"]["ports"] == [{"container_port": 80, "host_port": 8081, "proto": "tcp", "bind": ""}]
    assert guests["grafana"]["details"]["ports"] == [{"container_port": 3000, "host_port": 3000, "proto": "tcp", "bind": ""}]


def test_every_request_carries_the_app_id(ugos):
    plugin.fetch(ugos.config())
    assert all(app == "com.ugreen.nas" for path, app in ugos.calls if "rsa_public_key" not in path)


def test_older_firmware_gives_the_key_as_pem():
    fake = FakeUgos(legacy=True)
    try:
        assert len(plugin.fetch(fake.config())["guests"]) == 3
    finally:
        fake.close()


def test_wrong_password_stops_retries(ugos):
    with pytest.raises(Exception) as err:
        plugin.fetch(ugos.config("bad"))
    assert getattr(err.value, "auth_failed", False) is True and "wrong" in str(err.value)


def test_a_locked_account_is_explained():
    fake = FakeUgos(lock=True)
    try:
        with pytest.raises(plugin.LoginRefused) as err:
            plugin.fetch(fake.config())
        assert "locked" in str(err.value)
    finally:
        fake.close()


def test_test_message(ugos):
    message = plugin.test(ugos.config())["message"]
    assert "Nyx" in message and "DH4300 Plus" in message and "UGOS 1.13.1.0105" in message and "3 container(s)" in message


def test_not_a_ugreen_is_a_connection_problem():
    with pytest.raises(plugin.ConnectError):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 2})


def test_address_forms():
    assert plugin.normalize("192.168.0.50")[0] == "https://192.168.0.50:9443"
    assert plugin.normalize("http://nas:9000/")[0] == "http://nas:9000"
    with pytest.raises(ValueError):
        plugin.normalize("")


def test_diagnostic_never_contains_names_or_addresses(ugos):
    report = json.dumps(plugin.diagnose(ugos.config()))
    for leak in ("pihole", "grafana", "Nyx", "H43001", "192.168", "AA:BB", "127.0.0.1", "good-pass"):
        assert leak not in report, leak
    assert '"ok": true' in report


def test_storage_part_has_volumes_and_disks(ugos):
    st = validate_output("hypervisor", plugin.fetch(ugos.config()))["storage"]
    pools = {p["name"]: p for p in st["pools"]}
    assert pools["VOLUME1"]["raid"] == "RAID5" and pools["VOLUME1"]["health"] == "ok" and pools["VOLUME1"]["avail"] == 26321794252800 - 2555053056000
    assert pools["VOLUME2"]["health"] == "warning"
    disks = {d["name"]: d for d in st["disks"]}
    assert disks["Hard Drive 1"]["state"] == "ok" and disks["Hard Drive 2"]["state"] == "failed" and disks["Hard Drive 3"]["state"] == "degraded"
    assert st["systems"][0]["vendor"] == "UGREEN" and st["systems"][0]["health"] == "critical"
