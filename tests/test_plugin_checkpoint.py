"""The Check Point plugin against a simulated management server. The answers follow the Management API as documented; no real server has answered yet."""

import importlib.util
import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "checkpoint"
spec = importlib.util.spec_from_file_location("checkpoint_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

OBJECTS = [
    {"name": "gw-hq", "type": "CpmiGatewayCluster", "ipv4-address": "10.0.0.10", "version": "R81.20", "hardware": "Open server", "operating-system": "Gaia", "sic-state": "communicating"},
    {"name": "gw-hq-a", "type": "CpmiClusterMember", "ipv4-address": "10.0.0.11", "version": "R81.20", "hardware": "Open server", "operating-system": "Gaia", "sic-state": "communicating"},
    {"name": "gw-branch", "type": "simple-gateway", "ipv4-address": "10.1.0.1", "version": {"name": "R80.40"}, "hardware": "Check Point 3100", "operating-system": "Gaia", "sic-state": "uninitialized"},
    {"name": "mgmt", "type": "CpmiHostCkp", "ipv4-address": "10.0.0.5", "version": "R81.20"},
    {"name": "no-address", "type": "simple-gateway"},
]


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("cert")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"), "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return d / "c.pem", d / "k.pem"


class Fake:
    def __init__(self, cert, objects=None, key="apikey"):
        self.objects, self.key, self.calls, self.logged_out = objects or OBJECTS, key, [], False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                command = self.path.rsplit("/", 1)[-1]
                outer.calls.append((command, body, self.headers.get("X-chkp-sid")))
                if command == "login":
                    if body.get("api-key") == outer.key or (body.get("user") == "u" and body.get("password") == "p"):
                        return self._send(200, {"sid": "SID1", "api-server-version": "1.9"})
                    return self._send(400, {"code": "err_login_failed", "message": "Authentication to server failed."})
                if self.headers.get("X-chkp-sid") != "SID1":
                    return self._send(401, {"code": "generic_err_wrong_session", "message": "wrong session"})
                if command == "logout":
                    outer.logged_out = True
                    return self._send(200, {"message": "OK"})
                if command == "show-gateways-and-servers":
                    page = outer.objects[body["offset"]: body["offset"] + body["limit"]]
                    return self._send(200, {"objects": page, "from": body["offset"] + 1, "to": body["offset"] + len(page), "total": len(outer.objects)})
                self._send(404, {"message": "no such command"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert[0]), str(cert[1]))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake(cert):
    f = Fake(cert)
    yield f
    f.close()


def cfg(f, **row):
    return {"servers": [{"host": f.url, "api_key": "apikey", **row}], "verify_tls": False, "timeout": 5}


def test_the_manifest_is_valid():
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))


def test_fetch_gives_nodes_with_firmware_and_no_clients(fake):
    out = validate_output("topology", plugin.fetch(cfg(fake)))
    assert out["clients"] == [] and [n["name"] for n in out["nodes"]] == ["gw-hq", "gw-hq-a", "gw-branch", "mgmt"]       # an object without an address is left out
    by_name = {n["name"]: n for n in out["nodes"]}
    assert by_name["gw-hq"]["model"] == "Open server Gaia" and by_name["gw-hq"]["firewall"] == {"version": "R81.20", "model": "cluster", "ha": None, "tunnels": [], "licences": [], "serial": None}
    assert by_name["gw-branch"]["firewall"]["version"] == "R80.40"                 # a version given as an object {"name": ...}
    assert all(n["mac"].startswith("02:00:") for n in out["nodes"])                # no MAC known: a placeholder, matched by IP


def test_it_logs_in_read_only_and_logs_out_again(fake):
    plugin.fetch(cfg(fake))
    commands = [c for c, _, _ in fake.calls]
    assert commands == ["login", "show-gateways-and-servers", "logout"] and fake.logged_out
    assert fake.calls[0][1] == {"read-only": True, "api-key": "apikey"}
    assert fake.calls[1][2] == "SID1"


def test_user_name_and_password_work_too_and_a_domain_is_passed_on(fake):
    plugin.fetch({"servers": [{"host": fake.url, "username": "u", "password": "p", "domain": "Customer1"}], "verify_tls": False})
    assert fake.calls[0][1] == {"read-only": True, "user": "u", "password": "p", "domain": "Customer1"}


def test_a_wrong_key_stops_retries(fake):
    with pytest.raises(plugin.AuthRefused) as err:
        plugin.fetch(cfg(fake, api_key="nope"))
    assert err.value.auth_failed


def test_the_list_is_read_page_by_page(cert):
    many = [{"name": f"gw{i}", "type": "simple-gateway", "ipv4-address": f"10.5.{i // 250}.{i % 250 + 1}"} for i in range(230)]
    f = Fake(cert, many)
    try:
        assert len(plugin.fetch(cfg(f))["nodes"]) == 230
        assert sum(1 for c, _, _ in f.calls if c == "show-gateways-and-servers") == 3
    finally:
        f.close()


def test_a_certificate_that_is_not_trusted_is_explained(fake):
    with pytest.raises(plugin.CheckpointError) as err:
        plugin.fetch({"servers": [{"host": fake.url, "api_key": "apikey"}], "verify_tls": True, "timeout": 5})
    assert "certificate is not trusted" in str(err.value)


def test_test_and_diagnose(fake):
    message = plugin.test(cfg(fake))["message"]
    assert "4 gateway(s)" in message and "gw-branch: uninitialized" in message
    report = plugin.diagnose(cfg(fake))
    step = report["servers"][0]["steps"]["gateways_and_servers"]
    assert step["count"] == 5 and step["with_address"] == 4 and "CpmiGatewayCluster" in step["types"]
    assert "127.0.0.1" not in json.dumps(report) and "gw-hq" not in json.dumps(report)
    assert plugin.diagnose({"servers": []})["error"]
