"""The QNAP plugin against a fake QNAP: a small HTTP server that answers Container Station 3's web API and QTS' login/sysinfo
(paths and fields follow the QTS HTTP API Authentication document and the open-source qnap-containerstation-mcp client; not recorded from a real NAS)."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "qnap"
spec = importlib.util.spec_from_file_location("qnap_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

CONTAINERS = [
    {"id": "a1", "name": "nginx", "image": "nginx:latest", "type": "docker", "runtime": "docker", "project": "web", "networkMode": "bridge", "state": "running", "externalIP": "",
     "tcpPort": [{"hostPort": 8080, "containerPort": 80}], "privileged": False},
    {"id": "b2", "name": "unifi", "image": "jacobalberty/unifi", "type": "docker", "state": "exited", "externalIP": "192.168.0.77", "tcpPort": [8443, "8080/tcp"]},
    {"id": "c3", "name": "ubuntu-lxd", "image": "ubuntu", "type": "lxd", "state": "stopped", "tcpPort": []},
]
SYSINFO = "<?xml version='1.0'?><QDocRoot><func><ownContent><root><sysHostName>qnap-kelder</sysHostName><modelName>TS-464</modelName><version>5.2.1</version></root></ownContent></func></QDocRoot>"
LOGIN = "<?xml version='1.0'?><QDocRoot><authPassed><![CDATA[1]]></authPassed><authSid><![CDATA[sid42]]></authSid><isAdmin><![CDATA[1]]></isAdmin></QDocRoot>"


class FakeQnap:
    def __init__(self, qts=True, no_station=False):
        self.qts, self.no_station, self.calls = qts, no_station, []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype="application/json", cookie=None):
                raw = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()

            def do_POST(self):
                body = self._body()
                fake.calls.append(("POST", self.path, body))
                if self.path == "/container-station/api/v1/login":
                    if fake.no_station:
                        return self._send(404, {})
                    creds = json.loads(body)
                    if creds != {"username": "netlens", "password": "good-pass"}:
                        return self._send(401, {"message": "bad"})
                    return self._send(200, {}, cookie="NAS_SID=abc; Path=/")
                if self.path == "/cgi-bin/authLogin.cgi":
                    if not fake.qts:
                        return self._send(404, "")
                    pwd = dict(x.split("=", 1) for x in body.split("&"))["pwd"]
                    ok = base64.b64decode(__import__("urllib.parse").parse.unquote(pwd)).decode() == "good-pass"
                    return self._send(200, LOGIN if ok else LOGIN.replace("[CDATA[1]]><", "[CDATA[0]]><", 1), "text/xml")
                self._send(404, {})

            def do_PUT(self):
                fake.calls.append(("PUT", self.path, ""))
                self._send(200, {})

            def do_GET(self):
                fake.calls.append(("GET", self.path, ""))
                if self.path.startswith("/container-station/api/v1/"):
                    if "NAS_SID=abc" not in (self.headers.get("Cookie") or ""):
                        return self._send(401, {})
                    if self.path.endswith("/container"):
                        return self._send(200, CONTAINERS)
                    return self._send(200, {} if self.path.endswith("/apps") else [])
                if self.path.startswith("/cgi-bin/management/manaRequest.cgi") and "sid=sid42" in self.path:
                    return self._send(200, SYSINFO, "text/xml")
                self._send(200, "")

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
def qnap():
    fake = FakeQnap()
    yield fake
    fake.close()


def test_manifest_is_valid():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"


def test_fetch_gives_host_and_containers(qnap):
    out = validate_output("hypervisor", plugin.fetch(qnap.config()))
    host = out["hosts"][0]
    assert host["name"] == "qnap-kelder"
    guests = {g["name"]: g for g in out["guests"]}
    assert set(guests) == {"nginx", "unifi", "ubuntu-lxd"}
    assert guests["nginx"]["status"] == "running" and guests["nginx"]["kind"] == "container"
    assert guests["nginx"]["details"]["ports"] == [{"container_port": 80, "host_port": 8080, "proto": "tcp", "bind": ""}]
    assert guests["nginx"]["details"]["project"] == "web"
    assert guests["unifi"]["status"] == "stopped" and guests["unifi"]["ips"] == ["192.168.0.77"]
    assert [p["host_port"] for p in guests["unifi"]["details"]["ports"]] == [8443, 8080]
    assert guests["ubuntu-lxd"]["kind"] == "lxc" and guests["ubuntu-lxd"]["id"] == "lxd:ubuntu-lxd"


def test_the_password_is_not_in_a_url_and_the_session_is_closed(qnap):
    plugin.fetch(qnap.config())
    assert all("good-pass" not in path for _, path, _ in qnap.calls)
    assert ("PUT", "/container-station/api/v1/logout", "") in qnap.calls


def test_wrong_password_stops_retries(qnap):
    with pytest.raises(Exception) as err:
        plugin.fetch(qnap.config("bad"))
    assert getattr(err.value, "auth_failed", False) is True


def test_qts_part_is_optional():
    fake = FakeQnap(qts=False)
    try:
        out = validate_output("hypervisor", plugin.fetch(fake.config()))
        assert len(out["guests"]) == 3 and out["hosts"][0]["name"] == "127.0.0.1"
        assert "system information" in plugin.test(fake.config())["message"]
    finally:
        fake.close()


def test_without_container_station_it_says_so():
    fake = FakeQnap(no_station=True)
    try:
        with pytest.raises(plugin.ConnectError) as err:
            plugin.fetch(fake.config())
        assert "Container Station" in str(err.value)
    finally:
        fake.close()


def test_test_message(qnap):
    message = plugin.test(qnap.config())["message"]
    assert "qnap-kelder" in message and "TS-464" in message and "3 container(s)" in message


def test_not_a_qnap_is_a_connection_problem():
    with pytest.raises(plugin.ConnectError):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 2})


def test_address_forms():
    assert plugin.normalize("192.168.0.40")[0] == "https://192.168.0.40"
    assert plugin.normalize("http://nas:8080/")[0] == "http://nas:8080"
    with pytest.raises(ValueError):
        plugin.normalize("")


def test_diagnostic_never_contains_names_or_addresses(qnap):
    report = json.dumps(plugin.diagnose(qnap.config()))
    for leak in ("nginx", "unifi", "qnap-kelder", "TS-464", "192.168", "127.0.0.1", "good-pass"):
        assert leak not in report, leak
    assert '"ok": true' in report
