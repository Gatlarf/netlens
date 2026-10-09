"""The UniFi plugin against fake controllers: a UniFi OS console (/api/auth/login, /proxy/network prefix, CSRF header)
and a classic controller (/api/login, no prefix). Answers use the {"meta": {"rc"}, "data": [...]} envelope."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "unifi"
spec = importlib.util.spec_from_file_location("unifi_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

GW, SW, AP1, AP2, AP3 = ("aa:bb:cc:00:00:0%d" % i for i in range(1, 6))
DEVICES = [
    {"mac": GW, "type": "udm", "model": "UDMPRO", "name": "Dream Machine", "ip": "192.168.1.1", "adopted": True},
    {"mac": SW, "type": "usw", "model": "US8P150", "name": "Office switch", "ip": "192.168.1.2", "adopted": True, "uplink": {"type": "wire", "uplink_mac": GW.upper(), "port_idx": 2}},
    {"mac": AP1, "type": "uap", "model": "U6LR", "name": "Hall AP", "ip": "192.168.1.3", "adopted": True, "uplink": {"type": "wire", "uplink_mac": SW}},
    {"mac": AP2, "type": "uap", "model": "U6LITE", "ip": "192.168.1.4", "adopted": True, "uplink": {"type": "wireless", "uplink_mac": AP1}},  # a meshed AP, no name
    {"mac": AP3, "type": "uap", "model": "U6PRO", "name": "Not adopted", "adopted": False},
    {"mac": "aa:bb:cc:00:00:09", "type": "uap", "model": "X", "name": "Orphan", "adopted": True, "uplink": {"uplink_mac": "ff:ff:ff:00:00:99"}},
]
CLIENTS = [
    {"mac": "11:22:33:44:55:01", "name": "Anna's phone", "hostname": "annas-iphone", "ip": "192.168.1.50", "is_wired": False, "ap_mac": AP1, "radio": "na", "signal": -48, "tx_rate": 866700, "rx_rate": 600000},
    {"mac": "11:22:33:44:55:02", "hostname": "printer", "last_ip": "192.168.1.51", "is_wired": True, "sw_mac": SW, "sw_port": 4},
    {"mac": "11:22:33:44:55:03", "hostname": "sensor", "ip": "192.168.1.52", "is_wired": False, "ap_mac": AP2, "radio": "ng", "signal": -80, "tx_rate": 72000, "rx_rate": 0},
    {"mac": "11:22:33:44:55:04", "name": "nas", "ip": "192.168.1.60", "is_wired": True, "uplink_mac": GW},  # on the gateway itself
    {"mac": "11:22:33:44:55:05", "name": "6 GHz laptop", "ip": "192.168.1.61", "is_wired": False, "ap_mac": AP1, "radio": "6e", "signal": 5},
]


class Fake(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _ok(self, data):
        self._send({"meta": {"rc": "ok"}, "data": data})

    def do_POST(self):
        s = self.state
        s["calls"].append(("POST", self.path))
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        good = body.get("username") == "viewer" and body.get("password") == "secret"
        if self.path == "/api/auth/login" and s["os"]:
            s["logins"] += 1
            if s["mfa"]:
                return self._send({"code": "MFA_AUTH_REQUIRED"}, 499)
            if s["ratelimit"]:
                return self._send({}, 429)
            if not good:
                return self._send({"code": "AUTHENTICATION_FAILED_INVALID_CREDENTIALS", "message": "Invalid username or password"}, 401)
            return self._send({"unique_id": "x"}, 200, {"Set-Cookie": "TOKEN=jwt; Path=/", "X-CSRF-Token": "CSRF1"})
        if self.path == "/api/login" and not s["os"]:
            s["logins"] += 1
            if not good:
                return self._send({"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []}, 400)
            return self._send({"meta": {"rc": "ok"}, "data": []}, 200, {"Set-Cookie": "unifises=abc; Path=/"})
        if self.path in ("/api/auth/logout", "/api/logout"):
            if s["os"] and self.headers.get("X-CSRF-Token") != "CSRF1":
                return self._send({}, 403)
            s["logouts"] += 1
            return self._send({})
        self._send({"error": "not found"}, 404)

    def do_GET(self):
        s = self.state
        s["calls"].append(("GET", self.path))
        prefix = "/proxy/network" if s["os"] else ""
        cookie = self.headers.get("Cookie") or ""
        if ("TOKEN=jwt" if s["os"] else "unifises=abc") not in cookie:
            return self._send({"meta": {"rc": "error", "msg": "api.err.LoginRequired"}, "data": []}, 401)
        if not self.path.startswith(prefix + "/api/"):
            return self._send({"error": "wrong prefix"}, 404)
        path = self.path[len(prefix):]
        if path == "/api/self/sites":
            return self._ok(s["sites"])
        if path == "/api/s/default/stat/device":
            return self._ok(DEVICES)
        if path == "/api/s/default/stat/sta":
            return self._ok(CLIENTS)
        if path in ("/api/s/branch/stat/device", "/api/s/branch/stat/sta"):
            return self._ok([])
        self._send({"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}, "data": []}, 400)


def start(os_console, **extra):
    Fake.state = {"os": os_console, "mfa": False, "ratelimit": False, "calls": [], "logins": 0, "logouts": 0,
                  "sites": [{"name": "default", "desc": "Default"}, {"name": "branch", "desc": "Branch office"}], **extra}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}"


@pytest.fixture(params=["os", "classic"])
def server(request):
    httpd, url = start(request.param == "os")
    yield url, Fake.state
    httpd.shutdown()


def cfg(url="http://127.0.0.1:9", **kw):
    return {"url": url, "username": "viewer", "password": "secret", "mode": "auto", "site": "default", "verify_tls": False, **kw}


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["id"] == "unifi" and [o["value"] for o in manifest["config"][1]["options"]] == ["auto", "unifi_os", "classic"]


def test_fetch_follows_the_contract_on_both_kinds_of_controller(server):
    url, state = server
    out = validate_output("topology", plugin.fetch(cfg(url)))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["Dream Machine"]["role"] == "gateway" and nodes["Dream Machine"]["parent_mac"] is None
    assert nodes["Office switch"]["role"] == "switch" and nodes["Office switch"]["parent_mac"] == GW  # an upper-case uplink MAC is normalised
    assert nodes["Hall AP"]["role"] == "ap" and nodes["Hall AP"]["parent_mac"] == SW
    assert nodes["U6LITE"]["parent_mac"] == AP1 and nodes["U6LITE"]["model"] == "U6LITE"  # an unnamed device is called by its model; a meshed AP hangs below its AP
    assert "Not adopted" not in nodes and nodes["Orphan"]["parent_mac"] is None  # unknown uplink: below the gateway
    clients = {c["mac"]: c for c in out["clients"]}
    assert len(clients) == 5
    anna = clients["11:22:33:44:55:01"]
    assert anna["name"] == "Anna's phone" and anna["medium"] == "wifi" and anna["node_mac"] == AP1 and anna["band"] == "5 GHz"
    assert anna["rssi"] == -48 and anna["tx_mbps"] == 866.7 and anna["rx_mbps"] == 600.0
    printer = clients["11:22:33:44:55:02"]
    assert printer["name"] == "printer" and printer["ip"] == "192.168.1.51" and printer["medium"] == "wired" and printer["node_mac"] == SW and printer["tx_mbps"] is None
    sensor = clients["11:22:33:44:55:03"]
    assert sensor["band"] == "2.4 GHz" and sensor["node_mac"] == AP2 and sensor["rx_mbps"] is None  # a rate of 0 is no rate
    assert clients["11:22:33:44:55:04"]["node_mac"] == GW
    assert clients["11:22:33:44:55:05"]["band"] == "6 GHz" and clients["11:22:33:44:55:05"]["rssi"] is None  # a positive "signal" is not dBm


def test_auto_detection_and_one_login_one_logout(server):
    url, state = server
    plugin.fetch(cfg(url))
    assert state["logins"] == 1 and state["logouts"] == 1
    assert (("GET", "/proxy/network/api/s/default/stat/device") in state["calls"]) == state["os"]
    assert (("GET", "/api/s/default/stat/device") in state["calls"]) == (not state["os"])


def test_a_wrong_choice_of_type_fails_clearly():
    httpd, url = start(os_console=True)
    try:
        with pytest.raises(plugin.UnifiError, match="does not look like a UniFi controller"):
            plugin.fetch(cfg(url, mode="classic"))
    finally:
        httpd.shutdown()


def test_site_selection_by_name_or_description_and_all():
    httpd, url = start(os_console=False)
    try:
        assert len(plugin.fetch(cfg(url, site="Default"))["nodes"]) == 5
        assert len(plugin.fetch(cfg(url, site="branch office"))["nodes"]) == 0
        assert len(plugin.fetch(cfg(url, site=""))["nodes"]) == 5  # all sites, nothing duplicated
        with pytest.raises(plugin.UnifiError, match="no site named"):
            plugin.fetch(cfg(url, site="nowhere"))
    finally:
        httpd.shutdown()


def test_wrong_password_is_auth_failed_and_tried_once(server):
    url, state = server
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(cfg(url, password="wrong"))
    assert err.value.auth_failed is True and "local one" in str(err.value) and state["logins"] == 1


def test_two_factor_account_is_explained():
    httpd, url = start(os_console=True, mfa=True)
    try:
        with pytest.raises(plugin.LoginRefused, match="two-factor"):
            plugin.fetch(cfg(url))
    finally:
        httpd.shutdown()


def test_rate_limit_is_not_a_refused_login():
    httpd, url = start(os_console=True, ratelimit=True)
    try:
        with pytest.raises(plugin.UnifiError) as err:
            plugin.fetch(cfg(url))
        assert not getattr(err.value, "auth_failed", False) and "too many" in str(err.value)
    finally:
        httpd.shutdown()


def test_unreachable_controller_is_not_a_refused_login():
    with pytest.raises(plugin.UnifiError) as err:
        plugin.fetch(cfg("http://127.0.0.1:9"))
    assert not getattr(err.value, "auth_failed", False) and "cannot reach" in str(err.value)


def test_an_expired_session_is_an_error(server):
    url, _ = server
    controller = plugin.Controller(cfg(url))
    controller.login()
    controller.jar.clear()
    with pytest.raises(plugin.UnifiError, match="ended the session"):
        controller.sites()


def test_test_message():
    httpd, url = start(os_console=True)
    try:
        assert plugin.test(cfg(url))["message"] == "Connected to UniFi (UniFi OS console): 1 site(s), 5 device(s), 5 client(s)"
    finally:
        httpd.shutdown()


@pytest.mark.parametrize("bad", [{"url": ""}, {"username": ""}, {"password": ""}, {"mode": "weird"}, {"url": "http://"}])
def test_missing_settings_are_clear_value_errors(bad):
    with pytest.raises(ValueError):
        plugin.fetch(cfg(**bad))


def test_helpers():
    assert plugin._mac("AA:BB:CC:00:00:01") == "aa:bb:cc:00:00:01" and plugin._mac("nope") is None
    assert plugin._rate_mbps(866700) == 866.7 and plugin._rate_mbps(0) is None and plugin._rate_mbps(None) is None


def test_diagnose_writes_an_anonymised_report(tmp_path, monkeypatch):
    httpd, url = start(os_console=True)
    try:
        dspec = importlib.util.spec_from_file_location("unifi_diagnose", ROOT / "diagnose.py")
        diag = importlib.util.module_from_spec(dspec)
        dspec.loader.exec_module(diag)
        out = tmp_path / "d.json"
        monkeypatch.setattr(diag.getpass, "getpass", lambda prompt="": "secret")
        monkeypatch.setattr("sys.argv", ["diagnose.py", "--url", url, "--username", "viewer", "--site", "default", "--out", str(out)])
        diag.main()
        text = out.read_text()
        report = json.loads(text)
        for private in ("annas-iphone", "Anna", "192.168.1", "aa:bb:cc", "11:22:33", "secret", "127.0.0.1", "Dream Machine", "Hall AP"):
            assert private not in text, private
        assert report["controller_kind"] == "unifi_os" and report["steps"]["devices"]["shape"]["count"] == 6
        assert report["steps"]["clients"]["ok"] and report["result"]["nodes"] == 5 and report["result"]["clients"] == 5
        assert report["steps"]["devices"]["shape"]["first"][0]["mac"] == "<mac colons>"
    finally:
        httpd.shutdown()
