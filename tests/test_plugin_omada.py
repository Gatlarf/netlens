"""The Omada plugin against a fake controller that behaves like the real web API (login with CSRF token and cookie,
errors as HTTP 200 with an errorCode, a login page when the session is lost, paged client list)."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app.plugins.contract import ContractError, validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "omada"
spec = importlib.util.spec_from_file_location("omada_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

GW, SW, AP1, AP2 = "AA-BB-CC-00-00-01", "AA-BB-CC-00-00-02", "AA-BB-CC-00-00-03", "AA-BB-CC-00-00-04"
DEVICES = [
    {"type": "gateway", "mac": GW, "name": "ER605", "ip": "192.168.0.1", "model": "ER605", "showModel": "ER605 v2", "cpuUtil": 7, "memUtil": 41, "uptimeLong": 3600, "firmwareVersion": "2.1.3", "needUpgrade": True},
    {"type": "switch", "mac": SW, "name": "Rack switch", "ip": "192.168.0.2", "model": "TL-SG2008P", "cpuUtil": 12, "memUtil": 55, "uptime": "1day(s) 2h 3m 4s", "firmwareVersion": "1.0.4", "needUpgrade": False},
    {"type": "ap", "mac": AP1, "name": "Living room", "ip": "192.168.0.3", "model": "EAP653"},
    {"type": "ap", "mac": AP2, "name": "Garden", "ip": "192.168.0.4", "model": "EAP225"},
]
CLIENTS = [
    {"mac": "11-22-33-44-55-01", "name": "11-22-33-44-55-01", "hostName": "laptop", "ip": "192.168.0.50", "wireless": True, "active": True,
     "apMac": AP1, "radioId": 1, "rssi": -52, "signalLevel": 80, "txRate": 866700, "rxRate": 780000},
    {"mac": "11-22-33-44-55-02", "name": "printer", "ip": "192.168.0.51", "wireless": False, "active": True, "switchMac": SW, "port": 3},
    {"mac": "11-22-33-44-55-03", "name": "phone", "hostName": "", "ip": "192.168.0.52", "wireless": True, "active": True,
     "apMac": AP2, "radioId": 0, "rssi": -71, "txRate": 144, "rxRate": 72},
    {"mac": "11-22-33-44-55-04", "name": "old tablet", "wireless": True, "active": False, "apMac": AP1},
    {"mac": "11-22-33-44-55-05", "name": "nas", "ip": "192.168.0.60", "wireless": False, "active": True, "switchMac": "FF-FF-FF-00-00-99"},
]


class Fake(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, headers=None, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self):
        s = self.state
        return "TPOMADA_SESSIONID=s1" in (self.headers.get("Cookie") or "") and self.headers.get("Csrf-Token") == "CSRF1"

    def do_POST(self):
        s = self.state
        s["calls"].append(("POST", self.path))
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if self.path == "/ctl1/api/v2/login":
            s["logins"] += 1
            if body == {"username": "viewer", "password": "secret"}:
                return self._send({"errorCode": 0, "msg": "Log in successfully.", "result": {"token": "CSRF1"}}, headers={"Set-Cookie": "TPOMADA_SESSIONID=s1; Path=/"})
            return self._send({"errorCode": -30109, "msg": "Incorrect username or password."})
        if self.path.startswith("/openapi/authorize/token"):
            s["token_calls"].append((self.path, body))
            if parse_qs(urlsplit(self.path).query).get("grant_type") == ["client_credentials"] and body == {"omadacId": "ctl1", "client_id": "cid", "client_secret": "csecret"}:
                return self._send({"errorCode": 0, "msg": "Success.", "result": {"accessToken": "AT1", "tokenType": "bearer", "expiresIn": 7200, "refreshToken": "RT1"}})
            return self._send({"errorCode": -44106, "msg": "The client id or secret is wrong."})
        if self.path == "/ctl1/api/v2/logout":
            s["logouts"] += 1
            return self._send({"errorCode": 0})
        self._send(b"nope", 404, ctype="text/plain")

    def do_GET(self):
        s = self.state
        url = urlsplit(self.path)
        s["calls"].append(("GET", url.path))
        if url.path == "/api/info":
            return self._send({"errorCode": 0, "result": {"controllerVer": s["version"], "omadacId": "ctl1", "apiVer": "3"}})
        if url.path.endswith("/stat/dpi/category/categoryCards") and s.get("dpi"):
            q = parse_qs(url.query)
            s["dpi_calls"] = s.get("dpi_calls", []) + [(url.path, int(q["start"][0]), int(q["end"][0]), q.get("selectAll"))]
            return self._send({"errorCode": 0, "result": {"categoryCards": s["dpi"]}})
        if url.path.startswith("/openapi/v1/ctl1/"):
            if self.headers.get("Authorization") != "AccessToken=AT1":
                return self._send({"errorCode": -44112, "msg": "The access token has expired or is invalid."})
            q = parse_qs(url.query)
            if url.path == "/openapi/v1/ctl1/sites":
                return self._send({"errorCode": 0, "result": {"data": [{"siteId": "site1", "name": "Home"}, {"siteId": "site2", "name": "Office"}], "totalRows": 2}})
            if url.path == "/openapi/v1/ctl1/sites/site1/applicationControl/applications":
                return self._send({"errorCode": 0, "result": {"data": [{"applicationId": 1, "applicationName": "YouTube"}], "totalRows": 120, "currentPage": 1}})
            prefix = "/openapi/v1/ctl1/sites/site1/dashboard/specificClientInfo/"
            if url.path.startswith(prefix):
                mac = url.path[len(prefix):]
                s["app_calls"].append((mac, int(q["start"][0]), int(q["end"][0])))
                if s.get("need_colons") and ":" not in mac:
                    return self._send({"errorCode": 0, "result": []})            # a MAC written the wrong way finds nothing, without an error
                mac = mac.replace(":", "-")
                if mac == "11-22-33-44-55-03":
                    return self._send({"errorCode": -1, "msg": "General error."})     # one client that fails must not matter
                return self._send({"errorCode": 0, "result": s["apps"].get(mac, [])})
            return self._send({"errorCode": -1, "msg": "unknown " + url.path})
        if not self._authed():
            return self._send(b"<html>login page</html>", ctype="text/html")  # what a lost session looks like
        p = url.path.removeprefix("/ctl1/api/v2/")
        q = parse_qs(url.query)
        if p == "users/current":
            return self._send({"errorCode": 0, "result": {"privilege": {"sites": s["sites"]}}})
        if p == "sites/site1/devices":
            return self._send({"errorCode": 0, "result": DEVICES})
        if p == f"sites/site1/switches/{SW}":
            return self._send({"errorCode": 0, "result": {"mac": SW, "uplink": {"mac": GW, "port": 1, "type": "gateway"}, "ports": [
                {"port": 1, "name": "Port1", "disable": False, "portStatus": {"linkStatus": 1, "linkSpeed": 3, "duplex": 2, "poe": False, "tx": 5000, "rx": 9000}},
                {"port": 3, "name": "printer", "disable": False, "portStatus": {"linkStatus": 1, "linkSpeed": 2, "duplex": 1, "poe": True, "poePower": 4.5, "tx": 10, "rx": 20}},
                {"port": 4, "name": "Port4", "disable": False, "portStatus": {"linkStatus": 0, "linkSpeed": 0, "duplex": 0, "tx": 0, "rx": 0}},
                {"port": 5, "name": "off", "disable": True, "portStatus": {"linkStatus": 0}},
                {"name": "no number"}]}})
        if p == f"sites/site1/gateways/{GW}":
            return self._send({"errorCode": 0, "result": {"mac": GW, "showModel": "ER605 v2", "firmwareVersion": "2.3.1", "dpiEnable": True, "dpiSetting": {"loggingTraffic": False, "name": "secret-name"},
                                                           "devCap": {"supportDpi": True, "maxClients": 300}, "wan": {"ip": "203.0.113.9"}}})
        if p == f"sites/site1/eaps/{AP1}":
            return self._send({"errorCode": 0, "result": {"mac": AP1, "wiredUplink": {"uplinkMac": SW, "port": 5}}})
        if p == f"sites/site1/eaps/{AP2}":
            return self._send({"errorCode": -1, "msg": "not available"})  # a failing detail must not break the sync
        if p == "sites/site1/clients":
            need, got = s.get("clients_need"), q.get("filters.active", [None])[0]
            s.setdefault("client_attempts", []).append(got)
            if need == "never" or (need == "none" and got is not None) or (need in ("false", "true") and got != need):
                return self._send({"errorCode": -1, "msg": "General error."})  # what some controllers answer to a request they do not like
            size, page = int(q["currentPageSize"][0]), int(q["currentPage"][0])
            s["pages"].append(page)
            rows = CLIENTS[(page - 1) * size: page * size]
            return self._send({"errorCode": 0, "result": {"data": rows, "totalRows": len(CLIENTS), "currentPage": page, "currentSize": len(rows)}})
        if p.startswith("sites/site2/"):
            return self._send({"errorCode": 0, "result": [] if p.endswith("devices") else {"data": [], "totalRows": 0}})
        self._send({"errorCode": -1, "msg": "unknown " + p}, 200)


@pytest.fixture
def server():
    Fake.state = {"version": "5.14.26.1", "sites": [{"name": "Home", "key": "site1"}, {"name": "Office", "key": "site2"}], "calls": [], "logins": 0, "logouts": 0, "pages": [], "token_calls": [], "app_calls": [],
                  "apps": {"11-22-33-44-55-01": [{"applicationId": 1, "applicationName": "YouTube", "upload": 100, "download": 5000, "traffic": 5100},
                                                 {"applicationId": 2, "applicationName": "DNS", "upload": 0, "download": 0}],
                           "11-22-33-44-55-02": [{"applicationId": 1, "applicationName": "YouTube", "upload": 10, "download": 500},
                                                 {"applicationId": 3, "applicationName": "Printing", "upload": 7, "download": 1}]}}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", Fake.state
    httpd.shutdown()


def cfg(url="http://127.0.0.1:9", **kw):
    return {"url": url, "username": "viewer", "password": "secret", "site": "Home", "verify_tls": False, **kw}


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["id"] == "omada" and manifest["kind"] == "topology"


def test_fetch_follows_the_contract_and_maps_everything(server):
    url, state = server
    out = validate_output("topology", plugin.fetch(cfg(url)))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["ER605"]["role"] == "gateway" and nodes["ER605"]["parent_mac"] is None and nodes["ER605"]["model"] == "ER605 v2"
    assert nodes["Rack switch"]["role"] == "switch" and nodes["Rack switch"]["parent_mac"] == "aa:bb:cc:00:00:01"
    assert nodes["Living room"]["role"] == "ap" and nodes["Living room"]["parent_mac"] == "aa:bb:cc:00:00:02"  # wiredUplink / uplinkMac
    assert nodes["Garden"]["parent_mac"] is None  # its detail failed: unknown, hangs below the gateway
    clients = {c["mac"]: c for c in out["clients"]}
    assert len(clients) == 4  # the inactive client is left out
    laptop = clients["11:22:33:44:55:01"]
    assert laptop["name"] == "laptop" and laptop["medium"] == "wifi" and laptop["node_mac"] == "aa:bb:cc:00:00:03"
    assert laptop["band"] == "5 GHz" and laptop["rssi"] == -52 and laptop["tx_mbps"] == 866.7 and laptop["rx_mbps"] == 780.0
    printer = clients["11:22:33:44:55:02"]
    assert printer["medium"] == "wired" and printer["node_mac"] == "aa:bb:cc:00:00:02" and printer["band"] is None and printer["tx_mbps"] is None
    phone = clients["11:22:33:44:55:03"]
    assert phone["name"] == "phone" and phone["band"] == "2.4 GHz" and phone["tx_mbps"] == 144.0  # small values are already Mbps
    assert clients["11:22:33:44:55:05"]["node_mac"] is None  # a switch that is not in the device list
    assert printer["port"] == "3" and laptop["port"] is None and clients["11:22:33:44:55:05"]["port"] is None   # only a wired client on a known switch has a port
    ports = {p["port"]: p for p in nodes["Rack switch"]["ports"]}
    assert sorted(ports) == [1, 3, 4, 5]
    assert ports[1] == {**ports[1], "up": True, "enabled": True, "speed_mbps": 1000.0, "duplex": "full", "name": None, "tx_bytes": 5000, "rx_bytes": 9000}
    assert ports[3]["name"] == "printer" and ports[3]["speed_mbps"] == 100.0 and ports[3]["duplex"] == "half"
    assert ports[4]["up"] is False and ports[4]["speed_mbps"] is None and ports[5]["enabled"] is False
    assert not nodes["ER605"]["ports"] and not nodes["Living room"]["ports"]


def test_one_login_one_logout_and_paging(server, monkeypatch):
    url, state = server
    monkeypatch.setattr(plugin, "PAGE_SIZE", 2)
    plugin.fetch(cfg(url))
    assert state["logins"] == 1 and state["logouts"] == 1
    assert state["pages"] == [1, 2, 3]


def test_all_sites_when_none_is_named(server):
    url, state = server
    out = plugin.fetch(cfg(url, site=""))
    assert len(out["nodes"]) == 4 and any(c[1] == "/ctl1/api/v2/sites/site2/devices" for c in state["calls"])


def test_unknown_site(server):
    url, _ = server
    with pytest.raises(plugin.OmadaError, match="no site named"):
        plugin.fetch(cfg(url, site="Nowhere"))


def test_wrong_password_is_auth_failed_and_logs_in_once(server):
    url, state = server
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(cfg(url, password="wrong"))
    assert err.value.auth_failed is True and "username and password" in str(err.value) and state["logins"] == 1


def test_unreachable_controller_is_not_a_refused_login():
    with pytest.raises(plugin.OmadaError) as err:
        plugin.fetch(cfg("http://127.0.0.1:9"))
    assert not getattr(err.value, "auth_failed", False) and "cannot reach" in str(err.value)


def test_old_controller_is_refused_with_a_clear_message(server):
    url, state = server
    state["version"] = "4.4.8"
    with pytest.raises(plugin.OmadaError, match="too old"):
        plugin.fetch(cfg(url))
    assert state["logins"] == 0


def test_lost_session_is_an_error_not_empty_data(server):
    url, state = server
    controller = plugin.Controller(cfg(url))
    controller.login()
    controller.csrf = "stale"
    with pytest.raises(plugin.OmadaError, match="did not answer with data"):
        controller.sites()


def test_test_message(server):
    url, _ = server
    assert plugin.test(cfg(url))["message"].startswith("Connected to Omada controller 5.14.26.1: 1 site(s), 4 device(s), 4 client(s)")


@pytest.mark.parametrize("bad", [{"url": ""}, {"username": ""}, {"password": ""}, {"url": "http://"}])
def test_missing_settings_are_clear_value_errors(bad):
    with pytest.raises(ValueError):
        plugin.fetch(cfg(**bad))


def test_url_without_scheme_gets_https():
    assert plugin.Controller(cfg("192.168.0.10:8043")).base == "https://192.168.0.10:8043"


def test_helpers():
    assert plugin._mac("AA-BB-CC-00-00-01") == "aa:bb:cc:00:00:01" and plugin._mac("x") is None and plugin._mac(None) is None
    assert plugin._version("5.14.26.1") == (5, 14, 26) and plugin._version("5.1") == (5, 1, 0) and plugin._version("v5.15-beta") == (5, 15, 0)
    assert plugin._rate_mbps(866700) == 866.7 and plugin._rate_mbps(433) == 433.0 and plugin._rate_mbps(0) is None and plugin._rate_mbps("x") is None


def test_unreadable_output_would_fail_the_contract():
    with pytest.raises(ContractError):
        validate_output("topology", {"nodes": [{"mac": "bad"}], "clients": []})


def test_diagnose_describes_shapes_and_leaks_nothing(server):
    url, state = server
    report = plugin.diagnose(cfg(url))
    text = json.dumps(report)
    for private in ("laptop", "192.168.0", "AA-BB-CC", "11-22-33", "secret", "127.0.0.1", "Living room", "Rack switch", "Garden"):      # device names; the gateway model (the fake uses it as the name too) is hardware information and is shown on purpose
        assert private not in text, private
    assert report["controller_version"] == "5.14.26.1" and report["steps"]["devices"]["shape"]["count"] == 4
    assert report["steps"]["clients"]["ok"] and report["steps"]["switch_detail"]["ok"]
    assert report["steps"]["clients"]["shape"]["filter_used"] == {"filters.active": "false"} and report["steps"]["clients"]["shape"]["rejected"] == []
    assert report["result"]["nodes"] == 4 and report["result"]["wifi_clients"] == 2 and report["result"]["with_rssi"] == 2
    assert report["steps"]["devices"]["shape"]["first"][0]["mac"] == "<mac dashes, UPPER>"
    assert state["logouts"] == 1


def test_diagnose_records_which_client_variants_were_rejected(server):
    url, state = server
    state["clients_need"] = "none"
    shape = plugin.diagnose(cfg(url))["steps"]["clients"]["shape"]
    assert shape["filter_used"] == "none" and [r["filter"] for r in shape["rejected"]] == [{"filters.active": "false"}, {"filters.active": "true"}]
    assert "General error" in shape["rejected"][0]["error"] and "sites/<site>/clients" in shape["rejected"][0]["error"]


def test_diagnose_reports_a_failing_step_and_still_finishes(server):
    url, state = server
    state["clients_need"] = "never"
    report = plugin.diagnose(cfg(url))
    assert report["steps"]["clients"]["ok"] is False and "every variant" in report["steps"]["clients"]["error"] and state["logouts"] == 1
    assert report["steps"]["devices"]["ok"] is True


def test_diagnose_with_a_wrong_password_is_a_refused_login(server):
    url, state = server
    with pytest.raises(plugin.LoginRefused):
        plugin.diagnose(cfg(url, password="wrong"))


@pytest.mark.parametrize("need,attempts", [(None, ["false"]), ("false", ["false"]), ("true", ["false", "true"]), ("none", ["false", "true", None])])
def test_the_client_list_adapts_to_what_the_controller_accepts(server, need, attempts):
    url, state = server
    state["clients_need"] = need
    out = plugin.fetch(cfg(url))
    assert len(out["clients"]) == 4
    assert state["client_attempts"][: len(attempts)] == attempts and set(state["client_attempts"][len(attempts):]) <= {attempts[-1]}


def test_a_controller_that_rejects_every_client_request_gives_an_error_that_names_the_step(server):
    url, state = server
    state["clients_need"] = "never"
    with pytest.raises(plugin.OmadaError) as err:
        plugin.fetch(cfg(url))
    text = str(err.value)
    assert text.startswith("sites/<site>/clients: General error. (error -1)") and "site1" not in text
    assert state["logouts"] == 1  # it still logs out
    assert state["client_attempts"] == ["false", "true", None]


def test_other_failures_name_their_step_too(server):
    url, state = server
    state["sites"] = [{"name": "Home", "key": "siteX"}]  # a site the fake does not know: its devices request answers an error
    with pytest.raises(plugin.OmadaError, match=r"sites/<site>/devices: unknown sites/siteX/devices"):
        plugin.fetch(cfg(url, site=""))


def with_api(url, **kw):
    return cfg(url, client_id="cid", client_secret="csecret", **kw)


def test_application_statistics_are_summed_per_application_and_per_client(server):
    url, state = server
    out = validate_output("topology", plugin.fetch(with_api(url)))
    (day,) = out["usage"]
    assert day["applications"] == [{"name": "YouTube", "tx_bytes": 110, "rx_bytes": 5500}, {"name": "Printing", "tx_bytes": 7, "rx_bytes": 1}]     # zero rows left out, biggest first
    assert {c["mac"]: (c["tx_bytes"], c["rx_bytes"]) for c in day["clients"]} == {"11:22:33:44:55:01": (100, 5000), "11:22:33:44:55:02": (17, 501)}
    by_mac = {c["mac"]: c["applications"] for c in day["clients"]}      # and the same figures per device
    assert by_mac["11:22:33:44:55:01"] == [{"name": "YouTube", "tx_bytes": 100, "rx_bytes": 5000}]
    assert by_mac["11:22:33:44:55:02"] == [{"name": "YouTube", "tx_bytes": 10, "rx_bytes": 500}, {"name": "Printing", "tx_bytes": 7, "rx_bytes": 1}]
    assert len(day["day"]) == 10
    # logged in with the Open API's own login, asked once per client in the site, with a window from midnight to now
    assert len(state["token_calls"]) == 1
    asked = {mac for mac, _, _ in state["app_calls"] if mac.count("-") == 5}
    assert asked == {"11-22-33-44-55-01", "11-22-33-44-55-02", "11-22-33-44-55-03", "11-22-33-44-55-05"}
    assert all(0 < end - start <= 86400 + 3600 for _, start, end in state["app_calls"])


def test_nothing_is_asked_without_an_open_api_client(server):
    url, state = server
    out = plugin.fetch(cfg(url))
    assert out["usage"] == [] and state["token_calls"] == [] and state["app_calls"] == []


def test_a_wrong_open_api_secret_costs_the_statistics_not_the_topology(server):
    url, state = server
    out = validate_output("topology", plugin.fetch(cfg(url, client_id="cid", client_secret="wrong")))
    assert out["usage"] == [] and len(out["nodes"]) == 4 and len(out["clients"]) == 4
    assert state["logins"] == 1 and state["app_calls"] == []


def test_the_connection_test_says_whether_the_statistics_work(server):
    url, state = server
    assert "Application statistics: working" in plugin.test(with_api(url))["message"]
    assert "not available" in plugin.test(cfg(url, client_id="cid", client_secret="wrong"))["message"]
    assert "not available from this controller" in plugin.test(cfg(url))["message"]
    state["apps"] = {}
    assert "no application traffic" in plugin.test(with_api(url))["message"]


def test_the_application_reads_stop_at_the_time_budget(server, monkeypatch):
    url, state = server
    monkeypatch.setattr(plugin, "USAGE_BUDGET", -1)
    controller = plugin.Controller(with_api(url))
    controller.login()
    controller.snapshot()
    days, problem = controller.usage()
    assert days == [] and "not every client was read" in problem


def test_diagnose_shows_the_application_reply_without_names(server):
    url, state = server
    report = plugin.diagnose(with_api(url))
    step = report["steps"]["application_traffic"]
    assert step["ok"] and step["shape"]["site_ids_match_web_keys"] is True and step["shape"]["row_count"] == 2
    assert step["shape"]["rows"][0]["applicationName"] == "<text 7 chars>"
    text = json.dumps(report)
    for private in ("YouTube", "Printing", "csecret", "AT1", "11-22-33"):
        assert private not in text, private
    assert report["result"]["applications"] == 2 and report["result"]["clients_with_applications"] == 2
    assert "not asked for" in plugin.diagnose(cfg(url))["steps"]["application_traffic"]["shape"]


def test_netlens_switch_for_application_statistics_has_the_last_word(server):
    url, state = server
    out = plugin.fetch(with_api(url, collect_usage=False))
    assert out["usage"] == [] and state["token_calls"] == [] and state["app_calls"] == []
    assert "switched off in Netlens" in plugin.test(with_api(url, collect_usage=False))["message"]
    assert plugin.fetch(with_api(url, collect_usage=True))["usage"] != []


def test_the_diagnostic_says_what_the_application_reads_answered(server):
    url, state = server
    shape = plugin.diagnose(with_api(url))["steps"]["application_traffic"]["shape"]
    assert shape["application_catalogue"] == {"type": "dict", "total": 120} and shape["window_that_worked"] == "today_seconds"
    assert shape["clients_tried"] == 3 and len(shape["attempts"]) == 18 and all(a["window"] and a["mac_form"] for a in shape["attempts"])
    assert shape["mac_form_that_worked"] == "dashes"
    # a controller that has DPI off answers an empty list for everything: the report then says so for each window instead of staying silent
    state["apps"] = {}
    shape = plugin.diagnose(with_api(url))["steps"]["application_traffic"]["shape"]
    assert shape["rows"] == [] and {(a["mac_form"], a["window"]): (a.get("type"), a.get("count")) for a in shape["attempts"] if "type" in a} == {
        (form, w): ("list", 0) for form in ("dashes", "colons") for w in ("today_seconds", "24h_seconds", "24h_milliseconds")}


def test_the_busiest_clients_are_read_first(server):
    url, state = server
    controller = plugin.Controller(with_api(url))
    controller.login()
    controller.snapshot()
    controller.targets[0][1]["trafficDown"] = 1            # the first listed client moved the least
    controller.targets[-1][1]["trafficDown"] = 10 ** 9
    assert sorted(controller.targets, key=plugin._traffic_of)[0][1] is controller.targets[-1][1]


def test_a_controller_that_wants_colons_in_the_mac_address_is_understood(server):
    url, state = server
    state["need_colons"] = True
    (day,) = plugin.fetch(with_api(url))["usage"]
    assert [a["name"] for a in day["applications"]] == ["YouTube", "Printing"]                 # found out by trying both ways of writing the address
    later = [mac for mac, _, _ in state["app_calls"]][-4:]
    assert all(":" in mac for mac in later)                                                        # and then used for every client
    shape = plugin.diagnose(with_api(url))["steps"]["application_traffic"]["shape"]
    assert shape["mac_form_that_worked"] == "colons"


def test_the_diagnostic_reports_what_the_gateway_says_about_dpi_without_leaking_text(server):
    url, state = server
    report = plugin.diagnose(with_api(url))
    gateway = report["steps"]["gateway_dpi"]["shape"]
    assert gateway["model"] == "ER605 v2" and gateway["firmware"] == "2.3.1"
    assert gateway["dpi_related_settings"] == {"dpiEnable": True, "dpiSetting.loggingTraffic": False, "devCap.supportDpi": True}
    text = json.dumps(report)
    assert "secret-name" not in text and "203.0.113.9" not in text


def test_devices_report_processor_memory_uptime_and_the_firmware_that_waits(server):
    url, state = server
    out = validate_output("topology", plugin.fetch(cfg(url)))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert {m["metric"]: m["value"] for m in nodes["ER605"]["metrics"]} == {"cpu_pct": 7.0, "mem_pct": 41.0, "uptime_s": 3600.0}
    assert nodes["ER605"]["firmware"] == {"version": "2.1.3", "latest": "a newer version"}                  # the controller says that one waits, not which
    assert {m["metric"]: m["value"] for m in nodes["Rack switch"]["metrics"]} == {"cpu_pct": 12.0, "mem_pct": 55.0, "uptime_s": 93784.0}      # "1day(s) 2h 3m 4s"
    assert nodes["Rack switch"]["firmware"] == {"version": "1.0.4", "latest": None}
    assert not nodes["Living room"]["metrics"] and nodes["Living room"]["firmware"] is None


def test_the_site_wide_statistics_of_the_web_interface_need_no_open_api_client(server):
    url, state = server
    state["dpi"] = [{"familyId": 1, "familyName": "Streaming", "totalTraffic": 900, "applications": [{"applicationId": 1, "applicationName": "YouTube", "traffic": 700}, {"applicationId": 2, "applicationName": "Netflix", "traffic": 200}]},
                    {"familyId": 2, "familyName": "Gaming", "totalTraffic": 50, "applications": [{"applicationId": 3, "applicationName": "Roblox", "traffic": 50}, {"applicationId": 4, "applicationName": "Quiet", "traffic": 0}]}]
    out = plugin.fetch(cfg(url))                                    # no client id or secret
    (day,) = out["usage"]
    assert [(a["name"], a["rx_bytes"], a["tx_bytes"]) for a in day["applications"]] == [("YouTube", 700, 0), ("Netflix", 200, 0), ("Roblox", 50, 0)] and day["clients"] == []
    path, start, end, select = state["dpi_calls"][0]
    assert 0 < end - start <= 86400 + 3600 and select == ["true"] and state["token_calls"] == []
    assert "Application statistics: working (3 applications today" in plugin.test(cfg(url))["message"]
    assert plugin.fetch(cfg(url, collect_usage=False))["usage"] == []
