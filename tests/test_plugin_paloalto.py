"""The Palo Alto plugin against a simulated firewall. The answers follow the PAN-OS XML API as documented; no real firewall has answered yet."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "paloalto"
spec = importlib.util.spec_from_file_location("paloalto_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

KEY = "k"


def ok(inner):
    return f'<response status="success"><result>{inner}</result></response>'


ANSWERS = {
    "<show><system><info/></system></show>": ok("<system><hostname>PA-HQ</hostname><ip-address>192.168.1.1</ip-address><mac-address>00:1b:17:aa:00:01</mac-address><model>PA-440</model><serial>0123456789</serial><sw-version>10.2.4</sw-version></system>"),
    "<show><interface>all</interface></show>": ok("<hw><entry><name>ethernet1/1</name><id>16</id><mac>00:1b:17:aa:00:11</mac><speed>1000</speed><duplex>full</duplex><state>up</state></entry>"
                                                  "<entry><name>ethernet1/2</name><id>17</id><mac>00:1b:17:aa:00:12</mac><speed>ukn</speed><duplex>ukn</duplex><state>down</state></entry></hw>"),
    "<show><dhcp><server><lease><interface>all</interface></lease></server></dhcp></show>": ok('<interface name="ethernet1/2"><entry><ip>192.168.1.50</ip><mac>aa:bb:cc:00:00:50</mac><hostname>laptop</hostname></entry></interface>'),
    "<show><arp><entry name = 'all'/></arp></show>": ok("<entries><entry><status>c</status><ip>192.168.1.50</ip><mac>aa:bb:cc:00:00:50</mac><interface>ethernet1/2</interface></entry>"
                                                         "<entry><status>c</status><ip>192.168.1.60</ip><mac>aa:bb:cc:00:00:60</mac><interface>ethernet1/2</interface></entry>"
                                                         "<entry><status>i</status><ip>192.168.1.61</ip><mac>(incomplete)</mac><interface>ethernet1/2</interface></entry></entries>"),
    "<show><high-availability><state/></high-availability></show>": ok("<enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>active</state></local-info><peer-info><state>passive</state></peer-info><running-sync>synchronized</running-sync></group>"),
    "<show><vpn><flow/></vpn></show>": ok("<IPSec><entry><id>1</id><name>to-branch</name><gw>gw-branch</gw><state>active</state></entry><entry><id>2</id><name>to-lab</name><state>init</state></entry></IPSec>"),
    "<request><license><info/></license></request>": ok("<licenses><entry><feature>Threat Prevention</feature><expires>January 31, 2030</expires><expired>no</expired></entry>"
                                                         "<entry><feature>PAN-OS Support</feature><expires>Never</expires></entry></licenses>"),
}


class Fake:
    def __init__(self, answers=None, fail=None):
        self.answers, self.fail, self.seen = answers or ANSWERS, fail or {}, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                url = urlsplit(self.path)
                query = parse_qs(url.query)
                outer.seen.append((url.path, query, self.headers.get("X-PAN-KEY")))
                if self.headers.get("X-PAN-KEY") != KEY:
                    body = '<response status="error" code="403"><result><msg>Invalid credentials.</msg></result></response>'
                else:
                    cmd = query.get("cmd", [""])[0]
                    body = outer.fail.get(cmd) or outer.answers.get(cmd) or '<response status="error" code="17"><msg>Unknown command</msg></response>'
                raw = body.encode()
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


def cfg(f, key=KEY):
    return {"servers": [{"host": f.url, "api_key": key}], "verify_tls": True, "timeout": 5}


def test_the_manifest_is_valid():
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))


def test_fetch_gives_a_valid_topology_with_clients_interfaces_and_health(fake):
    out = validate_output("topology", plugin.fetch(cfg(fake)))
    node = out["nodes"][0]
    assert node["role"] == "gateway" and node["mac"] == "00:1b:17:aa:00:01" and node["name"] == "PA-HQ" and node["model"] == "PA-440"
    assert [(p["port"], p["name"], p["up"], p["speed_mbps"]) for p in node["ports"]] == [(16, "ethernet1/1", True, 1000.0), (17, "ethernet1/2", False, None)]
    fw = node["firewall"]
    assert fw["version"] == "10.2.4" and fw["serial"] == "0123456789"
    assert fw["ha"] == {"mode": "active-passive", "state": "active", "peer_state": "passive", "in_sync": True}
    assert {t["name"]: t["up"] for t in fw["tunnels"]} == {"to-branch": True, "to-lab": False}
    assert fw["licences"] == [{"name": "Threat Prevention", "expires": "2030-01-31"}]                       # "Never" has no end date
    by_mac = {c["mac"]: c for c in out["clients"]}
    assert set(by_mac) == {"aa:bb:cc:00:00:50", "aa:bb:cc:00:00:60"}                                         # the incomplete ARP entry is left out
    assert by_mac["aa:bb:cc:00:00:50"]["name"] == "laptop" and by_mac["aa:bb:cc:00:00:50"]["port"] == "ethernet1/2"
    assert all(c["node_mac"] == node["mac"] for c in out["clients"])


def test_only_show_commands_with_the_key_in_a_header(fake):
    plugin.fetch(cfg(fake))
    assert fake.seen and all(k == KEY and q["type"] == ["op"] and (q["cmd"][0].startswith("<show>") or q["cmd"][0].startswith("<request><license><info/>")) for _, q, k in fake.seen)
    assert not any(KEY in str(path) for path, _, _ in fake.seen)


def test_a_wrong_key_stops_retries(fake):
    with pytest.raises(plugin.AuthRefused) as err:
        plugin.fetch(cfg(fake, key="nope"))
    assert err.value.auth_failed


def test_a_command_this_version_does_not_know_is_skipped():
    answers = dict(ANSWERS)
    answers.pop("<show><vpn><flow/></vpn></show>")
    f = Fake(answers)
    try:
        out = plugin.fetch(cfg(f))
        assert "tunnels" not in out["nodes"][0]["firewall"] and out["nodes"][0]["firewall"]["version"] == "10.2.4"
    finally:
        f.close()


def test_no_ha_when_it_is_not_enabled():
    answers = dict(ANSWERS)
    answers["<show><high-availability><state/></high-availability></show>"] = ok("<enabled>no</enabled>")
    f = Fake(answers)
    try:
        assert "ha" not in plugin.fetch(cfg(f))["nodes"][0]["firewall"]
    finally:
        f.close()


def test_test_and_diagnose(fake):
    assert "PAN-OS 10.2.4" in plugin.test(cfg(fake))["message"]
    report = plugin.diagnose(cfg(fake))
    steps = report["firewalls"][0]["steps"]
    assert steps["dhcp"]["entries"] == 1 and "hostname" in steps["dhcp"]["tags"] and steps["licences"]["entries"] == 2
    assert "127.0.0.1" not in json.dumps(report) and "0123456789" not in json.dumps(report) and "laptop" not in json.dumps(report)
