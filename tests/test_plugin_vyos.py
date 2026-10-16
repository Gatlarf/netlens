"""The VyOS plugin against a simulated VyOS HTTPS API (texts recorded from VyOS 2026.10 rolling on 2026-10-16; the DHCP lease table follows the VyOS documentation)."""

import importlib.util
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "vyos"
spec = importlib.util.spec_from_file_location("vyos_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

INTERFACES = """Codes: S - State, L - Link, u - Up, D - Down, A - Admin Down
Interface    IP Address    MAC                VRF        MTU  S/L    Description
-----------  ------------  -----------------  -------  -----  -----  -------------
eth0         192.168.1.1/24  52:54:00:12:34:56  default   1500  u/u    LAN
eth1         203.0.113.5/24  52:54:00:12:34:57  default   1500  u/u    WAN
lo           127.0.0.1/8   00:00:00:00:00:00  default  65536  u/u
             ::1/128
"""
ARP = """Address       Interface    Link layer address    State
------------  -----------  --------------------  ---------
192.168.1.77  eth0         02:aa:00:00:00:77     PERMANENT
192.168.1.20  eth0         02:11:22:33:44:55     REACHABLE
192.168.1.30  eth0         02:11:22:33:44:99     FAILED
192.168.1.31  eth0                               INCOMPLETE
203.0.113.1   eth1         52:55:0a:00:02:02     STALE
"""
LEASES = """IP Address    MAC address        State    Lease start          Lease expiration     Remaining    Pool    Hostname
------------  -----------------  -------  -------------------  -------------------  -----------  ------  ----------
192.168.1.20  02:11:22:33:44:55  active   2026/10/16 10:00:00  2026/10/17 10:00:00  23:59:00     LAN     laptop
192.168.1.21  02:11:22:33:44:66  active   2026/10/16 10:00:00  2026/10/17 10:00:00  23:59:00     LAN     -
"""


@pytest.fixture
def vyos():
    state = {"nat": True, "leases": LEASES}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, payload):
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/info":
                return self.send(200, {"success": True, "data": {"banner": "Welcome", "hostname": "vyos-lab", "version": "2026.10.16-0024-rolling"}, "error": None})
            self.send(404, {})

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            data = json.loads(re.search(r'name="data"\r\n\r\n(.*?)\r\n--', body, re.S).group(1))
            key = re.search(r'name="key"\r\n\r\n(.*?)\r\n--', body, re.S).group(1)
            if key != "k":
                return self.send(401, {"success": False, "error": "Valid API key is required", "data": None})
            path = tuple(data["path"])
            if self.path == "/show" and path == ("interfaces",):
                out = INTERFACES
            elif self.path == "/show" and path == ("arp",):
                out = ARP
            elif self.path == "/show" and path == ("dhcp", "server", "leases"):
                out = state["leases"]
            elif self.path == "/retrieve" and data["op"] == "exists":
                out = state["nat"]
            else:
                return self.send(400, {"success": False, "error": "Invalid command", "data": None})
            self.send(200, {"success": True, "data": out, "error": None})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", state
    httpd.shutdown()
    httpd.server_close()


def config(vyos, key="k", **row):
    return {"servers": [{"host": vyos[0], "api_key": key, **row}], "timeout": 5}


def test_manifest_and_output_follow_the_contract(vyos):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(vyos)))
    node = out["nodes"][0]
    assert (node["mac"], node["ip"], node["name"], node["role"]) == ("52:54:00:12:34:56", "192.168.1.1", "vyos-lab", "gateway") and "VyOS 2026.10" in node["model"]
    assert "52:54:00:12:34:57" in node["macs"]
    clients = {c["mac"]: c for c in out["clients"]}
    assert set(clients) == {"02:aa:00:00:00:77", "02:11:22:33:44:55", "52:55:0a:00:02:02", "02:11:22:33:44:66"}              # FAILED, INCOMPLETE and the router itself are skipped
    assert clients["02:11:22:33:44:55"]["name"] == "laptop" and clients["02:11:22:33:44:66"].get("name") is None
    assert clients["02:11:22:33:44:66"]["ip"] == "192.168.1.21"


def test_role_without_nat_two_routers_and_no_dhcp_server(vyos):
    url, state = vyos
    state["nat"], state["leases"] = False, "DHCP server is not configured\n"
    out = plugin.fetch(config(vyos))
    assert out["nodes"][0]["role"] == "node" and len(out["clients"]) == 3
    assert plugin.fetch(config(vyos, role="gateway"))["nodes"][0]["role"] == "gateway"


def test_message_wrong_key_and_diagnose(vyos):
    assert "Connected to 1 VyOS router(s) (2026.10.16-0024-rolling): 4 client(s)" in plugin.test(config(vyos))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(vyos, key="wrong"))
    assert caught.value.auth_failed is True
    text = json.dumps(plugin.diagnose(config(vyos)))
    assert "192.168" not in text and "laptop" not in text and '"parsed_rows": 4' in text and '"source_nat": true' in text


def test_parsers():
    assert plugin.parse_neighbors("10.0.0.5 eth0 aa:bb:cc:dd:ee:ff REACHABLE")[0] == ("10.0.0.5", "eth0", "aa:bb:cc:dd:ee:ff", "REACHABLE")
    assert plugin.parse_leases("10.0.0.9 aa:bb:cc:dd:ee:01 active 2026/10/16 10:00:00 2026/10/17 10:00:00 23:59:00 LAN host-1")[0][2] == "host-1"
    assert plugin.parse_leases("10.0.0.9 aa:bb:cc:dd:ee:01 active 2026/10/16 10:00:00 2026/10/17 10:00:00 23:59:00 LAN -")[0][2] is None
