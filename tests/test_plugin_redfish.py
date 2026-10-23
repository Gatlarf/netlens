"""The Redfish plugin against a fake BMC: a small HTTP server with a Redfish tree. The tree follows the DMTF public-rackmount1 mockup (which the
plugin was also run against, see the README) and adds the Storage/Drives/Volumes collections that the mockup lacks."""

import importlib.util
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "redfish"
spec = importlib.util.spec_from_file_location("redfish_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def ref(path):
    return {"@odata.id": path}


def coll(*paths):
    return {"Members": [ref(p) for p in paths], "Members@odata.count": len(paths)}


TREE = {
    "/redfish/v1/": {"Vendor": "Contoso", "RedfishVersion": "1.22.0", "Systems": ref("/redfish/v1/Systems"), "Managers": ref("/redfish/v1/Managers"), "Chassis": ref("/redfish/v1/Chassis")},
    "/redfish/v1/Systems": coll("/redfish/v1/Systems/S1"),
    "/redfish/v1/Systems/S1": {"Id": "S1", "Name": "web", "HostName": "web483", "Manufacturer": "Contoso", "Model": "3500", "SerialNumber": "SN123", "BiosVersion": "P79", "PowerState": "On",
                               "Status": {"State": "Enabled", "Health": "OK", "HealthRollup": "OK"}, "EthernetInterfaces": ref("/redfish/v1/Systems/S1/Eth"), "Storage": ref("/redfish/v1/Systems/S1/Storage")},
    "/redfish/v1/Systems/S1/Eth": coll("/redfish/v1/Systems/S1/Eth/1"),
    "/redfish/v1/Systems/S1/Eth/1": {"MACAddress": "12:44:6A:3B:04:11", "IPv4Addresses": [{"Address": "192.168.0.10"}]},
    "/redfish/v1/Systems/S1/Storage": coll("/redfish/v1/Systems/S1/Storage/RAID"),
    "/redfish/v1/Systems/S1/Storage/RAID": {"Id": "RAID", "Drives": [ref("/d/1"), ref("/d/2"), ref("/d/3"), ref("/d/4")], "Volumes": ref("/redfish/v1/Systems/S1/Storage/RAID/Volumes")},
    "/redfish/v1/Systems/S1/Storage/RAID/Volumes": coll("/redfish/v1/Systems/S1/Storage/RAID/Volumes/V1"),
    "/redfish/v1/Systems/S1/Storage/RAID/Volumes/V1": {"Id": "V1", "Name": "Data", "RAIDType": "RAID5", "CapacityBytes": 12000000000000, "Status": {"Health": "Warning", "State": "Enabled"}},
    "/d/1": {"Id": "Disk.Bay.1", "Name": "Bay 1", "Model": "ST8000", "CapacityBytes": 8000000000000, "Status": {"State": "Enabled", "Health": "OK"}},
    "/d/2": {"Id": "Disk.Bay.2", "Name": "Bay 2", "Model": "ST8000", "CapacityBytes": 8000000000000, "Status": {"State": "Enabled", "Health": "Critical"}},
    "/d/3": {"Id": "Disk.Bay.3", "Name": "Bay 3", "Status": {"State": "Absent"}},
    "/d/4": {"Id": "Disk.Bay.4", "Name": "Bay 4", "Model": "ST8000", "CapacityBytes": 8000000000000, "HotspareType": "Global", "Status": {"State": "Enabled", "Health": "OK"}},
    "/redfish/v1/Managers": coll("/redfish/v1/Managers/BMC"),
    "/redfish/v1/Managers/BMC": {"Id": "BMC", "Name": "Manager", "FirmwareVersion": "1.45", "Status": {"State": "Enabled", "Health": "OK"}, "EthernetInterfaces": ref("/redfish/v1/Managers/BMC/Eth")},
    "/redfish/v1/Managers/BMC/Eth": coll("/redfish/v1/Managers/BMC/Eth/1"),
    "/redfish/v1/Managers/BMC/Eth/1": {"PermanentMACAddress": "23:11:8a:33:cf:ea", "IPv4Addresses": [{"Address": "192.168.0.70"}]},
    "/redfish/v1/Chassis": coll("/redfish/v1/Chassis/1U"),
    "/redfish/v1/Chassis/1U": {"Id": "1U", "Name": "Chassis", "Status": {"State": "Enabled", "Health": "OK"}, "Power": ref("/redfish/v1/Chassis/1U/Power"), "Thermal": ref("/redfish/v1/Chassis/1U/Thermal")},
    "/redfish/v1/Chassis/1U/Power": {"PowerSupplies": [{"Name": "PSU 1", "Status": {"Health": "OK"}}, {"Name": "PSU 2", "Status": {"Health": "Warning"}}]},
    "/redfish/v1/Chassis/1U/Thermal": {"Fans": [{"Name": "Fan 1", "Status": {"Health": "Critical"}}], "Temperatures": [{"Name": "CPU", "Status": {"Health": "OK"}}]},
}


class Bmc:
    def __init__(self, tree=None, user="u", password="p"):
        self.tree, self.auth, self.seen = tree or TREE, "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode(), []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fake.seen.append(self.path)
                if self.headers.get("Authorization") != fake.auth:
                    return self._send(401, {"error": {"message": "bad login"}})
                body = fake.tree.get(self.path.split("?")[0])
                self._send(200, body) if body is not None else self._send(404, {"error": {}})

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def config(self, password="p"):
        return {"servers": [{"host": self.url, "username": "u", "password": password}]}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def bmc():
    b = Bmc()
    yield b
    b.close()


def test_manifest_and_output_are_valid(bmc):
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    out = validate_output("storage", plugin.fetch(bmc.config()))
    assert out["systems"][0]["serial"] == "SN123" and out["systems"][0]["name"] == "web483"


def test_health_is_the_worst_part_and_problems_become_alerts(bmc):
    out = plugin.fetch(bmc.config())
    assert out["systems"][0]["health"] == "critical"                       # a failed fan and a failed drive
    texts = {a["text"] for a in out["alerts"]}
    assert {"PSU 2: warning", "Fan 1: critical", "Drive Disk.Bay.2: failed"} <= texts
    assert "CPU: ok" not in texts


def test_drives_volumes_and_controllers(bmc):
    out = plugin.fetch(bmc.config())
    states = {d["slot"]: d["state"] for d in out["disks"]}
    assert states == {"Disk.Bay.1": "ok", "Disk.Bay.2": "failed", "Disk.Bay.4": "spare"}      # the empty bay is left out
    assert out["volumes"][0]["protocol"] == "RAID5" and out["volumes"][0]["health"] == "warning" and out["volumes"][0]["size"] == 12000000000000
    by_ip = {c["ip"]: c for c in out["controllers"]}
    assert by_ip["192.168.0.70"]["mac"] == "23:11:8a:33:cf:ea"                # the BMC
    assert by_ip["192.168.0.10"]["mac"] == "12:44:6a:3b:04:11"                # the host's network card, lower-cased


def test_wrong_password_stops_retrying(bmc):
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(bmc.config(password="wrong"))
    assert err.value.auth_failed is True


def test_missing_parts_are_noted_not_fatal():
    tree = {k: v for k, v in TREE.items() if "Chassis" not in k and "Storage" not in k}
    tree["/redfish/v1/"] = {**TREE["/redfish/v1/"]}
    b = Bmc(tree)
    try:
        out = plugin.fetch(b.config())
        assert out["disks"] == [] and out["systems"][0]["health"] in ("ok", "unknown")
        assert "Not available" in plugin.test(b.config())["message"]
    finally:
        b.close()


def test_not_redfish_is_reported():
    b = Bmc({"/redfish/v1/": {"nothing": True}})
    try:
        with pytest.raises(plugin.RedfishError):
            plugin.fetch(b.config())
    finally:
        b.close()


def test_diagnose_has_no_addresses_or_serials(bmc):
    text = json.dumps(plugin.diagnose(bmc.config()))
    for secret in ("SN123", "12:44", "192.168.0", "127.0.0.1", "web483", "23:11"):
        assert secret not in text
    assert '"ok": true' in text


def test_problem_text_has_no_address():
    class Fake:
        id, base, host = "10.1.2.3:8443", "https://10.1.2.3:8443", "10.1.2.3"
    text = plugin._problem(plugin.ConnectError("cannot reach the BMC at 10.1.2.3: timed out https://10.1.2.3:8443/redfish/v1/ bmc.example.com:443"), Fake())
    assert "10.1.2.3" not in text and "example.com" not in text
