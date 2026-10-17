import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app import inventory, tsdb
from app.db import connect, init_db
from app.plugins.contract import ContractError, validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "homeassistant"
spec = importlib.util.spec_from_file_location("ha_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

REGISTRY = [
    {"id": "d1", "name": "Hall lamp", "manufacturer": "IKEA", "model": "E27", "sw": "1.2", "area": "Hall", "connections": [["zigbee", "00:11:22:33:44:55:66:77"]], "via": "d4", "identifiers": [["zha", "x"]],
     "url": None, "entry_type": None, "disabled": None, "avail": True, "batt": None, "low": False, "upd": True, "entities": 3},
    {"id": "d2", "name": "Door sensor", "manufacturer": "Aqara", "model": "MCCGQ11LM", "sw": None, "area": "Front door", "connections": [["zigbee", "aa"]], "via": "d4", "identifiers": [["zha", "y"]],
     "url": None, "entry_type": None, "disabled": None, "avail": False, "batt": 12.0, "low": False, "upd": False, "entities": 4},
    {"id": "d3", "name": "Router", "manufacturer": "ASUSTek", "model": "RT-AX88U", "sw": "3.0", "area": None, "connections": [["mac", "AA-BB-CC-DD-EE-01"]], "via": None, "identifiers": [["asusrouter", "z"]],
     "url": "http://192.168.1.1", "entry_type": None, "disabled": None, "avail": True, "batt": None, "low": False, "upd": False, "entities": 20},
    {"id": "d4", "name": "Zigbee coordinator", "manufacturer": "Nabu Casa", "model": "SkyConnect", "sw": None, "area": None, "connections": [], "via": None, "identifiers": [["zha", "c"]],
     "url": None, "entry_type": None, "disabled": None, "avail": True, "batt": None, "low": False, "upd": False, "entities": 1},
    {"id": "d5", "name": "Supervisor", "manufacturer": "Home Assistant", "model": "Supervisor", "sw": "1", "area": None, "connections": [], "via": None, "identifiers": [["hassio", "s"]],
     "url": None, "entry_type": "service", "disabled": None, "avail": True, "batt": None, "low": False, "upd": False, "entities": 5},
    {"id": "d6", "name": "Disabled", "manufacturer": "X", "model": "Y", "connections": [], "via": None, "identifiers": [], "entry_type": None, "disabled": "user", "avail": True, "entities": 1},
]


class FakeHa(BaseHTTPRequestHandler):
    log = []

    def _send(self, code, doc):
        raw = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        FakeHa.log.append(("GET", self.path))
        if self.headers.get("Authorization") != "Bearer good":
            return self._send(401, {"message": "401: Unauthorized"})
        if self.path == "/api/config":
            return self._send(200, {"version": "2026.7.1", "location_name": "Home"})
        self._send(404, {})

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        FakeHa.log.append(("POST", self.path))
        if self.path == "/auth/login_flow":
            return self._send(200, {"flow_id": "f1", "type": "form"})
        if self.path == "/auth/login_flow/f1":
            ok = json.loads(body).get("password") == "pw"
            return self._send(200, {"type": "create_entry", "result": "code1"} if ok else {"type": "form", "errors": {"base": "invalid_auth"}})
        if self.path == "/auth/token":
            return self._send(200, {"access_token": "good"})
        if self.headers.get("Authorization") != "Bearer good":
            return self._send(401, {})
        if self.path == "/api/template":
            return self.wfile.write(b"") if False else self._send(200, REGISTRY)
        self._send(404, {})

    def log_message(self, *a):
        pass


@pytest.fixture
def ha():
    FakeHa.log = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeHa)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "i.db")
    init_db(c)
    yield c
    c.close()
    tsdb.forget_all()


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "inventory"


def test_plugin_with_token_and_with_password(ha):
    out = plugin.fetch({"url": ha, "token": "good"})
    devices = {d["id"]: d for d in out["devices"]}
    assert set(devices) == {"d1", "d2", "d3", "d4"}                      # the service and the disabled device are left out
    assert devices["d1"]["protocol"] == "zigbee" and devices["d1"]["via_id"] == "d4" and devices["d1"]["update"] is True
    assert devices["d2"]["available"] is False and devices["d2"]["battery"] == 12 and devices["d2"]["battery_low"] is True
    assert devices["d3"]["mac"] == "aa:bb:cc:dd:ee:01" and devices["d3"]["ip"] == "192.168.1.1" and devices["d3"]["protocol"] == "asusrouter"
    validate_output("inventory", out)
    assert len(plugin.fetch({"url": ha, "username": "u", "password": "pw", "include_services": True})["devices"]) == 5
    assert "refused" in str(pytest.raises(plugin.AuthRefused, plugin.fetch, {"url": ha, "username": "u", "password": "bad"}).value)
    assert pytest.raises(plugin.AuthRefused, plugin.fetch, {"url": ha, "token": "nope"})
    assert "unavailable" in plugin.test({"url": ha, "token": "good"})["message"]
    assert all(m == "GET" or p in ("/api/template", "/auth/login_flow", "/auth/login_flow/f1", "/auth/token") for m, p in FakeHa.log)


def test_diagnose_has_no_names(ha):
    text = json.dumps(plugin.diagnose({"url": ha, "token": "good"}))
    assert "Hall lamp" not in text and "127.0.0.1" not in text and "aa:bb" not in text and '"devices": 6' in text
    assert "127.0.0.1" not in json.dumps(plugin.diagnose({"url": "http://127.0.0.1:1", "token": "x"}))


def test_contract_rejects_bad_output():
    with pytest.raises(ContractError):
        validate_output("inventory", {"servers": [], "devices": [{"id": "a", "server_id": "nope"}]})
    out = validate_output("inventory", {"servers": [{"id": "s"}], "devices": [{"id": "a", "server_id": "s", "via_id": "missing", "battery": 50, "mac": "AA-BB-CC-DD-EE-FF"}]})
    assert out["devices"][0]["via_id"] is None and out["devices"][0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_apply_matches_devices_and_raises_events(conn, ha):
    conn.execute("INSERT INTO devices (mac, primary_ip, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.1', '2026-10-17T00:00:00Z', '2026-10-17T00:00:00Z')")
    conn.commit()
    did = conn.execute("SELECT id FROM devices").fetchone()["id"]
    data = validate_output("inventory", plugin.fetch({"url": ha, "token": "good"}))
    first = inventory.apply_inventory(conn, "homeassistant", data)
    assert first["devices"] == 4 and first["matched"] == 1 and first["unavailable"] == 1 and first["battery_low"] == 1 and first["events"] == 0
    assert inventory.for_device(conn, did)["model"] == "RT-AX88U"
    # the door sensor comes back, the lamp goes away
    for d in data["devices"]:
        if d["id"] == "d2":
            d.update(available=True, battery=80, battery_low=False)
        if d["id"] == "d1":
            d.update(available=False, battery=9, battery_low=True)
    second = inventory.apply_inventory(conn, "homeassistant", data)
    kinds = sorted(r["kind"] for r in conn.execute("SELECT kind FROM events"))
    assert kinds == ["inventory_available", "inventory_battery_low", "inventory_unavailable"] and second["events"] == 3
    again = inventory.apply_inventory(conn, "homeassistant", data)
    assert again["events"] == 0
    doc = inventory.overview(conn)
    assert doc["summary"]["devices"] == 4 and next(d for d in doc["devices"] if d["id"] == "d1")["via"] == "Zigbee coordinator"
    inventory.remove_plugin(conn, "homeassistant")
    assert inventory.overview(conn)["devices"] == []
