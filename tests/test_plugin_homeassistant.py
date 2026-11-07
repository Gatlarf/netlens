"""The Home Assistant plugin against canned answers (the shapes of /api/config and the device list of the template call)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "homeassistant"
spec = importlib.util.spec_from_file_location("homeassistant_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

CONFIG = {"location_name": "Home", "version": "2026.10.1"}
DEVICES = [
    {"id": "d1", "name": "Hallway lamp", "manufacturer": "IKEA", "model": "E27", "area": "Hall", "sw": "1.2", "avail": True, "batt": None, "upd": False,
     "connections": [["mac", "AA:BB:CC:00:00:01"]], "url": "http://192.168.0.50", "via": "d2", "entities": 2},
    {"id": "d2", "name": "Zigbee hub", "manufacturer": "Sonoff", "model": "ZBBridge", "avail": True, "batt": None, "connections": [], "via": None, "entities": 5},
    {"id": "d3", "name": "Door sensor", "manufacturer": "Aqara", "model": "MCCGQ11LM", "avail": False, "batt": 12, "connections": [["zigbee", "00:11:22"]], "via": "d2", "entities": 1},
    {"id": "d4", "name": "Weather", "avail": True, "entry_type": "service", "connections": []},          # a service, not a device: left out by default
    {"id": "d5", "name": "Off", "disabled": True, "avail": True, "connections": []},
]
AUTH = "Bearer secret-token"
ROUTES = {"/api/config": CONFIG, ("POST", "/api/template"): DEVICES}


def config(url, **extra):
    return {"url": url, "token": "secret-token", "timeout": 5, **extra}


def test_manifest_and_devices_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "inventory"
    with Canned(ROUTES, auth=AUTH) as s:
        out = validate_output("inventory", plugin.fetch(config(s.url)))
    by = {d["id"]: d for d in out["devices"]}
    assert sorted(by) == ["d1", "d2", "d3"]                                  # the service and the disabled device are not listed
    assert by["d1"]["mac"] == "aa:bb:cc:00:00:01" and by["d1"]["ip"] == "192.168.0.50" and by["d1"]["via_id"] == "d2"
    assert by["d3"]["available"] is False and by["d3"]["battery"] == 12 and by["d3"]["battery_low"] is True      # below the default threshold of 20
    assert out["servers"][0]["name"] == "Home" and out["servers"][0]["version"] == "2026.10.1"


def test_services_and_the_battery_threshold_can_be_set():
    with Canned(ROUTES, auth=AUTH) as s:
        out = plugin.fetch(config(s.url, include_services=True, battery_low=10))
    by = {d["id"]: d for d in out["devices"]}
    assert "d4" in by and by["d3"]["battery_low"] is False                   # 12 % is not low when the limit is 10


def test_the_message_counts_what_needs_attention():
    with Canned(ROUTES, auth=AUTH) as s:
        message = plugin.test(config(s.url))["message"]
    assert "3 device(s)" in message and "1 with a MAC address" in message and "1 unavailable" in message and "1 with a low battery" in message


def test_a_wrong_token_is_refused_and_the_report_holds_no_names_or_addresses():
    with Canned(ROUTES, auth="Bearer other") as s:
        with pytest.raises(plugin.AuthRefused):
            plugin.fetch(config(s.url))
    with Canned(ROUTES, auth=AUTH) as s:
        report = json.dumps(plugin.diagnose(config(s.url)))
    assert "Hallway" not in report and "aa:bb" not in report.lower() and "127.0.0.1" not in report and '"devices": 5' in report


def test_input_is_checked_and_an_unreachable_server_is_explained():
    with pytest.raises(plugin.HaError, match="long-lived access token"):
        plugin.Server({"url": "http://ha.local:8123"})
    with pytest.raises(plugin.HaError, match="is not an address"):
        plugin.Server({"url": "ftp://ha.local", "token": "x"})
    import socket

    with socket.socket() as sock:                                              # a port nothing listens on: refused at once
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    with pytest.raises(plugin.HaError, match="cannot reach"):
        plugin.fetch(config(f"http://127.0.0.1:{closed}"))
