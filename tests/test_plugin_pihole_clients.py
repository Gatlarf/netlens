"""The Pi-hole clients plugin against canned answers (shapes recorded from Pi-hole 6.4.3 on 2026-10-16)."""

import importlib.util
import json
import time
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "pihole-clients"
spec = importlib.util.spec_from_file_location("pihole_clients_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

NOW = int(time.time())


def device(i, hwaddr, ips, last=NOW - 60, vendor=""):
    return {"id": i, "hwaddr": hwaddr, "interface": "eth0", "firstSeen": NOW - 99999, "lastQuery": last, "numQueries": 5, "macVendor": vendor,
            "ips": [{"ip": ip, "name": name, "lastSeen": seen, "nameUpdated": 0} for ip, name, seen in ips]}


DEVICES = [device(1, "02:42:81:30:e0:53", [("172.23.0.1", None, NOW)]),
           device(2, "ip-127.0.0.1", [("127.0.0.1", "localhost", NOW)]),
           device(3, "AA:BB:CC:00:00:03", [("192.168.0.30", "tv.home.lan.", NOW - 100), ("fe80::1", "tv-v6", NOW)], vendor="Samsung Electronics"),
           device(4, "aa:bb:cc:00:00:04", [("192.168.0.40", "old-ip", NOW - 5000), ("192.168.0.41", "new-ip", NOW - 10)]),
           device(5, "aa:bb:cc:00:00:05", [("192.168.0.50", "ancient", NOW - 99999)], last=NOW - 90 * 86400),
           device(6, "01:00:5e:00:00:01", [("224.0.0.1", "mcast", NOW)])]


@pytest.fixture
def pihole():
    r = {("POST", "/api/auth"): {"session": {"valid": True, "totp": False, "sid": "abc", "validity": 300, "message": "correct password"}},
         "/api/info/version": {"version": {"core": {"local": {"version": "v6.4.3"}}}}, "/api/network/devices": {"devices": DEVICES, "took": 0.001}}
    with Canned(r) as s:
        yield s


def config(s, password="pw", **extra):
    return {"servers": [{"host": s.url, "password": password}], "timeout": 5, **extra}


def test_manifest_and_clients_follow_the_contract(pihole):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(pihole)))
    assert out["nodes"] == []
    clients = {c["mac"]: c for c in out["clients"]}
    assert sorted(clients) == ["02:42:81:30:e0:53", "aa:bb:cc:00:00:03", "aa:bb:cc:00:00:04"]      # no ip-... rows, no multicast, nothing older than 30 days
    tv = clients["aa:bb:cc:00:00:03"]
    assert tv["ip"] == "192.168.0.30" and tv["name"] == "tv.home.lan" and tv["vendor"] == "Samsung Electronics"           # IPv4 only, trailing dot removed
    assert clients["aa:bb:cc:00:00:04"]["ip"] == "192.168.0.41" and clients["aa:bb:cc:00:00:04"]["name"] == "new-ip"       # the address seen last
    assert clients["02:42:81:30:e0:53"]["name"] is None


def test_days_setting(pihole):
    out = plugin.fetch(config(pihole, days=365))
    assert "aa:bb:cc:00:00:05" in {c["mac"] for c in out["clients"]}


def test_message(pihole):
    message = plugin.test(config(pihole))["message"]
    assert "Pi-hole v6.4.3" in message and "3 device(s)" in message and "2 with a name" in message


def test_wrong_password_stops_retries():
    with Canned({("POST", "/api/auth"): 401}) as s:
        with pytest.raises(plugin.AuthRefused) as exc:
            plugin.fetch(config(s))
        assert exc.value.auth_failed
    with Canned({("POST", "/api/auth"): {"session": {"valid": False, "totp": True, "sid": None}}}) as s:
        with pytest.raises(plugin.AuthRefused, match="two-factor"):
            plugin.fetch(config(s))


def test_unreachable_and_settings():
    with pytest.raises(plugin.PiholeError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "password": "x"}], "timeout": 3})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": [{"password": "x"}]})


def test_diagnose_has_only_counts(pihole):
    report = plugin.diagnose(config(pihole))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["devices"]["count"] == 6 and steps["devices"]["with_mac"] == 4 and steps["devices"]["with_vendor"] == 1 and steps["devices"]["multi_address"] == 2
    for secret in ("home.lan", "192.168", "aa:bb", "Samsung", "127.0.0.1", "pw"):
        assert secret not in text
