"""The AdGuard Home clients plugin against canned answers (shapes recorded from AdGuard Home v0.107.79 on 2026-10-16)."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "adguard-clients"
spec = importlib.util.spec_from_file_location("adguard_clients_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Basic " + base64.b64encode(b"admin:pw").decode()


def client(name, ids, tags=None):
    return {"name": name, "ids": ids, "tags": tags, "use_global_settings": True, "filtering_enabled": False}


ROUTES = {
    "/control/status": {"version": "v0.107.79", "running": True, "dhcp_available": True},
    "/control/dhcp/status": {"interface_name": "eth0", "enabled": True, "leases": [{"mac": "1a:1b:1c:1d:1e:1f", "ip": "192.168.0.101", "hostname": "laptop", "expires": "2026-10-17T10:00:00Z"},
                                                                                {"mac": "01:00:5e:00:00:01", "ip": "192.168.0.102", "hostname": "multicast"}, {"mac": "bad", "ip": "192.168.0.103", "hostname": "x"}],
                             "static_leases": [{"mac": "aa:bb:cc:00:00:04", "ip": "192.168.0.40", "hostname": "printer"}]},
    "/control/clients": {"clients": [client("Living room TV", ["192.168.0.30", "AA:BB:CC:00:00:03"], ["device_tv", "os_android", "user_admin"]), client("Kids tablet", ["192.168.0.0/28"]),
                                     client("Laptop of Sam", ["1a:1b:1c:1d:1e:1f"], ["device_laptop", "os_windows"]), client("By address", ["10.0.0.5"])],
                         "auto_clients": [{"ip": "172.23.0.3", "name": "47dc73422f36", "source": "etc/hosts"}], "supported_tags": ["device_tv"]},
}


@pytest.fixture
def adguard():
    with Canned(dict(ROUTES), auth=AUTH) as s:
        yield s


def config(s, password="pw", **extra):
    return {"servers": [{"host": s.url, "username": "admin", "password": password}], "timeout": 5, **extra}


def test_manifest_and_clients_follow_the_contract(adguard):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(adguard)))
    assert out["nodes"] == []
    clients = {c["mac"]: c for c in out["clients"]}
    assert sorted(clients) == ["1a:1b:1c:1d:1e:1f", "aa:bb:cc:00:00:03", "aa:bb:cc:00:00:04"]      # no multicast or invalid MAC, no client without a MAC
    laptop = clients["1a:1b:1c:1d:1e:1f"]
    assert laptop["name"] == "Laptop of Sam" and laptop["ip"] == "192.168.0.101" and laptop["device_type"] == "pc" and laptop["os"] == "Windows"      # the client's name beats the lease's, the lease gives the address
    tv = clients["aa:bb:cc:00:00:03"]
    assert tv["name"] == "Living room TV" and tv["ip"] == "192.168.0.30" and tv["device_type"] == "tv" and tv["os"] == "Android"
    assert clients["aa:bb:cc:00:00:04"]["name"] == "printer" and clients["aa:bb:cc:00:00:04"]["device_type"] is None


def test_works_without_dhcp():
    r = dict(ROUTES)
    r["/control/dhcp/status"] = 404
    with Canned(r, auth=AUTH) as s:
        out = plugin.fetch(config(s))
    assert sorted(c["mac"] for c in out["clients"]) == ["1a:1b:1c:1d:1e:1f", "aa:bb:cc:00:00:03"]


def test_message(adguard):
    assert "AdGuard Home v0.107.79: 3 device(s)" in plugin.test(config(adguard))["message"]


def test_wrong_password_stops_retries(adguard):
    with pytest.raises(plugin.AuthRefused) as exc:
        plugin.fetch(config(adguard, password="nope"))
    assert exc.value.auth_failed


def test_unreachable_and_settings():
    with pytest.raises(plugin.AdguardError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 3})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": [{"host": "http://x:3000"}]})


def test_diagnose_has_only_counts(adguard):
    report = plugin.diagnose(config(adguard))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["dhcp"]["leases"] == 3 and steps["dhcp"]["static_leases"] == 1 and steps["clients"]["with_mac"] == 2 and steps["clients"]["id_kinds"] == {"mac": 2, "ip": 2, "other": 1}
    for secret in ("laptop", "Sam", "192.168", "aa:bb", "printer", "127.0.0.1", "pw"):
        assert secret not in text
