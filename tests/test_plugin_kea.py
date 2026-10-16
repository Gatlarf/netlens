"""The Kea plugin against a simulated Control Agent (answers recorded from a real Kea 2.6.3 on 2026-10-16)."""

import importlib.util
import json
import time
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_kea import FakeKea

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "kea"
spec = importlib.util.spec_from_file_location("kea_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

NOW = int(time.time())


def lease(ip, mac, hostname="", state=0, cltt=NOW, lft=4000):
    return {"cltt": cltt, "fqdn-fwd": False, "fqdn-rev": False, "hostname": hostname, "hw-address": mac, "ip-address": ip, "state": state, "subnet-id": 1, "valid-lft": lft}


LEASES = [lease("192.168.77.101", "1a:1b:1c:1d:1e:1f", "laptop.lab"), lease("192.168.77.102", "2a:2b:2c:2d:2e:2f"),
          lease("192.168.77.150", "3a:3b:3c:3d:3e:3f", "old.lab", cltt=NOW - 9000), lease("192.168.77.160", "4a:4b:4c:4d:4e:4f", "bad.lab", state=1)]
RESERVATIONS = [{"hw-address": "aa:bb:cc:00:00:01", "ip-address": "192.168.77.10", "hostname": "printer"}, {"duid": "01:02", "ip-address": "192.168.77.11"},
                {"hw-address": "1a:1b:1c:1d:1e:1f", "ip-address": "192.168.77.101", "hostname": "laptop-fixed"}]


@pytest.fixture
def kea():
    with FakeKea(LEASES, RESERVATIONS) as s:
        yield s


def config(s, password="labpass", **extra):
    return {"servers": [{"host": s.url, "user": "netlens", "password": password}], "timeout": 5, **extra}


def test_manifest_and_clients_follow_the_contract(kea):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(kea)))
    assert out["nodes"] == []
    by_mac = {c["mac"]: c for c in out["clients"]}
    assert sorted(by_mac) == ["1a:1b:1c:1d:1e:1f", "2a:2b:2c:2d:2e:2f", "aa:bb:cc:00:00:01"]       # expired and declined leases left out, a reservation by DUID is skipped
    assert by_mac["1a:1b:1c:1d:1e:1f"]["name"] == "laptop.lab" and by_mac["1a:1b:1c:1d:1e:1f"]["ip"] == "192.168.77.101"      # the lease wins over the reservation
    assert by_mac["2a:2b:2c:2d:2e:2f"]["name"] is None
    assert by_mac["aa:bb:cc:00:00:01"]["name"] == "printer"


def test_reservations_can_be_left_out(kea):
    out = plugin.fetch(config(kea, reservations=False))
    assert "config-get" not in kea.seen
    assert sorted(c["mac"] for c in out["clients"]) == ["1a:1b:1c:1d:1e:1f", "2a:2b:2c:2d:2e:2f"]


def test_test_message(kea):
    message = plugin.test(config(kea))["message"]
    assert "Kea 2.6.3" in message and "3 device(s)" in message and "1 only reserved" in message and "2 expired" in message


def test_wrong_password_stops_retries(kea):
    with pytest.raises(plugin.AuthRefused) as exc:
        plugin.fetch(config(kea, password="nope"))
    assert exc.value.auth_failed


def test_missing_lease_hook_is_explained():
    with FakeKea(LEASES, unsupported=["lease4-get-all"]) as s:
        with pytest.raises(plugin.KeaError, match="lease_cmds"):
            plugin.fetch(config(s))


def test_no_leases_is_not_an_error():
    with FakeKea([]) as s:
        assert plugin.fetch(config(s, reservations=False)) == {"nodes": [], "clients": []}


def test_unreachable_server():
    with pytest.raises(plugin.KeaError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1"}], "timeout": 3})


def test_settings_are_checked():
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": [{"user": "x"}]})


def test_diagnose_has_only_counts(kea):
    report = plugin.diagnose(config(kea))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["leases"]["count"] == 4 and steps["leases"]["with_hostname"] == 3 and steps["reservations"]["count"] == 2
    for secret in ("laptop", "192.168", "1a:1b", "printer", "127.0.0.1"):
        assert secret not in text
