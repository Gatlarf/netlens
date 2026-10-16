"""The AdGuard Home plugin against a simulated server (behaviour recorded from AdGuard Home v0.107.79)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_adguard import FakeAdguard

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "adguard"
spec = importlib.util.spec_from_file_location("adguard_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

Z = "home.lan"
ROWS = [
    {"domain": "nas.home.lan", "answer": "192.168.0.7", "enabled": True},
    {"domain": "files.home.lan", "answer": "nas.home.lan", "enabled": True},
    {"domain": "v6.home.lan", "answer": "fd00::7", "enabled": True},
    {"domain": "off.home.lan", "answer": "192.168.0.9", "enabled": False},
    {"domain": "*.home.lan", "answer": "192.168.0.1", "enabled": True},
    {"domain": "block.home.lan", "answer": "A", "enabled": True},
    {"domain": "other.example", "answer": "10.0.0.1", "enabled": True},
]


@pytest.fixture
def adguard():
    with FakeAdguard(rewrites=ROWS) as s:
        yield s


def config(s, password="pw"):
    return {"servers": [{"host": s.url, "username": "admin", "password": password}], "zones": [Z], "timeout": 5}


def change(action, rtype, name, value, old=None, cid="c"):
    return {"id": cid, "action": action, "zone": Z, "name": name, "type": rtype, "value": value, "old_value": old, "comment": "managed by Netlens"}


def test_manifest_and_snapshot_follow_the_contract(adguard):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "dns"
    snap = validate_output("dns", plugin.fetch(config(adguard)))
    assert {(r["name"], r["type"], r["value"]) for r in snap["records"]} == {("nas.home.lan", "A", "192.168.0.7"), ("files.home.lan", "CNAME", "nas.home.lan"), ("v6.home.lan", "AAAA", "fd00::7")}
    assert [z["name"] for z in snap["zones"]] == [Z] and not any(r["managed"] for r in snap["records"])


def test_message_and_bad_password(adguard):
    assert "version v0.107.79, 3 DNS rewrite(s) in your zone(s)" in plugin.test(config(adguard))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(adguard, "wrong"))
    assert caught.value.auth_failed is True


def test_changes_are_checked_because_adguard_answers_200_to_everything(adguard):
    result = plugin.apply(config(adguard), [
        change("add", "A", "new.home.lan", "192.168.0.50", cid="1"),
        change("add", "A", "nas.home.lan", "192.168.0.99", cid="2"),                 # taken: not written
        change("update", "A", "nas.home.lan", "192.168.0.70", old="192.168.0.7", cid="3"),
        change("update", "A", "nas.home.lan", "192.168.0.71", old="192.168.0.123", cid="4"),
        change("delete", "A", "new.home.lan", "192.168.0.50", cid="5"),
        change("add", "PTR", "50.0.168.192.in-addr.arpa", "new.home.lan", cid="6"),
    ])
    assert [(r["id"], r["ok"]) for r in result] == [("1", True), ("2", False), ("3", True), ("4", False), ("5", True), ("6", False)]
    answers = {(r["domain"], r["answer"]) for r in adguard.rewrites}
    assert ("nas.home.lan", "192.168.0.70") in answers and ("nas.home.lan", "192.168.0.7") not in answers and ("new.home.lan", "192.168.0.50") not in answers


def test_diagnose_has_counts_only(adguard):
    report = plugin.diagnose(config(adguard))
    step = report["servers"][0]["steps"]["rewrites"]
    assert step["count"] == 7 and step["kinds"]["A"] >= 3 and step["in_your_zones"] == 3
    assert "nas" not in json.dumps(report) and "192.168" not in json.dumps(report)
