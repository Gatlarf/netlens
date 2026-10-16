"""The Pi-hole plugin against a simulated Pi-hole v6 (behaviour recorded from a real Pi-hole 6.4.3)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_pihole import FakePihole

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "pihole"
spec = importlib.util.spec_from_file_location("pihole_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

Z = "home.lan"


@pytest.fixture
def pihole():
    with FakePihole(password="pw", hosts=["192.168.0.7 nas.home.lan", "192.168.0.8 a.home.lan b.home.lan", "10.0.0.1 other.example"], cnames=["files.home.lan,nas.home.lan"]) as s:
        yield s


def config(s, password="pw"):
    return {"servers": [{"host": s.url, "password": password}], "zones": [Z], "timeout": 5}


def change(action, rtype, name, value, old=None, cid="c"):
    return {"id": cid, "action": action, "zone": Z, "name": name, "type": rtype, "value": value, "old_value": old, "comment": "managed by Netlens"}


def test_manifest_and_snapshot_follow_the_contract(pihole):
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "dns"
    snap = validate_output("dns", plugin.fetch(config(pihole)))
    assert [(z["name"], z["kind"], z["writable"]) for z in snap["zones"]] == [(Z, "forward", True)]
    found = {(r["name"], r["type"], r["value"]) for r in snap["records"]}
    assert found == {("nas.home.lan", "A", "192.168.0.7"), ("a.home.lan", "A", "192.168.0.8"), ("b.home.lan", "A", "192.168.0.8"), ("files.home.lan", "CNAME", "nas.home.lan")}
    assert not any(r["managed"] for r in snap["records"])        # Pi-hole has no comments: Netlens relies on what it remembers
    assert pihole.logins == pihole.logouts == 1                  # one login, and a logout


def test_message_and_bad_password(pihole):
    assert "Connected to 1 Pi-hole(s), version v6.4.3, 4 Local DNS record(s)" in plugin.test(config(pihole))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(pihole, "wrong"))
    assert caught.value.auth_failed is True


def test_add_update_delete_and_the_safety_checks(pihole):
    cfg = config(pihole)
    result = plugin.apply(cfg, [
        change("add", "A", "new.home.lan", "192.168.0.50", cid="1"),
        change("add", "A", "nas.home.lan", "192.168.0.99", cid="2"),                # taken in the meantime
        change("add", "CNAME", "wiki.home.lan", "nas.home.lan", cid="3"),
        change("add", "PTR", "50.0.168.192.in-addr.arpa", "new.home.lan", cid="4"),  # Pi-hole makes PTR itself
        change("update", "A", "nas.home.lan", "192.168.0.70", old="192.168.0.7", cid="5"),
        change("update", "A", "nas.home.lan", "192.168.0.71", old="192.168.0.123", cid="6"),   # it no longer has that value
        change("delete", "A", "new.home.lan", "192.168.0.50", cid="7"),
        change("delete", "A", "gone.home.lan", "1.2.3.4", cid="8"),                 # nothing to delete is success
    ])
    assert [(r["id"], r["ok"]) for r in result] == [("1", True), ("2", False), ("3", True), ("4", False), ("5", True), ("6", False), ("7", True), ("8", True)]
    assert "got a record in the meantime" in result[1]["error"] and "no longer points to" in result[5]["error"]
    assert "192.168.0.70 nas.home.lan" in pihole.hosts and "192.168.0.7 nas.home.lan" not in pihole.hosts
    assert "192.168.0.50 new.home.lan" not in pihole.hosts and "wiki.home.lan,nas.home.lan" in pihole.cnames
    assert pihole.logins == pihole.logouts


def test_diagnose_has_counts_only(pihole):
    report = plugin.diagnose(config(pihole))
    text = json.dumps(report)
    assert report["servers"][0]["steps"]["hosts"] == {"ok": True, "count": 3} and report["servers"][0]["records_in_your_zones"] == 4
    assert "nas" not in text and "192.168" not in text
