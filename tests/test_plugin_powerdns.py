"""The PowerDNS plugin against a simulated server (behaviour recorded from PowerDNS Authoritative 4.9.17)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_powerdns import FakePowerdns, rrset

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "powerdns"
spec = importlib.util.spec_from_file_location("powerdns_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

Z, R, M = "home.lan", "0.168.192.in-addr.arpa", "managed by Netlens"


def zones(kind="Native"):
    return {f"{Z}.": {"kind": kind, "rrsets": [rrset(f"nas.{Z}.", "A", ["192.168.0.7"], comment=M), rrset(f"printer.{Z}.", "A", ["192.168.0.9"], 300),
                                                rrset(f"multi.{Z}.", "A", ["192.168.0.20", "192.168.0.21"], comment=M), rrset(f"{Z}.", "SOA", ["a. b. 1 2 3 4 5"]), rrset(f"{Z}.", "NS", [f"ns1.{Z}."])]},
            f"{R}.": {"kind": kind, "rrsets": [rrset(f"7.{R}.", "PTR", [f"nas.{Z}."], comment=M)]}}


@pytest.fixture
def server():
    with FakePowerdns(key="k", zones=zones()) as s:
        yield s


def config(s, key="k"):
    return {"servers": [{"host": s.url, "api_key": key}], "zones": [Z], "timeout": 5}


def change(action, rtype, name, value, old=None, zone=Z, cid="c"):
    return {"id": cid, "action": action, "zone": zone, "name": name, "type": rtype, "value": value, "old_value": old, "comment": M}


def stored(s, zone, name, rtype):
    return next((r for r in s.zones[zone]["rrsets"] if r["name"] == name and r["type"] == rtype), None)


def test_manifest_and_snapshot_follow_the_contract(server):
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "dns" and manifest["capabilities"] == ["delete", "marker"]
    snap = validate_output("dns", plugin.fetch(config(server)))
    assert {z["name"]: (z["kind"], z["writable"]) for z in snap["zones"]} == {Z: ("forward", True), R: ("reverse", True)}
    by = {(r["name"], r["type"], r["value"]): r for r in snap["records"]}
    assert by[(f"nas.{Z}", "A", "192.168.0.7")]["managed"] is True and by[(f"printer.{Z}", "A", "192.168.0.9")]["managed"] is False
    assert by[(f"7.{R}", "PTR", f"nas.{Z}")]["managed"] is True and not [r for r in snap["records"] if r["type"] in ("SOA", "NS")]


def test_add_update_delete_with_the_safety_checks(server):
    cfg = config(server)
    result = plugin.apply(cfg, [
        change("add", "A", f"new.{Z}", "192.168.0.50", cid="1"),
        change("add", "A", f"nas.{Z}", "192.168.0.99", cid="2"),                            # taken
        change("add", "PTR", f"50.{R}", f"new.{Z}", zone=R, cid="3"),
        change("update", "A", f"nas.{Z}", "192.168.0.70", old="192.168.0.7", cid="4"),
        change("update", "A", f"printer.{Z}", "192.168.0.2", old="192.168.0.9", cid="5"),   # not ours
        change("update", "A", f"multi.{Z}", "192.168.0.22", old="192.168.0.20", cid="6"),   # a set with other records
        change("delete", "A", f"new.{Z}", "192.168.0.50", cid="7"),
        change("delete", "A", f"printer.{Z}", "192.168.0.9", cid="8"),                      # not ours
        change("delete", "A", f"multi.{Z}", "192.168.0.20", cid="9"),
        change("delete", "A", f"ghost.{Z}", "1.1.1.1", cid="10"),                           # nothing to delete is success
    ])
    assert [(r["id"], r["ok"]) for r in result] == [("1", True), ("2", False), ("3", True), ("4", True), ("5", False), ("6", False), ("7", True), ("8", False), ("9", False), ("10", True)]
    z = f"{Z}."
    assert stored(server, z, f"nas.{Z}.", "A")["records"][0]["content"] == "192.168.0.70" and stored(server, z, f"nas.{Z}.", "A")["comments"][0]["content"] == M
    assert stored(server, z, f"new.{Z}.", "A") is None and stored(server, z, f"printer.{Z}.", "A")["records"][0]["content"] == "192.168.0.9"
    assert len(stored(server, z, f"multi.{Z}.", "A")["records"]) == 2
    ptr = stored(server, f"{R}.", f"50.{R}.", "PTR")
    assert ptr["records"][0]["content"] == f"new.{Z}." and ptr["ttl"] == 3600


def test_login_secondary_zone_and_diagnose(server):
    assert "zone home.lan writable, 1 reverse zone(s)" in plugin.test(config(server))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(server, "wrong"))
    assert caught.value.auth_failed is True
    text = json.dumps(plugin.diagnose(config(server)))
    assert "192.168" not in text and "nas" not in text and '"marked": 2' in text and '"multi_record_sets": 1' in text
    with FakePowerdns(key="k", zones=zones("Slave")) as s:
        assert plugin.fetch(config(s))["zones"][0]["writable"] is False
        assert plugin.apply(config(s), [change("add", "A", f"x.{Z}", "1.2.3.4")])[0]["ok"] is False
    with FakePowerdns(key="k", zones=zones(), daemon="recursor") as s, pytest.raises(plugin.PowerdnsError):
        plugin.test(config(s))
