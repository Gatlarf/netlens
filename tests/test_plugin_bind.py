"""The BIND plugin against a simulated BIND (AXFR and RFC 2136 UPDATE with TSIG, behaviour checked against a real BIND 9.20 on 2026-10-16)."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_bind import FakeBind

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "bind"
spec = importlib.util.spec_from_file_location("bind_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

SECRET = b"secret-for-tests-0123456789abcdef"
Z, R = "home.lan", "0.168.192.in-addr.arpa"


def zones():
    return {Z: [("nas.home.lan", "A", "192.168.0.7", 3600), ("printer.home.lan", "A", "192.168.0.9", 300), ("www.home.lan", "CNAME", "nas.home.lan", 3600)],
            R: [("7.0.168.192.in-addr.arpa", "PTR", "nas.home.lan", 3600)]}


@pytest.fixture
def bind():
    with FakeBind(secret=SECRET, zones=zones()) as s:
        yield s


def config(s, secret=SECRET, name="netlens-key"):
    return {"servers": [{"host": s.address, "key_name": name, "key_secret": base64.b64encode(secret).decode()}], "zones": [Z], "reverse_zones": R, "timeout": 5}


def change(action, rtype, name, value, old=None, zone=Z, cid="c"):
    return {"id": cid, "action": action, "zone": zone, "name": name, "type": rtype, "value": value, "old_value": old, "comment": "x"}


def test_manifest_and_snapshot_follow_the_contract(bind):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "dns"
    snap = validate_output("dns", plugin.fetch(config(bind)))
    assert {z["name"]: (z["kind"], z["writable"]) for z in snap["zones"]} == {Z: ("forward", True), R: ("reverse", True)}
    assert {(r["name"], r["type"], r["value"]) for r in snap["records"]} == {("nas.home.lan", "A", "192.168.0.7"), ("printer.home.lan", "A", "192.168.0.9"),
                                                                              ("www.home.lan", "CNAME", "nas.home.lan"), ("7.0.168.192.in-addr.arpa", "PTR", "nas.home.lan")}
    assert not any(r["managed"] for r in snap["records"])


def test_prerequisites_make_every_change_safe(bind):
    result = plugin.apply(config(bind), [
        change("add", "A", "new.home.lan", "192.168.0.50", cid="1"),
        change("add", "A", "nas.home.lan", "192.168.0.99", cid="2"),                           # name in use: YXDOMAIN
        change("add", "PTR", f"50.{R}", "new.home.lan", zone=R, cid="3"),
        change("add", "AAAA", "v6.home.lan", "fd00::7", cid="4"),
        change("update", "A", "new.home.lan", "192.168.0.51", old="192.168.0.50", cid="5"),
        change("update", "A", "new.home.lan", "192.168.0.52", old="192.168.0.99", cid="6"),    # the old value is not there: NXRRSET
        change("delete", "A", "new.home.lan", "192.168.0.51", cid="7"),
        change("delete", "A", "ghost.home.lan", "1.1.1.1", cid="8"),                           # already gone is success
        change("delete", "TXT", "x.home.lan", "no", cid="9"),
    ])
    assert [(r["id"], r["ok"]) for r in result] == [("1", True), ("2", False), ("3", True), ("4", True), ("5", True), ("6", False), ("7", True), ("8", True), ("9", False)]
    assert "got a record in the meantime" in result[1]["error"] and "no longer points to 192.168.0.99" in result[5]["error"]
    records = {(n, t, v) for n, t, v, _ in bind.zones[Z]}
    assert ("new.home.lan", "A", "192.168.0.51") not in records and ("v6.home.lan", "AAAA", "fd00::7") in records
    assert ("nas.home.lan", "A", "192.168.0.7") in records and ("printer.home.lan", "A", "192.168.0.9") in records
    assert ("50.0.168.192.in-addr.arpa", "PTR", "new.home.lan", 3600) in bind.zones[R]


def test_wrong_key_and_read_only_key(bind):
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(bind, secret=b"another-secret-another-secret-12"))
    assert caught.value.auth_failed is True
    with FakeBind(secret=SECRET, zones=zones(), deny_update=True) as s:
        snap = plugin.fetch(config(s))
        assert all(z["writable"] is False for z in snap["zones"])
        assert plugin.apply(config(s), [change("add", "A", "x.home.lan", "1.2.3.4")])[0]["ok"] is False


def test_message_and_diagnose(bind):
    assert "zone home.lan: 3 record(s), writable, zone 0.168.192.in-addr.arpa: 1 record(s), writable" in plugin.test(config(bind))["message"]
    text = json.dumps(plugin.diagnose(config(bind)))
    assert "nas" not in text and "192.168" not in text and '"update_allowed": true' in text and '"A": 2' in text


def test_wire_helpers():
    assert plugin.encode_name("Nas.Home.LAN.") == b"\x03nas\x04home\x03lan\x00"
    buf = b"\x04home\x00\x03nas\xc0\x00"
    assert plugin.read_name(buf, 6) == ("nas.home", 12)
    with pytest.raises(plugin.BindError):
        plugin.read_name(b"\xc0\x00", 0)                 # a pointer to itself
    with pytest.raises(plugin.BindError):
        plugin.Key("k", "not base64!!")
