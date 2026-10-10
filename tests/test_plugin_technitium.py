"""The Technitium plugin against a simulated server: reading, writing, primary/secondary and cluster layouts, and the safety checks."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

from app.dns.plan import DnsDevice, DnsSettings, build_plan, parse_networks
from app.plugins.contract import validate_dns_results, validate_manifest, validate_output
from tests.fake_technitium import FakeTechnitium, a_record, ptr_record

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "technitium"
spec = importlib.util.spec_from_file_location("technitium_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

Z, R = "home.example.com", "0.168.192.in-addr.arpa"
MARK = "managed by Netlens"


def zones(kind="Primary"):
    return {
        Z: {"type": kind, "records": [a_record(f"nas.{Z}", "192.168.0.7", MARK), a_record(f"desktop-abc.{Z}", "192.168.0.20", "")]},
        R: {"type": kind, "records": [ptr_record(f"7.{R}", f"nas.{Z}", MARK)]},
    }


@pytest.fixture
def primary():
    with FakeTechnitium(token="tok1", zones=zones("Primary")) as s:
        yield s


@pytest.fixture
def pair():
    with FakeTechnitium(token="tok1", zones=zones("Primary")) as p, FakeTechnitium(token="tok2", zones=zones("Secondary")) as s:
        yield p, s


def config(*servers, tokens="tok1", **extra):
    return {"servers": ", ".join(s.url for s in servers), "tokens": tokens, "zones": [Z], "marker": MARK, "timeout": 5, **extra}


def change(action, rtype, name, value, old=None, zone=Z, cid=None):
    return {"id": cid or f"{action}:{rtype}:{name}", "action": action, "zone": zone, "name": name, "type": rtype, "value": value, "old_value": old, "comment": MARK}


# ---------------------------------------------------------------- reading
def test_manifest_and_snapshot_follow_the_contract(primary):
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "dns" and manifest["capabilities"] == ["delete", "marker"]
    snap = validate_output("dns", plugin.fetch(config(primary)))
    assert {z["name"]: (z["kind"], z["writable"]) for z in snap["zones"]} == {Z: ("forward", True), R: ("reverse", True)}      # the reverse zone is found by itself
    by_name = {(r["name"], r["type"]): r for r in snap["records"]}
    assert by_name[(f"nas.{Z}", "A")]["managed"] is True and by_name[(f"desktop-abc.{Z}", "A")]["managed"] is False
    assert by_name[(f"7.{R}", "PTR")]["value"] == f"nas.{Z}"
    assert not [r for r in snap["records"] if r["type"] in ("SOA", "NS")]            # only what matters for hosts


def test_a_server_that_does_not_return_comments_makes_every_record_look_foreign(primary):
    with FakeTechnitium(token="tok1", zones=zones(), comments_in_records=False) as old:
        snap = plugin.fetch(config(old))
    assert not any(r["managed"] for r in snap["records"])      # Netlens then relies on what it remembers writing (the tracking table)


def test_primary_and_secondary_the_zone_is_written_on_the_primary_only(pair):
    p, s = pair
    cfg = config(p, s, tokens="tok1, tok2")
    snap = plugin.fetch(cfg)
    assert all(z["writable"] for z in snap["zones"]) and snap["server"] == p.url.split("//")[1]
    results = plugin.apply(cfg, [change("add", "A", f"tv.{Z}", "192.168.0.9"), change("add", "PTR", f"9.{R}", f"tv.{Z}", zone=R)])
    assert all(r["ok"] for r in results)
    assert any(r["name"] == f"tv.{Z}" and r["comments"] == MARK for r in p.records(Z))
    assert not any(r["name"] == f"tv.{Z}" for r in s.records(Z))                 # the secondary gets it by zone transfer, not from us
    assert not any(path.endswith("/add") and params.get("zone")[0] == Z for path, params, _ in s.requests if "zone" in params)


def test_a_zone_held_only_as_secondary_is_read_only(primary):
    with FakeTechnitium(token="tok1", zones=zones("Secondary")) as secondary:
        snap = plugin.fetch(config(secondary))
        assert not any(z["writable"] for z in snap["zones"])
        out = plugin.apply(config(secondary), [change("add", "A", f"tv.{Z}", "192.168.0.9")])
        assert out[0]["ok"] is False and "read-only" in out[0]["error"]
        assert not any(r["name"] == f"tv.{Z}" for r in secondary.records(Z))


def test_cluster_the_primary_node_is_where_writes_go():
    with FakeTechnitium(token="t", zones=zones("Primary"), cluster={"type": "Primary", "name": "dns1.example.com"}) as node1, \
            FakeTechnitium(token="t", zones=zones("Secondary"), cluster={"type": "Secondary", "name": "dns2.example.com"}) as node2:
        cfg = config(node2, node1, tokens="t")                 # the order in the settings does not matter
        message = plugin.test({**cfg, "zones": [Z]})["message"]
        assert "cluster" in message and f"zone {Z} writable" in message and "1 reverse zone" in message
        assert all(r["ok"] for r in plugin.apply(cfg, [change("add", "A", f"tv.{Z}", "192.168.0.9")]))
        assert any(r["name"] == f"tv.{Z}" for r in node1.records(Z)) and not any(r["name"] == f"tv.{Z}" for r in node2.records(Z))


def test_two_independent_servers_are_both_written(pair):
    with FakeTechnitium(token="tok2", zones=zones("Primary")) as second:
        p, _ = pair
        out = plugin.apply(config(p, second, tokens="tok1, tok2"), [change("add", "A", f"tv.{Z}", "192.168.0.9")])
        assert out[0]["ok"] is True
        assert all(any(r["name"] == f"tv.{Z}" for r in s.records(Z)) for s in (p, second))


def test_connection_test_names_the_problems(primary):
    assert "zone nope.example.com NOT found" in plugin.test({**config(primary), "zones": ["nope.example.com"]})["message"]
    dead = "http://127.0.0.1:9"
    message = plugin.test({**config(primary), "servers": f"{primary.url}, {dead}", "tokens": "tok1"})["message"]
    assert "Connected to 1 server" in message and "not reachable" in message
    with pytest.raises(plugin.TechnitiumError):
        plugin.test({**config(primary), "servers": dead})


def test_a_refused_token_is_reported_as_an_authentication_failure(primary):
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.fetch(config(primary, tokens="wrong"))
    assert caught.value.auth_failed is True
    with pytest.raises(ValueError, match="one token for all"):
        plugin.fetch({**config(primary), "servers": f"{primary.url}, {primary.url}", "tokens": "a, b, c"})


# ---------------------------------------------------------------- writing
def test_add_update_and_delete(primary):
    cfg = config(primary)
    out = plugin.apply(cfg, [
        change("add", "A", f"tv.{Z}", "192.168.0.9"), change("add", "PTR", f"9.{R}", f"tv.{Z}", zone=R),
        change("update", "A", f"nas.{Z}", "192.168.0.77", old="192.168.0.7"), change("update", "PTR", f"7.{R}", f"nas2.{Z}", old=f"nas.{Z}", zone=R),
        change("delete", "A", f"nas.{Z}", "192.168.0.77"),
    ])
    assert [r["ok"] for r in out] == [True] * 5, out
    validate_dns_results(out, [c["id"] for c in out])
    names = {(r["name"], r["rData"].get("ipAddress") or r["rData"].get("ptrName")) for r in primary.records(Z) + primary.records(R) if r["type"] in ("A", "PTR")}
    assert (f"tv.{Z}", "192.168.0.9") in names and (f"9.{R}", f"tv.{Z}") in names and (f"7.{R}", f"nas2.{Z}") in names
    assert not any(n == f"nas.{Z}" for n, _ in names)
    add_call = next(p for path, p, _ in primary.requests if path.endswith("/records/add") and p["type"] == ["A"])
    assert add_call["ptr"] == ["false"] and add_call["comments"] == [MARK] and "ttl" not in add_call       # zone default TTL: none is sent


def test_an_add_is_refused_when_a_record_appeared_in_the_meantime(primary):
    out = plugin.apply(config(primary), [change("add", "A", f"desktop-abc.{Z}", "192.168.0.99")])      # a Windows machine registered itself first
    assert out[0]["ok"] is False and "in the meantime" in out[0]["error"]
    assert [r["rData"]["ipAddress"] for r in primary.records(Z) if r["name"] == f"desktop-abc.{Z}"] == ["192.168.0.20"]


def test_an_update_of_a_record_that_changed_is_refused_by_the_server(primary):
    out = plugin.apply(config(primary), [change("update", "A", f"desktop-abc.{Z}", "192.168.0.99", old="192.168.0.50")])
    assert out[0]["ok"] is False and "does not exist" in out[0]["error"]
    assert [r["rData"]["ipAddress"] for r in primary.records(Z) if r["name"] == f"desktop-abc.{Z}"] == ["192.168.0.20"]


def test_missing_permission_is_reported_per_change():
    with FakeTechnitium(token="tok1", zones=zones(), can_modify=False) as s:
        out = plugin.apply(config(s), [change("add", "A", f"tv.{Z}", "192.168.0.9")])
        assert out[0]["ok"] is False and "denied" in out[0]["error"].lower()


def test_unknown_zone_in_a_change_is_an_error_not_a_crash(primary):
    out = plugin.apply(config(primary), [change("add", "A", "x.other.org", "1.2.3.4", zone="other.org")])
    assert out[0]["ok"] is False and "primary zone" in out[0]["error"]


# ---------------------------------------------------------------- the whole loop with the engine
def test_plan_apply_and_plan_again_ends_with_nothing_to_do(primary):
    cfg = config(primary)
    st = DnsSettings(networks=parse_networks(f"192.168.0.0/24 = {Z}"), grace_hours=0)
    devices = [
        DnsDevice(1, "192.168.0.7", hostname="nas"),                                    # registered by Netlens already
        DnsDevice(2, "192.168.0.20", hostname="desktop-abc"),                           # the Windows machine registered itself
        DnsDevice(3, "192.168.0.30", hostname="printer"),                               # missing
        DnsDevice(4, "192.168.0.40", hostname=None, type="tv", vendor="Samsung", mac="aa:bb:cc:00:a1:b2"),   # nameless
    ]
    now = "2026-10-10T12:00:00Z"
    first = build_plan(devices, validate_output("dns", plugin.fetch(cfg)), st, now)
    states = {i["device_id"]: i["state"] for i in first["items"] if i["device_id"]}
    assert states == {1: "ok", 2: "self", 3: "add", 4: "add"}
    changes = [c for i in first["items"] for c in i["changes"]]
    results = plugin.apply(cfg, changes)
    assert all(r["ok"] for r in results), results
    second = build_plan(devices, validate_output("dns", plugin.fetch(cfg)), st, now)
    assert {i["device_id"]: i["state"] for i in second["items"] if i["device_id"]} == {1: "ok", 2: "self", 3: "ok", 4: "ok"}
    assert [r["rData"]["ipAddress"] for r in primary.records(Z) if r["name"] == f"desktop-abc.{Z}"] == ["192.168.0.20"]     # untouched
    # the printer's address changes (DHCP): its own record follows, the Windows machine's is still not touched
    devices[2].ip = "192.168.0.31"
    third = build_plan(devices, validate_output("dns", plugin.fetch(cfg)), st, now)
    move = next(i for i in third["items"] if i["device_id"] == 3)
    assert move["state"] == "update" and move["changes"][0]["old_value"] == "192.168.0.30"
    assert all(r["ok"] for r in plugin.apply(cfg, move["changes"]))
    assert {i["state"] for i in build_plan(devices, validate_output("dns", plugin.fetch(cfg)), st, now)["items"] if i["device_id"] == 3} == {"ok"}


# ---------------------------------------------------------------- diagnostic
def test_the_diagnostic_counts_things_and_leaks_nothing(pair):
    p, s = pair
    report = plugin.diagnose(config(p, s, tokens="tok1, tok2"))
    text = json.dumps(report)
    assert report["servers"][0]["zones"]["primary"] == 2 and report["servers"][1]["zones"]["secondary"] == 2
    assert report["servers"][0]["steps"]["records"]["comments_returned"] is True and report["servers"][0]["steps"]["dynamic_updates"]["policy"] == "Deny"
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text) and "tok1" not in text and "nas" not in text and "desktop" not in text
    assert plugin.diagnose({"servers": "", "tokens": "x"})["error"].startswith("enter the address")


def test_cname_add_replace_and_delete(primary):
    cfg = {"servers": primary.url, "tokens": "tok1", "zones": [Z], "marker": MARK}
    change = lambda action, value, old=None: {"id": "c:" + action, "action": action, "zone": Z, "name": f"web.{Z}", "type": "CNAME", "value": value, "old_value": old, "comment": MARK}
    assert plugin.apply(cfg, [change("add", f"host.{Z}")])[0]["ok"]
    rows = [r for r in plugin.fetch(cfg)["records"] if r["name"] == f"web.{Z}"]
    assert [(r["type"], r["value"], r["managed"]) for r in rows] == [("CNAME", f"host.{Z}", True)]
    assert plugin.apply(cfg, [change("update", f"other.{Z}", f"host.{Z}")])[0]["ok"]
    assert [r["value"] for r in plugin.fetch(cfg)["records"] if r["name"] == f"web.{Z}"] == [f"other.{Z}"]
    # a record that changed meanwhile is not replaced
    assert not plugin.apply(cfg, [change("update", f"x.{Z}", f"host.{Z}")])[0]["ok"]
    assert plugin.apply(cfg, [change("delete", f"other.{Z}")])[0]["ok"]
    assert not [r for r in plugin.fetch(cfg)["records"] if r["name"] == f"web.{Z}"]
