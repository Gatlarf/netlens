"""The DNS plugin kind: manifest capabilities, the snapshot a plugin returns, and the apply() answers."""

import textwrap

import pytest

from app.plugins.contract import ContractError, validate_dns_results, validate_manifest, validate_output
from app.plugins.registry import discover
from app.plugins.runner import run_subprocess
from tests.plugin_helpers import write_plugin

MANIFEST = {"id": "dnsdemo", "name": "Demo DNS", "version": "1.0.0", "api_version": 1, "kind": "dns", "capabilities": ["delete", "marker", "marker"]}


def snapshot(**extra):
    base = {
        "zones": [{"name": "Home.Example.com.", "kind": "forward", "writable": True}, {"name": "0.168.192.in-addr.arpa", "kind": "reverse"}],
        "records": [
            {"zone": "home.example.com", "name": "NAS.Home.Example.com.", "type": "a", "value": "192.168.0.7", "ttl": 3600, "managed": True, "comment": "managed by Netlens"},
            {"zone": "0.168.192.in-addr.arpa", "name": "7.0.168.192.in-addr.arpa", "type": "PTR", "value": "Nas.Home.Example.com.", "managed": False},
        ],
        "server": "dns1",
    }
    base.update(extra)
    return base


def test_manifest_capabilities():
    manifest = validate_manifest(MANIFEST)
    assert manifest["kind"] == "dns" and manifest["capabilities"] == ["delete", "marker"]
    assert validate_manifest({**MANIFEST, "kind": "topology", "capabilities": None})["capabilities"] == []
    with pytest.raises(ContractError, match="only a dns plugin"):
        validate_manifest({**MANIFEST, "kind": "topology", "capabilities": ["marker"]})
    with pytest.raises(ContractError, match="not one of"):
        validate_manifest({**MANIFEST, "capabilities": ["format-c"]})


def test_snapshot_is_normalised():
    out = validate_output("dns", snapshot())
    assert [z["name"] for z in out["zones"]] == ["home.example.com", "0.168.192.in-addr.arpa"]
    a, ptr = out["records"]
    assert (a["name"], a["type"], a["managed"]) == ("nas.home.example.com", "A", True)
    assert ptr["value"] == "nas.home.example.com" and ptr["managed"] is False       # names are compared in lower case without the final dot
    assert out["server"] == "dns1"


@pytest.mark.parametrize("change,message", [
    ({"zones": [{"name": "a.com"}, {"name": "A.com."}]}, "listed twice"),
    ({"zones": [{"name": "a.com", "kind": "sideways"}]}, "forward or reverse"),
    ({"records": [{"zone": "other.com", "name": "x.other.com", "type": "A", "value": "1.2.3.4"}]}, "not one of the zones"),
    ({"records": [{"zone": "home.example.com", "name": "x", "type": "A", "value": "1.2.3.4", "ttl": -5}]}, "whole number"),
])
def test_bad_snapshots_are_refused(change, message):
    with pytest.raises(ContractError, match=message):
        validate_output("dns", snapshot(**change))


def test_apply_results():
    ok = validate_dns_results([{"id": "a", "ok": True}, {"id": "b", "ok": False, "error": "zone is read-only"}], ["a", "b", "c"])
    assert ok == [{"id": "a", "ok": True, "error": None}, {"id": "b", "ok": False, "error": "zone is read-only"},
                  {"id": "c", "ok": False, "error": "the plugin gave no answer for this change"}]
    with pytest.raises(ContractError, match="was not asked for"):
        validate_dns_results([{"id": "zzz", "ok": True}], ["a"])
    with pytest.raises(ContractError, match="twice"):
        validate_dns_results([{"id": "a", "ok": True}, {"id": "a", "ok": True}], ["a"])


def test_apply_receives_its_changes_in_the_real_worker(tmp_path):
    write_plugin(tmp_path, "demo", py=textwrap.dedent('''
        def test(config):
            return {"message": "ok"}
        def fetch(config):
            return {"zones": [], "records": []}
        def apply(config, changes):
            return [{"id": c["id"], "ok": c["action"] == "add"} for c in changes]
    '''), kind="dns")
    plugin = discover(tmp_path)["demo"]
    out = run_subprocess(plugin, "apply", {"x": 1}, payload=[{"id": "1", "action": "add"}, {"id": "2", "action": "delete"}])
    assert out == [{"id": "1", "ok": True}, {"id": "2", "ok": False}]
