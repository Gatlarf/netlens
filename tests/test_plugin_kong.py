"""The Kong plugin against canned answers (shapes recorded from Kong 3.9.4 DB-less on 2026-10-16; the TCP route follows the Kong documentation)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "kong"
spec = importlib.util.spec_from_file_location("kong_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

SERVICES = {"data": [
    {"id": "s1", "name": "whoami", "host": "whoami", "port": 80, "protocol": "http", "enabled": True},
    {"id": "s2", "name": "api", "host": "192.168.0.7", "port": 8443, "protocol": "https", "enabled": True},
    {"id": "s3", "name": "off", "host": "192.168.0.8", "port": 80, "protocol": "http", "enabled": False},
    {"id": "s4", "name": "pg", "host": "192.168.0.30", "port": 5432, "protocol": "tcp", "enabled": True}], "next": None}
ROUTES = {"data": [
    {"id": "r1", "name": "who", "hosts": ["Who.Example.com"], "protocols": ["http", "https"], "service": {"id": "s1"}},
    {"id": "r2", "name": "api", "hosts": ["*.api.example.com"], "protocols": ["https"], "service": {"id": "s2"}},
    {"id": "r3", "name": "off", "hosts": ["off.example.com"], "protocols": ["http"], "service": {"id": "s3"}},
    {"id": "r4", "name": "pg", "protocols": ["tcp"], "destinations": [{"port": 15432}], "service": {"id": "s4"}},
    {"id": "r5", "name": "rpc", "hosts": ["rpc.example.com"], "protocols": ["grpc"], "service": {"id": "s1"}},
    {"id": "r6", "name": "orphan", "hosts": ["orphan.example.com"], "protocols": ["http"], "service": None}], "next": None}
ROUTES_ALL = {"/": {"version": "3.9.4", "hostname": "kong1", "configuration": {"database": "off"}}, "/services": SERVICES, "/routes": ROUTES}


def config(url, **row):
    return {"servers": [{"host": url, "lan": "192.168.0.4", **row}], "timeout": 5}


def test_manifest_and_sites_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    with Canned(ROUTES_ALL) as s:
        out = validate_output("proxy", plugin.fetch(config(s.url)))
    assert (out["proxies"][0]["ip"], out["proxies"][0]["version"]) == ("192.168.0.4", "3.9.4")
    sites = {x["name"]: x for x in out["sites"]}
    assert "rpc" not in sites                                                                         # gRPC routes are skipped
    who = sites["who"]
    assert who["domains"] == ["who.example.com"] and (who["forward_host"], who["forward_port"], who["scheme"], who["ssl"]) == ("whoami", 80, "http", True)
    assert (sites["api"]["scheme"], sites["api"]["forward_port"]) == ("https", 8443) and sites["off"]["enabled"] is False
    pg = sites["pg"]
    assert (pg["type"], pg["incoming_port"], pg["forward_host"], pg["forward_port"]) == ("stream", 15432, "192.168.0.30", 5432)
    assert sites["orphan"]["type"] == "dead"


def test_paged_lists_follow_the_offset():
    class Fake(plugin.Admin):
        def get(self, path, **params):
            return {"data": [{"id": "a"}, {"id": "b"}], "offset": "next"} if not params.get("offset") else {"data": [{"id": "c"}], "offset": None}

    assert [r["id"] for r in Fake("http://127.0.0.1:1").paged("/routes")] == ["a", "b", "c"]


def test_message_diagnose_and_refused_token():
    with Canned(ROUTES_ALL) as s:
        assert "Connected to 1 Kong (3.9.4): 5 route(s)" in plugin.test(config(s.url))["message"]
        text = json.dumps(plugin.diagnose(config(s.url)))
    assert "192.168" not in text and "example.com" not in text and '"database": "off"' in text
    with Canned({"/": 403}) as s, pytest.raises(plugin.AuthRefused):
        plugin.test(config(s.url, token="t"))
