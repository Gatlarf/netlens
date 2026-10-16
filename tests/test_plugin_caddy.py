"""The Caddy plugin against canned answers (shapes recorded from Caddy 2.11.7 on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "caddy"
spec = importlib.util.spec_from_file_location("caddy_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def sub(*handlers):
    return [{"handler": "subroute", "routes": [{"handle": list(handlers)}]}]


SERVERS = {
    "srv0": {"listen": [":443"], "routes": [
        {"match": [{"host": ["app.example.com", "www.example.com"]}], "handle": sub({"handler": "reverse_proxy", "upstreams": [{"dial": "whoami:80"}]})},
        {"match": [{"host": ["secure.example.com"]}], "handle": sub({"handler": "encode"}, {"handler": "reverse_proxy", "upstreams": [{"dial": "192.168.0.20:8443"}], "transport": {"protocol": "http", "tls": {}}})},
        {"match": [{"host": ["old.example.com"]}], "handle": sub({"handler": "static_response", "headers": {"Location": ["https://app.example.com{http.request.uri}"]}, "status_code": 301})},
        {"match": [{"host": ["files.example.com"]}], "handle": sub({"handler": "file_server"})},
        {"handle": sub({"handler": "static_response", "body": "hello"})},
    ]},
    "plain": {"listen": [":8089"], "automatic_https": {"disable": True}, "routes": [{"match": [{"host": ["lab.lan"]}], "handle": sub({"handler": "reverse_proxy", "upstreams": [{"dial": "10.0.0.5"}]})}]},
}


def config(url):
    return {"servers": [{"host": url, "lan": "192.168.0.4"}], "timeout": 5}


def test_manifest_and_sites_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    with Canned({"/config/apps/http/servers": SERVERS, "/config/apps/tls": {"automation": {}}}) as s:
        out = validate_output("proxy", plugin.fetch(config(s.url)))
    assert out["proxies"][0]["ip"] == "192.168.0.4"
    sites = {x["id"]: x for x in out["sites"]}
    assert sorted(sites) == ["plain/0", "srv0/0", "srv0/1", "srv0/2"]                                  # file servers and routes without a host are no sites
    app = sites["srv0/0"]
    assert app["domains"] == ["app.example.com", "www.example.com"] and (app["forward_host"], app["forward_port"], app["ssl"]) == ("whoami", 80, True)
    assert (sites["srv0/1"]["scheme"], sites["srv0/1"]["forward_port"]) == ("https", 8443)
    assert sites["srv0/2"]["type"] == "redirect" and sites["srv0/2"]["redirect_to"].startswith("https://app.example.com")
    assert sites["plain/0"]["ssl"] is False and sites["plain/0"]["forward_port"] == 80 and sites["plain/0"]["incoming_port"] == 8089


def test_message_and_errors():
    with Canned({"/config/apps/http/servers": SERVERS}) as s:
        assert "4 site(s) (3 proxy, 1 redirect)" in plugin.test(config(s.url))["message"]
        report = json.dumps(plugin.diagnose(config(s.url)))
        assert "example.com" not in report and '"routes": 6' in report
    with Canned({}) as s, pytest.raises(plugin.CaddyError):
        plugin.test(config(s.url))
