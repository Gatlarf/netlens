"""The Traefik plugin against canned answers (shapes recorded from Traefik 3.7.15 on 2026-10-16)."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "traefik"
spec = importlib.util.spec_from_file_location("traefik_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

ROUTES = {
    "/api/version": {"Version": "3.7.15", "Codename": "langres"},
    "/api/entrypoints": [{"name": "traefik", "address": ":8080"}, {"name": "web", "address": ":80"}, {"name": "websecure", "address": ":443"}, {"name": "db", "address": ":5432"}],
    "/api/http/routers": [
        {"name": "api@internal", "rule": "PathPrefix(`/api`)", "service": "api@internal", "status": "enabled", "provider": "internal", "tls": None},
        {"name": "who@docker", "rule": "Host(`who.example.com`) || Host(`who2.example.com`)", "service": "who", "entryPoints": ["websecure"], "status": "enabled", "provider": "docker", "tls": {"certResolver": "le"}},
        {"name": "old@file", "rule": "Host(`old.example.com`) && PathPrefix(`/x`)", "service": "old@file", "status": "disabled", "provider": "file", "tls": None},
        {"name": "web-to-https@file", "rule": "HostRegexp(`^.+$`)", "service": "noop@internal", "status": "enabled", "provider": "file", "tls": None, "middlewares": ["https@file"]},
        {"name": "nosvc@file", "rule": "Host(`nosvc.example.com`)", "service": "missing@file", "status": "enabled", "provider": "file"},
    ],
    "/api/http/services": [
        {"name": "who@docker", "provider": "docker", "type": "loadbalancer", "loadBalancer": {"servers": [{"url": "http://172.18.0.7:80"}]}},
        {"name": "old@file", "provider": "file", "type": "loadbalancer", "loadBalancer": {"servers": [{"url": "https://nas.lan:5001"}]}},
    ],
    "/api/http/middlewares": [{"name": "https@file", "type": "redirectscheme", "provider": "file", "redirectScheme": {"scheme": "https", "permanent": True}}],
    "/api/tcp/routers": [{"name": "pg@file", "rule": "HostSNI(`db.example.com`)", "service": "pg@file", "entryPoints": ["db"], "status": "enabled", "provider": "file", "tls": {"passthrough": True}}],
    "/api/tcp/services": [{"name": "pg@file", "provider": "file", "loadBalancer": {"servers": [{"address": "192.168.0.30:5432"}]}}],
}


def config(url, **row):
    return {"servers": [{"host": url, "lan": "192.168.0.4", **row}], "timeout": 5}


def test_rule_parsing():
    assert plugin.domains_of("Host(`a.example.com`, `b.example.com`) && PathPrefix(`/x`)") == ["a.example.com", "b.example.com"]
    assert plugin.domains_of("HostRegexp(`^.+$`)") == [] and plugin.domains_of("Host(`A.Example.com`) || Host(`a.example.com`)") == ["a.example.com"]


def test_manifest_and_sites_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    with Canned(ROUTES) as s:
        out = validate_output("proxy", plugin.fetch(config(s.url)))
    assert out["proxies"][0]["ip"] == "192.168.0.4" and out["proxies"][0]["version"] == "3.7.15"
    sites = {x["id"]: x for x in out["sites"]}
    assert "http:api@internal" not in sites
    who = sites["http:who@docker"]
    assert who["domains"] == ["who.example.com", "who2.example.com"] and (who["forward_host"], who["forward_port"], who["scheme"]) == ("172.18.0.7", 80, "http")
    assert who["ssl"] is True and who["cert_provider"] == "le" and who["enabled"] is True
    old = sites["http:old@file"]
    assert old["enabled"] is False and (old["forward_host"], old["forward_port"], old["scheme"]) == ("nas.lan", 5001, "https")
    assert sites["http:web-to-https@file"]["type"] == "redirect" and sites["http:web-to-https@file"]["redirect_to"].startswith("https")
    assert sites["http:nosvc@file"]["type"] == "dead"
    pg = sites["tcp:pg@file"]
    assert (pg["type"], pg["incoming_port"], pg["forward_host"], pg["forward_port"]) == ("stream", 5432, "192.168.0.30", 5432)


def test_message_login_and_diagnose():
    auth = "Basic " + base64.b64encode(b"u:p").decode()
    with Canned(ROUTES, auth=auth) as s:
        assert "Connected to 1 Traefik (3.7.15): 5 site(s)" in plugin.test(config(s.url, username="u", password="p"))["message"]
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config(s.url, username="u", password="wrong"))
        assert caught.value.auth_failed is True
        report = json.dumps(plugin.diagnose(config(s.url, username="u", password="p")))
    assert "example.com" not in report and "172.18" not in report and '"count": 5' in report
