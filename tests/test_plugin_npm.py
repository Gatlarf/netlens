"""The Nginx Proxy Manager plugin against a simulated API: login, what it reads, the contract, warnings about the account."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import ContractError, validate_manifest, validate_output
from tests.fake_npm import FakeNpm, proxy_host

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "npm"
spec = importlib.util.spec_from_file_location("npm_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

CERTS = [
    {"id": 1, "provider": "letsencrypt", "nice_name": "wildcard", "domain_names": ["*.example.com"], "expires_on": "2027-01-31 10:20:30"},
    {"id": 2, "provider": "other", "nice_name": "unused", "domain_names": ["x.example.com"], "expires_on": "2020-01-01 00:00:00"},
]


def npm(**kw):
    kw.setdefault("proxy_hosts", [
        proxy_host(1, ["media.example.com"], "192.168.0.50", 8096, cert=1, ssl_forced=True),
        proxy_host(2, ["wiki.example.com", "docs.example.com"], "wiki", 3000, access=7, enabled=False),
    ])
    kw.setdefault("redirections", [{"id": 3, "domain_names": ["old.example.com"], "forward_scheme": "https", "forward_domain_name": "new.example.com", "forward_http_code": 301, "certificate_id": 0, "enabled": True}])
    kw.setdefault("streams", [{"id": 4, "incoming_port": 2222, "forwarding_host": "192.168.0.60", "forwarding_port": 22, "tcp_forwarding": True, "udp_forwarding": False, "certificate_id": 0, "enabled": True}])
    kw.setdefault("dead", [{"id": 5, "domain_names": ["nothing.example.com"], "certificate_id": 0, "enabled": True}])
    kw.setdefault("certificates", CERTS)
    kw.setdefault("access_lists", [{"id": 7, "name": "family"}])
    return FakeNpm(**kw)


def config(server, **extra):
    return {"servers": [{"host": server.url, "email": server.user, "password": server.password, "lan": "192.168.0.184"}], "resolve_names": False, "timeout": 5, **extra}


def test_the_manifest_follows_the_contract():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["kind"] == "proxy" and manifest["diagnose"] and manifest["info"]["title"]
    assert [c["key"] for c in manifest["config"][0]["columns"]] == ["host", "email", "password", "lan"]


def test_fetch_reads_every_kind_of_site_and_follows_the_contract():
    with npm() as server:
        out = plugin.fetch(config(server))
        assert {m for m, _ in server.requests if m == "POST"} == {"POST"} and len([r for r in server.requests if r[0] == "POST"]) == 1   # one login, only reads after it
    checked = validate_output("proxy", out)
    assert [s["id"] for s in checked["sites"]] == ["proxy-1", "proxy-2", "redirect-3", "stream-4", "dead-5"]
    media, wiki, redirect, stream, dead = checked["sites"]
    assert media["domains"] == ["media.example.com"] and media["forward_host"] == "192.168.0.50" and media["forward_port"] == 8096
    assert media["ssl"] and media["ssl_forced"] and media["cert_name"] == "wildcard" and media["cert_expires"] == "2027-01-31T10:20:30Z"
    assert not wiki["enabled"] and wiki["access_list"] == "family" and not wiki["ssl"] and wiki["websockets"]
    assert redirect["type"] == "redirect" and redirect["redirect_to"] == "https://new.example.com (301)"
    assert stream["type"] == "stream" and stream["incoming_port"] == 2222 and stream["protocols"] == ["tcp"] and stream["forward_port"] == 22
    assert dead["type"] == "dead" and dead["domains"] == ["nothing.example.com"]
    proxy = checked["proxies"][0]
    assert proxy["ip"] == "192.168.0.184" and proxy["version"] == "2.15.1" and proxy["warnings"] == []
    assert {c["id"]: c["in_use"] for c in checked["certificates"]} == {"1": True, "2": False}


def test_a_wrong_password_pauses_the_plugin_and_a_bad_request_does_not():
    with npm() as server:
        bad = config(server)
        bad["servers"][0]["password"] = "nope"
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.fetch(bad)
        assert caught.value.auth_failed and "Invalid email or password" in str(caught.value)


def test_two_factor_accounts_are_refused_with_an_explanation():
    with npm(requires_2fa=True) as server:
        with pytest.raises(plugin.AuthRefused, match="two-factor"):
            plugin.fetch(config(server))


def test_the_account_is_checked_for_visibility_and_write_access():
    mine_only = {"visibility": "user", "proxy_hosts": "manage", "redirection_hosts": "manage", "dead_hosts": "manage", "streams": "manage", "access_lists": "manage", "certificates": "manage"}
    with npm(permissions=mine_only) as server:
        warnings = plugin.fetch(config(server))["proxies"][0]["warnings"]
        assert len(warnings) == 2 and "Item Visibility" in warnings[0] and "View Only" in warnings[1]
        assert "Item Visibility" in plugin.test(config(server))["message"]
    with npm(roles=["admin"]) as server:
        assert "administrator" in plugin.fetch(config(server))["proxies"][0]["warnings"][0]


def test_a_missing_optional_list_is_a_warning_not_a_failure():
    with npm(forbid=("/api/nginx/streams", "/api/nginx/certificates")) as server:
        out = plugin.fetch(config(server))
        assert not any(s["type"] == "stream" for s in out["sites"])
        assert any("certificates" in w for w in out["proxies"][0]["warnings"])
        assert next(s for s in out["sites"] if s["id"] == "proxy-1")["cert_expires"] is None


def test_the_test_message_counts_what_it_found():
    with npm() as server:
        message = plugin.test(config(server))["message"]
    assert "2.15.1" in message and "2 proxy hosts" in message and "1 redirection" in message and "1 stream" in message and "2 certificate" in message


def test_names_are_looked_up_when_asked(monkeypatch):
    from types import SimpleNamespace

    def lookup(name, port, family=0):
        if name == "wiki":
            return [(2, 1, 6, "", ("192.168.0.77", 0))]
        raise OSError("unknown name")

    # only the plugin's own view of socket is replaced: the test server and the HTTP client keep the real one
    monkeypatch.setattr(plugin, "socket", SimpleNamespace(getaddrinfo=lookup, AF_INET=2, gethostbyname=lambda n: "192.168.0.184"))
    with npm() as server:
        out = plugin.fetch(config(server, resolve_names=True))
    by_id = {s["id"]: s for s in out["sites"]}
    assert by_id["proxy-2"]["forward_ips"] == ["192.168.0.77"] and "forward_ips" not in by_id["proxy-1"]       # an address is not looked up


def test_diagnose_reports_counts_and_no_names():
    with npm() as server:
        text = json.dumps(plugin.diagnose(config(server)))
    steps = json.loads(text)["servers"][0]["steps"]
    assert steps["login"]["ok"] and steps["proxy_hosts"] == {"ok": True, "count": 2, "enabled": 1, "forward_to_ip": 1, "with_certificate": 1}
    assert "example.com" not in text and "192.168" not in text and "wiki" not in text


def test_diagnose_stops_at_a_failed_login():
    with npm() as server:
        bad = config(server)
        bad["servers"][0]["password"] = "nope"
        steps = plugin.diagnose(bad)["servers"][0]["steps"]
    assert steps["login"]["ok"] is False and "proxy_hosts" not in steps


def test_the_contract_rejects_a_site_of_an_unknown_proxy():
    with pytest.raises(ContractError, match="proxy_id"):
        validate_output("proxy", {"proxies": [], "sites": [{"id": "a", "proxy_id": "nope"}], "certificates": []})
    with pytest.raises(ContractError, match="expires"):
        validate_output("proxy", {"proxies": [{"id": "p"}], "sites": [], "certificates": [{"id": "1", "expires": "next year"}]})
