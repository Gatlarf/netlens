"""The APISIX plugin against canned answers (shapes recorded from APISIX 3.11.0 on 2026-10-16; the certificate is a throwaway one made for the lab)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "apisix"
spec = importlib.util.spec_from_file_location("apisix_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

PEM = """-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIUDQ+9zU5Md6Zv5g09PvW0DvOWTokwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMYXBwLmhvbWUubGFuMB4XDTI2MTAxNjE2NTg0NVoXDTI3
MDExNDE2NTg0NVowFzEVMBMGA1UEAwwMYXBwLmhvbWUubGFuMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1U2q71l6hpCftJeUlpmFxKkeWoqI4Tbgvk1Z
NLERWYxlRsX/vuumNJc9LIUrxLRvHclTMK1m6V5KOdLAyyRGBIip2UWbjgdvBnI+
JvJ5EcjEZr4ZHcKPA61Y83N0dzl7uXLNMlTutw0gVxILCjzeQ0aDrP42YJyahMoF
kQHp6tX9JRMLGA0ZVG+6tAoE0qawXLeuzJTcQ3VBxCGkEnlMi9gnxklhII9RTpfq
si+jXzy0pIfSECllQ9f6SV8uktgxfjNYyjYXjFp76YvgP0fBME7eDK4REMC94nh9
OCWACK1VejP8VG3y481HpWfEIqLzK0eGjhTjNOatmEcjRPzhYwIDAQABo3gwdjAd
BgNVHQ4EFgQUu+K2n199fvmUsUF/I0HyPYNb8XQwHwYDVR0jBBgwFoAUu+K2n199
fvmUsUF/I0HyPYNb8XQwDwYDVR0TAQH/BAUwAwEB/zAjBgNVHREEHDAaggxhcHAu
aG9tZS5sYW6CCiouaG9tZS5sYW4wDQYJKoZIhvcNAQELBQADggEBAKbs8d9Y01Tz
ARWLfGIT2jcNjRJe3o5wPGq22yHRvQlM6qYCfa8TTGYegguGMcYuah0c51MlGrXd
VpJLECK2242v6p38BoG+Qg+GXt3DBPFGroZTsMNkbDGZVFlbljpWqxHSm/pMpCqY
868IQyudDXvATc/xhcCoj0sPgEaziRuOiK6gAKVw/sTDmBujAtWxGVrIXwlm73UP
OcLlJInElMjUFagUCY+o84wcvo/ZitifDfW2ftoSUh75sDQR0FIfI0l50y/0qPZ2
OEICAG9eKtvMfIEd2il7xc7HDSvtajD2eM0NVztaUaNdozpdO/PuhPEpK6gB7D26
ikH0GdyNo4Y=
-----END CERTIFICATE-----"""   # notAfter Jan 14 16:58:45 2027 GMT


def lst(*values):
    return {"list": [{"key": f"/apisix/x/{v['id']}", "value": v} for v in values], "total": len(values)}


ROUTES = lst(
    {"id": "1", "name": "app", "hosts": ["app.home.lan", "www.home.lan"], "uri": "/*", "upstream_id": "1", "enable_websocket": True, "status": 1},
    {"id": "2", "name": "api", "host": "api.home.lan", "uris": ["/v1/*"], "upstream_id": "2", "status": 1},
    {"id": "3", "name": "redir", "host": "old.home.lan", "uri": "/*", "plugins": {"redirect": {"uri": "https://app.home.lan/", "ret_code": 301}}},
    {"id": "4", "name": "inline", "hosts": ["inline.home.lan"], "uri": "/*", "upstream": {"type": "roundrobin", "scheme": "http", "nodes": {"192.168.0.80:3000": 1}}},
    {"id": "5", "name": "off", "host": "off.home.lan", "uri": "/*", "upstream_id": "1", "status": 0},
    {"id": "6", "name": "viasvc", "host": "svc.home.lan", "uri": "/*", "service_id": "1"},
    {"id": "7", "name": "nothing", "host": "none.other.lan", "uri": "/*"})
UPSTREAMS = lst({"id": "1", "name": "app-up", "nodes": {"192.168.0.51:8080": 2, "192.168.0.50:8080": 1}, "scheme": "http"},
                {"id": "2", "name": "api-up", "nodes": [{"host": "api.internal", "port": 9443, "weight": 1, "priority": 0}], "scheme": "https"})
SERVICES = lst({"id": "1", "name": "svc", "upstream_id": "1"})
SSLS = lst({"id": "1", "snis": ["app.home.lan", "*.home.lan"], "type": "server", "status": 1, "cert": PEM, "key": "ENCRYPTED"})


@pytest.fixture
def apisix():
    r = {"/apisix/admin/routes": ROUTES, "/apisix/admin/upstreams": UPSTREAMS, "/apisix/admin/services": SERVICES, "/apisix/admin/ssls": SSLS, "/apisix/admin/stream_routes": 400}
    with Canned(r) as s:
        yield s


def config(s, **extra):
    return {"servers": [{"host": s.url, "key": "viewerkey", "lan": "192.168.0.4"}], "timeout": 5, **extra}


def test_manifest_and_sites_follow_the_contract(apisix):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    out = validate_output("proxy", plugin.fetch(config(apisix)))
    assert out["proxies"][0]["ip"] == "192.168.0.4"
    sites = {s["name"]: s for s in out["sites"]}
    assert sorted(sites) == ["api", "app", "inline", "nothing", "off", "redir", "viasvc"]
    app = sites["app"]
    assert app["domains"] == ["app.home.lan", "www.home.lan"] and app["forward_host"] == "192.168.0.51" and app["forward_port"] == 8080 and app["forward_ips"] == ["192.168.0.51", "192.168.0.50"] and app["websockets"]
    assert sites["api"]["scheme"] == "https" and sites["api"]["forward_host"] == "api.internal" and sites["api"]["forward_port"] == 9443
    assert sites["redir"]["type"] == "redirect" and sites["redir"]["redirect_to"] == "https://app.home.lan/"
    assert sites["inline"]["forward_host"] == "192.168.0.80" and sites["inline"]["forward_port"] == 3000
    assert sites["off"]["enabled"] is False
    assert sites["viasvc"]["forward_host"] == "192.168.0.51" and sites["viasvc"]["forward_port"] == 8080     # through the service's upstream
    assert sites["nothing"]["type"] == "dead" and sites["nothing"]["certificate_id"] is None


def test_certificates_follow_sni_with_wildcards(apisix):
    out = validate_output("proxy", plugin.fetch(config(apisix)))
    cert = out["certificates"][0]
    assert cert["expires"] == "2027-01-14T16:58:45Z" and cert["domains"] == ["app.home.lan", "*.home.lan"] and cert["in_use"]
    sites = {s["name"]: s for s in out["sites"]}
    assert sites["api"]["ssl"] and sites["api"]["certificate_id"] == cert["id"] and sites["api"]["cert_expires"] == "2027-01-14T16:58:45Z"      # *.home.lan
    assert not sites["nothing"]["ssl"]                                                                                                             # none.other.lan matches no SNI


def test_certificate_expiry_parser():
    assert plugin._validity(PEM) == "2027-01-14T16:58:45Z"
    assert plugin._validity("not a certificate") is None and plugin._validity("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----") is None


def test_stream_routes_when_enabled(apisix):
    apisix.routes["/apisix/admin/stream_routes"] = lst({"id": "s1", "server_port": 15432, "upstream": {"nodes": {"192.168.0.70:5432": 1}, "type": "roundrobin"}})
    out = validate_output("proxy", plugin.fetch(config(apisix)))
    stream = next(s for s in out["sites"] if s["type"] == "stream")
    assert stream["incoming_port"] == 15432 and stream["forward_host"] == "192.168.0.70" and stream["forward_port"] == 5432


def test_message_and_wrong_key(apisix):
    message = plugin.test(config(apisix))["message"]
    assert "7 route(s)" in message and "1 certificate(s)" in message and "1 redirect" in message
    with Canned({}, auth="X") as s:
        with pytest.raises(plugin.AuthRefused) as exc:
            plugin.fetch(config(s))
        assert exc.value.auth_failed


def test_settings_are_checked():
    with pytest.raises(ValueError):
        plugin.parse_admins({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_admins({"servers": [{"host": "http://x:9180"}]})
    with pytest.raises(plugin.ApisixError):
        plugin.parse_admins({"servers": [{"host": "http://x:9180", "key": "k", "lan": "nope"}]})


def test_diagnose_has_only_counts(apisix):
    report = plugin.diagnose(config(apisix))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["routes"]["count"] == 7 and steps["routes"]["redirects"] == 1 and steps["routes"]["disabled"] == 1 and steps["ssls"]["readable_expiry"] == 1
    for secret in ("home.lan", "192.168", "viewerkey", "127.0.0.1", "api.internal"):
        assert secret not in text
