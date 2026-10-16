"""The Envoy plugin against canned answers (config_dump recorded from Envoy 1.32.13 on 2026-10-16; the xDS variant follows the admin API documentation)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "envoy"
spec = importlib.util.spec_from_file_location("envoy_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

T = "type.googleapis.com/envoy.admin.v3."


def sock(ip, port):
    return {"endpoint": {"address": {"socket_address": {"address": ip, "port_value": port}}}}


def cluster(name, *eps, **extra):
    return {"name": name, "type": "STATIC", "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [sock(*e) for e in eps]}]}, **extra}


HCM = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
TCP = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"
ROUTES = {"name": "local_route", "virtual_hosts": [
    {"name": "app", "domains": ["app.home.lan", "www.home.lan"], "routes": [{"match": {"prefix": "/"}, "route": {"cluster": "app_cluster"}}]},
    {"name": "api", "domains": ["api.home.lan"], "routes": [{"match": {"prefix": "/v1"}, "route": {"cluster": "api_cluster"}}, {"match": {"prefix": "/"}, "redirect": {"host_redirect": "app.home.lan"}}]},
    {"name": "old", "domains": ["old.home.lan", "*"], "routes": [{"match": {"prefix": "/"}, "redirect": {"host_redirect": "app.home.lan", "https_redirect": True}}]},
    {"name": "nothing", "domains": ["x.home.lan"], "routes": [{"match": {"prefix": "/"}, "direct_response": {"status": 404}}]}]}


def dump(dynamic=False, tls=False):
    web = {"name": "web", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 10000 if not tls else 10443}},
           "filter_chains": [{"filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": {"@type": HCM, "stat_prefix": "web", **({"rds": {"route_config_name": "local_route"}} if dynamic else {"route_config": ROUTES})}}],
                              **({"transport_socket": {"name": "envoy.transport_sockets.tls"}} if tls else {})}]}
    db = {"name": "tcp_db", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 15432}},
          "filter_chains": [{"filters": [{"name": "envoy.filters.network.tcp_proxy", "typed_config": {"@type": TCP, "stat_prefix": "db", "cluster": "db_cluster"}}]}]}
    clusters = [cluster("app_cluster", ("192.168.0.50", 8080), ("192.168.0.51", 8080)), cluster("api_cluster", ("192.168.0.60", 9000), transport_socket={"name": "envoy.transport_sockets.tls"}), cluster("db_cluster", ("192.168.0.70", 5432))]
    if dynamic:
        # xDS: the listener, route and cluster come from a control plane, the endpoints of app_cluster from EDS
        clusters[0] = {"name": "app_cluster", "type": "EDS", "eds_cluster_config": {"service_name": "app_cluster"}}
        return {"configs": [
            {"@type": T + "ClustersConfigDump", "dynamic_active_clusters": [{"cluster": c} for c in clusters]},
            {"@type": T + "EndpointsConfigDump", "dynamic_endpoint_configs": [{"endpoint_config": {"cluster_name": "app_cluster", "endpoints": [{"lb_endpoints": [sock("192.168.0.50", 8080)]}]}}]},
            {"@type": T + "ListenersConfigDump", "dynamic_listeners": [{"name": "web", "active_state": {"listener": web}}, {"name": "tcp_db", "active_state": {"listener": db}}]},
            {"@type": T + "RoutesConfigDump", "dynamic_route_configs": [{"route_config": ROUTES}]}]}
    return {"configs": [
        {"@type": T + "BootstrapConfigDump", "bootstrap": {}},
        {"@type": T + "ClustersConfigDump", "static_clusters": [{"cluster": c} for c in clusters]},
        {"@type": T + "EndpointsConfigDump", "static_endpoint_configs": []},
        {"@type": T + "ListenersConfigDump", "static_listeners": [{"listener": web}, {"listener": db}]},
        {"@type": T + "RoutesConfigDump", "static_route_configs": [{"route_config": ROUTES}]}]}


CLUSTERS_TEXT = "app_cluster::192.168.0.50:8080::cx_active::0\napp_cluster::192.168.0.50:8080::health_flags::healthy\napp_cluster::192.168.0.51:8080::health_flags::/failed_active_hc\napi_cluster::192.168.0.60:9000::health_flags::healthy\n"


class Envoy(Canned):
    def __init__(self, dump, state="LIVE"):
        super().__init__({"/server_info": {"version": "0c686a/1.32.13/Clean/RELEASE/BoringSSL", "state": state}, "/config_dump": dump})
        self.text = CLUSTERS_TEXT


@pytest.fixture
def envoy():
    with Envoy(dump()) as s:
        yield s


def config(s, **extra):
    return {"servers": [{"host": s.url, "lan": "192.168.0.4"}], "timeout": 5, **extra}


def test_manifest_and_sites_follow_the_contract(envoy):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    out = validate_output("proxy", plugin.fetch(config(envoy)))
    assert out["proxies"][0]["version"] == "1.32.13" and out["proxies"][0]["ip"] == "192.168.0.4"
    sites = {s["name"]: s for s in out["sites"]}
    assert sorted(sites) == ["api", "app", "nothing", "old", "tcp_db"]
    app = sites["app"]
    assert app["domains"] == ["app.home.lan", "www.home.lan"] and app["forward_host"] == "192.168.0.50" and app["forward_port"] == 8080
    assert app["forward_ips"] == ["192.168.0.50", "192.168.0.51"] and app["incoming_port"] == 10000
    assert sites["api"]["scheme"] == "https"                                                    # the cluster talks TLS to its upstream
    assert sites["old"]["type"] == "redirect" and sites["old"]["redirect_to"] == "https://app.home.lan" and sites["old"]["domains"] == ["old.home.lan"]     # "*" is no domain
    assert sites["nothing"]["type"] == "dead"
    db = sites["tcp_db"]
    assert db["type"] == "stream" and db["incoming_port"] == 15432 and db["forward_host"] == "192.168.0.70" and db["protocols"] == ["tcp"]


def test_xds_configuration_is_read(envoy):
    with Envoy(dump(dynamic=True)) as s:
        out = validate_output("proxy", plugin.fetch(config(s)))
    sites = {x["name"]: x for x in out["sites"]}
    assert sites["app"]["forward_host"] == "192.168.0.50" and sites["app"]["forward_ips"] == ["192.168.0.50"]       # the endpoints come from EDS
    assert sorted(sites) == ["api", "app", "nothing", "old", "tcp_db"]                           # the route configuration is found through its listener's rds name


def test_tls_listener_marks_sites_as_ssl():
    with Envoy(dump(tls=True)) as s:
        out = plugin.fetch(config(s))
    assert all(x["ssl"] for x in out["sites"] if x["type"] != "stream")


def test_test_message_and_down_envoy(envoy):
    assert "Envoy (1.32.13): 5 site(s)" in plugin.test(config(envoy))["message"]
    with Envoy(dump(), state="DRAINING") as s:
        assert plugin.fetch(config(s))["proxies"][0]["online"] is False


def test_unreachable_and_settings():
    with pytest.raises(plugin.EnvoyError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1"}], "timeout": 3})
    with pytest.raises(ValueError):
        plugin.parse_admins({"servers": []})
    with pytest.raises(plugin.EnvoyError):
        plugin.parse_admins({"servers": [{"host": "http://x:1", "lan": "not-an-ip"}]})


def test_unhealthy_endpoints_are_counted():
    assert plugin._health(CLUSTERS_TEXT) == 1


def test_diagnose_has_only_counts(envoy):
    report = plugin.diagnose(config(envoy))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["config_dump"]["virtual_hosts"] == 4 and steps["config_dump"]["filter_chains"] == {"http": 1, "tcp_proxy": 1} and steps["config_dump"]["clusters"] == 3
    for secret in ("home.lan", "192.168", "app_cluster", "127.0.0.1"):
        assert secret not in text
