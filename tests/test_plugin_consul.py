"""The Consul plugin against canned answers (shapes recorded from Consul 1.20.6 on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "consul"
spec = importlib.util.spec_from_file_location("consul_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def node(name, address, meta=None):
    return {"ID": "", "Node": name, "Address": address, "Datacenter": "dc1", "TaggedAddresses": None, "Meta": meta, "CreateIndex": 1, "ModifyIndex": 1}


def inst(n, address, sid, name, port, svc_address="", tags=()):
    return {"ID": "", "Node": n, "Address": address, "ServiceID": sid, "ServiceName": name, "ServiceTags": list(tags), "ServiceAddress": svc_address, "ServicePort": port, "ServiceMeta": {}}


def check(n, cid, status, sid="", sname=""):
    return {"Node": n, "CheckID": cid, "Name": cid, "Status": status, "ServiceID": sid, "ServiceName": sname}


ROUTES = {
    "/v1/agent/self": {"Config": {"Datacenter": "dc1", "NodeName": "srv", "Version": "1.20.6"}},
    "/v1/catalog/nodes": [node("srv", "127.0.0.1", {"consul-version": "1.20.6"}), node("db1", "192.168.0.70"), node("nosvc", "192.168.0.99"), node("web1", "192.168.0.50"), node("web2", "192.168.0.51"), node("lost", "192.168.0.98")],
    "/v1/catalog/services": {"consul": [], "postgres": [], "web": ["prod"]},
    "/v1/catalog/service/consul": [inst("srv", "127.0.0.1", "consul", "consul", 8300)],
    "/v1/catalog/service/postgres": [inst("db1", "192.168.0.70", "pg", "postgres", 5432)],
    "/v1/catalog/service/web": [inst("web1", "192.168.0.50", "web-1", "web", 8080, tags=["prod"]), inst("web2", "192.168.0.51", "web-2", "web", 8080, "192.168.0.151", ["prod"]),
                                inst("web1", "192.168.0.50", "web-1b", "web", 8081, tags=["canary"])],
    "/v1/health/state/any": [check("srv", "serfHealth", "passing"), check("lost", "serfHealth", "critical"), check("db1", "pg-tcp", "critical", "pg", "postgres"),
                             check("web1", "web-1-http", "passing", "web-1", "web"), check("web2", "web-2-http", "warning", "web-2", "web"),
                             check("web1", "web-1b-http", "passing", "web-1b", "web"), check("web1", "web-1b-disk", "critical", "web-1b", "web")],
}


@pytest.fixture
def consul():
    with Canned(dict(ROUTES)) as s:
        yield s


def config(s, **extra):
    return {"servers": [{"host": s.url}], "timeout": 5, **extra}


def test_manifest_and_output_follow_the_contract(consul):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    out = validate_output("hypervisor", plugin.fetch(config(consul)))
    hosts = {h["id"]: h for h in out["hosts"]}
    assert sorted(hosts) == ["db1", "lost", "nosvc", "srv", "web1", "web2"]
    assert hosts["srv"]["ip"] is None and hosts["web1"]["ip"] == "192.168.0.50"                 # a loopback address is no address
    assert hosts["lost"]["online"] is False and hosts["nosvc"]["online"] is True               # serfHealth critical = offline; no check = online
    guests = {g["id"]: g for g in out["guests"]}
    assert sorted(guests) == ["db1/pg", "web1/web-1", "web1/web-1b", "web2/web-2"]            # the 'consul' service is hidden
    assert guests["web1/web-1"]["status"] == "running" and guests["web2/web-2"]["status"] == "warning" and guests["db1/pg"]["status"] == "critical"
    assert guests["web1/web-1b"]["status"] == "critical"                                      # the worst check of an instance wins
    assert guests["web2/web-2"]["ips"] == ["192.168.0.151"] and guests["web1/web-1"]["ips"] == ["192.168.0.50"]
    assert guests["web1/web-1"]["host_id"] == "web1" and guests["web1/web-1"]["kind"] == "service"
    assert guests["web1/web-1"]["details"]["tags"] == "prod" and guests["web1/web-1"]["details"]["ports"][0]["host_port"] == 8080


def test_consul_service_can_be_shown(consul):
    out = plugin.fetch(config(consul, hide_consul=False))
    assert "srv/consul" in {g["id"] for g in out["guests"]}


def test_message(consul):
    message = plugin.test(config(consul))["message"]
    assert "Consul 1.20.6" in message and "6 node(s)" in message and "4 service instance(s)" in message and "3 not passing" in message


def test_acl_refusal_stops_retries():
    r = dict(ROUTES)
    r["/v1/catalog/nodes"] = 403
    with Canned(r) as s:
        with pytest.raises(plugin.AuthRefused) as exc:
            plugin.fetch(config(s))
        assert exc.value.auth_failed


def test_agent_self_may_be_refused():
    r = dict(ROUTES)
    r["/v1/agent/self"] = 403
    with Canned(r) as s:
        assert "(version unknown)" in plugin.test(config(s))["message"]


def test_two_datacenters_with_the_same_node_name():
    with Canned(dict(ROUTES)) as a, Canned(dict(ROUTES)) as b:
        out = validate_output("hypervisor", plugin.fetch({"servers": [{"host": a.url}, {"host": b.url}], "timeout": 5}))
    assert len({h["id"] for h in out["hosts"]}) == 12 and len({g["id"] for g in out["guests"]}) == 8


def test_unreachable_and_settings():
    with pytest.raises(plugin.ConsulError, match="cannot reach"):
        plugin.fetch({"servers": [{"host": "http://127.0.0.1:1"}], "timeout": 3})
    with pytest.raises(ValueError):
        plugin.parse_clusters({"servers": []})


def test_diagnose_has_only_counts(consul):
    report = plugin.diagnose(config(consul))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["nodes"]["count"] == 6 and steps["checks"]["statuses"] == {"critical": 3, "passing": 3, "warning": 1}
    for secret in ("web1", "postgres", "192.168", "127.0.0.1", "prod"):
        assert secret not in text
