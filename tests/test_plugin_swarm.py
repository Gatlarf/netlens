"""The Docker Swarm plugin against canned answers (shapes recorded from Docker 26.1.5 swarm mode on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "swarm"
spec = importlib.util.spec_from_file_location("swarm_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def node(i, role="manager", state="ready", avail="active", addr="192.168.0.1"):
    return {"ID": f"node{i}", "Spec": {"Role": role, "Availability": avail}, "Description": {"Hostname": f"host{i}"}, "Status": {"State": state, "Addr": addr}}


def task(i, node_id="node1", state="running", desired="running", slot=1, service="svc1"):
    return {"ID": f"task{i}", "ServiceID": service, "NodeID": node_id, "Slot": slot, "DesiredState": desired, "Status": {"State": state, "Timestamp": "2026-10-16T10:46:24Z"}}


ROUTES = {
    "/info": {"Swarm": {"LocalNodeState": "active", "ControlAvailable": True, "Cluster": {"ID": "clusterid123456789"}, "Managers": 1, "Nodes": 2}},
    "/nodes": [node(1), node(2, role="worker", addr="192.168.0.2"), node(3, role="worker", state="down", addr="192.168.0.3")],
    "/services": [{"ID": "svc1", "Spec": {"Name": "web", "Labels": {"com.docker.stack.namespace": "shop"}, "TaskTemplate": {"ContainerSpec": {"Image": "nginx:alpine@sha256:abc"}}},
                   "Endpoint": {"Ports": [{"Protocol": "tcp", "TargetPort": 80, "PublishedPort": 8080, "PublishMode": "ingress"}]}}],
    "/tasks": [task(1), task(2, "node2", slot=2), task(3, "node1", state="shutdown", desired="shutdown"), task(4, "node3", state="failed", slot=3)],
}


def config(url):
    return {"servers": [{"host": url}], "timeout": 5}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    with Canned(ROUTES) as s:
        out = validate_output("hypervisor", plugin.fetch(config(s.url)))
    assert [(h["name"], h["ip"], h["online"]) for h in out["hosts"]] == [("host1", "192.168.0.1", True), ("host2", "192.168.0.2", True), ("host3", "192.168.0.3", False)]
    guests = {g["name"]: g for g in out["guests"]}
    assert sorted(guests) == ["web.1", "web.2", "web.3"]                                      # the shut down copy is left out
    web = guests["web.1"]
    assert web["kind"] == "task" and web["status"] == "running" and web["host_id"].endswith("/node1")
    assert (web["details"]["image"], web["details"]["project"], web["details"]["service"]) == ("nginx:alpine", "shop", "web")
    assert web["details"]["ports"][0]["host_port"] == 8080 and guests["web.3"]["details"]["health"] == "unhealthy"


def test_message_worker_node_and_diagnose():
    with Canned(ROUTES) as s:
        assert "1 swarm(s): 3 node(s), 3 task(s), 2 running. 1 node(s) are down or drained" in plugin.test(config(s.url))["message"]
        text = json.dumps(plugin.diagnose(config(s.url)))
        assert "192.168" not in text and "nginx" not in text and "shop" not in text and '"managers": 1' in text
    worker = {**ROUTES, "/info": {"Swarm": {"LocalNodeState": "active", "ControlAvailable": False}}}
    with Canned(worker) as s, pytest.raises(plugin.SwarmError) as caught:
        plugin.test(config(s.url))
    assert "not a swarm manager" in str(caught.value)
