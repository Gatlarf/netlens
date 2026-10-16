"""The Kubernetes plugin against canned answers (shapes recorded from k3s v1.36.5 on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "kubernetes"
spec = importlib.util.spec_from_file_location("kubernetes_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Bearer tok"


def pod(name, ns="demo", phase="Running", node="n1", ready=True, owner=("ReplicaSet", "web-5d6b5c7df9"), restarts=0, waiting=None, host_network=False, host_port=None, ip="10.42.0.10"):
    status = {"phase": phase, "podIP": ip, "podIPs": [{"ip": ip}], "startTime": "2026-10-16T09:16:52Z",
              "containerStatuses": [{"ready": ready, "restartCount": restarts, "state": {"waiting": {"reason": waiting}} if waiting else {"running": {}}}]}
    port = {"containerPort": 80, **({"hostPort": host_port} if host_port else {})}
    return {"metadata": {"name": name, "namespace": ns, "ownerReferences": [{"kind": owner[0], "name": owner[1]}] if owner else []},
            "spec": {"nodeName": node, "hostNetwork": host_network, "containers": [{"image": "nginx:alpine", "ports": [port]}]}, "status": status}


NODES = {"items": [
    {"metadata": {"name": "n1"}, "status": {"addresses": [{"type": "InternalIP", "address": "192.168.0.10"}, {"type": "Hostname", "address": "n1"}], "conditions": [{"type": "Ready", "status": "True"}]}},
    {"metadata": {"name": "n2"}, "status": {"addresses": [{"type": "InternalIP", "address": "192.168.0.11"}], "conditions": [{"type": "Ready", "status": "False"}]}}], "metadata": {}}
PODS = {"items": [pod("web-5d6b5c7df9-abc12"), pod("db-0", owner=("StatefulSet", "db"), restarts=3, host_port=5432),
                  pod("crash", ready=False, waiting="CrashLoopBackOff", owner=None), pod("job-x", phase="Succeeded"),
                  pod("agent", ns="kube-system", node="n2", host_network=True, owner=("DaemonSet", "agent"), ip="192.168.0.11")], "metadata": {}}
ROUTES = {"/version": {"gitVersion": "v1.36.5+k3s1"}, "/api/v1/nodes": NODES, "/api/v1/pods": PODS, "/api/v1/namespaces/demo/pods": {"items": PODS["items"][:3], "metadata": {}}}


def config(url, token="tok", **extra):
    return {"servers": [{"host": url, "token": token, **extra}], "timeout": 5}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    with Canned(ROUTES, auth=AUTH) as s:
        out = validate_output("hypervisor", plugin.fetch(config(s.url)))
    assert [(h["name"], h["ip"], h["online"]) for h in out["hosts"]] == [("n1", "192.168.0.10", True), ("n2", "192.168.0.11", False)]
    guests = {g["name"]: g for g in out["guests"]}
    assert "job-x" not in guests                                                       # finished pods are left out
    web = guests["web-5d6b5c7df9-abc12"]
    assert web["kind"] == "pod" and web["status"] == "running" and web["host_id"].endswith("/n1") and web["ips"] == []
    assert (web["details"]["project"], web["details"]["service"], web["details"]["health"]) == ("demo", "web", "healthy")
    db = guests["db-0"]
    assert db["details"]["service"] == "db" and db["details"]["restarts"] == 3 and db["details"]["ports"][0]["host_port"] == 5432 and db["details"]["exposed"] is True
    assert guests["crash"]["status"] == "crashloopbackoff" and guests["crash"]["details"]["health"] == "unhealthy"
    assert guests["agent"]["details"]["network_driver"] == "host" and guests["agent"]["host_id"].endswith("/n2")


def test_pod_addresses_only_on_request_and_never_on_the_host_network():
    with Canned(ROUTES, auth=AUTH) as s:
        out = plugin.fetch({**config(s.url), "pod_ips": True})
    ips = {g["name"]: g["ips"] for g in out["guests"]}
    assert ips["web-5d6b5c7df9-abc12"] == ["10.42.0.10"] and ips["agent"] == []


def test_namespace_filter_message_and_refused_token():
    with Canned(ROUTES, auth=AUTH) as s:
        assert "2 node(s), 3 pod(s), 2 running. 1 node(s) are not Ready" in plugin.test(config(s.url, namespaces="demo"))["message"]
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config(s.url, token="wrong"))
        assert caught.value.auth_failed is True
        report = json.dumps(plugin.diagnose(config(s.url)))
    assert "192.168" not in report and "nginx" not in report and '"count": 5' in report and '"Succeeded": 1' in report      # counts only; the finished pod is counted here
