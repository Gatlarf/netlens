"""The Nomad plugin against canned answers (shapes recorded from Nomad 2.0.7 in dev mode on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "nomad"
spec = importlib.util.spec_from_file_location("nomad_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

NODES = [{"ID": "n-1", "Name": "client1", "Address": "192.168.0.11", "Status": "ready", "Version": "2.0.7"},
         {"ID": "n-2", "Name": "client2", "Address": "192.168.0.12", "Status": "down", "Version": "2.0.7"}]


def stub(i, status="running", desired="run", job="web", node="n-1", restarts=0, failed=False, ns="default"):
    return {"ID": f"a-{i}", "JobID": job, "Namespace": ns, "TaskGroup": "frontend", "Name": f"{job}.frontend[{i}]", "NodeID": node, "ClientStatus": status, "DesiredStatus": desired,
            "TaskStates": {"nginx": {"State": "running", "Failed": failed, "Restarts": restarts, "StartedAt": "2026-10-16T09:56:03Z"}}}


DETAIL = {"AllocatedResources": {"Shared": {"Ports": [{"HostIP": "192.168.0.11", "Label": "http", "To": 80, "Value": 22745}]}},
          "Job": {"TaskGroups": [{"Name": "frontend", "Tasks": [{"Config": {"image": "nginx:alpine"}}]}]}}
ROUTES = {"/v1/agent/self": {"config": {"Version": {"Version": "2.0.7"}}}, "/v1/nodes": NODES,
          "/v1/allocations": [stub(0), stub(1, restarts=3, failed=True, node="n-2"), stub(2, status="complete", desired="stop"), stub(3, status="pending", ns="apps"), stub(4, status="failed")],
          "/v1/allocation/a-0": DETAIL}


def config(url, **row):
    return {"servers": [{"host": url, **row}], "timeout": 5}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    with Canned(ROUTES) as s:
        out = validate_output("hypervisor", plugin.fetch(config(s.url)))
    assert [(h["name"], h["ip"], h["online"]) for h in out["hosts"]] == [("client1", "192.168.0.11", True), ("client2", "192.168.0.12", False)]
    guests = {g["name"]: g for g in out["guests"]}
    assert "web.frontend[2]" not in guests                                                       # finished allocations are left out
    web0 = guests["web.frontend[0]"]
    assert web0["kind"] == "alloc" and web0["host_id"].endswith("/n-1") and web0["status"] == "running"
    assert web0["details"]["image"] == "nginx:alpine" and web0["details"]["service"] == "web" and web0["details"]["ports"][0]["host_port"] == 22745
    web1 = guests["web.frontend[1]"]
    assert web1["details"]["restarts"] == 3 and web1["details"]["health"] == "unhealthy" and web1["host_id"].endswith("/n-2")
    assert guests["web.frontend[3]"]["details"]["project"] == "apps" and guests["web.frontend[3]"]["status"] == "pending"
    assert guests["web.frontend[4]"]["status"] == "failed"


def test_message_acl_refusal_and_diagnose():
    with Canned(ROUTES) as s:
        assert "2 node(s), 4 allocation(s), 2 running. 1 node(s) are not ready" in plugin.test(config(s.url))["message"]
        text = json.dumps(plugin.diagnose(config(s.url)))
    assert "192.168" not in text and "nginx" not in text and "client1" not in text and '"count": 5' in text
    with Canned({**ROUTES, "/v1/nodes": 403}) as s, pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(s.url, token="t"))
    assert caught.value.auth_failed is True


def test_allocation_errors_are_reported_not_hidden():
    with Canned({**ROUTES, "/v1/allocations": 400}) as s, pytest.raises(plugin.NomadError):
        plugin.fetch(config(s.url))            # an unexpected HTTP error (here 400 on both tries) reaches the user
