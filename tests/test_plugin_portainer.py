"""The Portainer plugin against a simulated Portainer 2.45 (shapes recorded from a real one, 2026-10-16)."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "portainer"
spec = importlib.util.spec_from_file_location("portainer_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

KEY = "ptr_testkey"
ENVS = [
    {"Id": 1, "Name": "local", "Type": 1, "URL": "unix:///var/run/docker.sock", "Status": 1},
    {"Id": 2, "Name": "nas", "Type": 2, "URL": "tcp://192.168.0.7:9001", "Status": 1},
    {"Id": 3, "Name": "edge", "Type": 4, "URL": "", "Status": 2},
    {"Id": 4, "Name": "k8s", "Type": 5, "URL": "https://192.168.0.9:6443", "Status": 1},
]
CONTAINERS = [
    {"Id": "abc123", "Names": ["/web"], "Image": "nginx:1", "ImageID": "sha256:1", "State": "running", "Labels": {"com.docker.compose.project": "site", "com.docker.compose.service": "web"},
     "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
     "HostConfig": {"NetworkMode": "default"}, "NetworkSettings": {"Networks": {"site_default": {"NetworkID": "n1", "IPAddress": "172.18.0.2", "MacAddress": "02:42:ac:12:00:02"}}}},
    {"Id": "def456", "Names": ["/lan"], "Image": "app:2", "ImageID": "sha256:2", "State": "exited", "Labels": {}, "Ports": [], "HostConfig": {"NetworkMode": "lan"},
     "NetworkSettings": {"Networks": {"lan": {"NetworkID": "n2", "IPAddress": "192.168.0.60", "MacAddress": "02:42:c0:a8:00:3c"}}}},
]
NETWORKS = [{"Id": "n1", "Name": "site_default", "Driver": "bridge"}, {"Id": "n2", "Name": "lan", "Driver": "macvlan"}]


@pytest.fixture
def portainer():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            if self.headers.get("X-API-Key") != KEY:
                code, body = 401, {"message": "Invalid JWT token"}
            elif path == "/api/endpoints":
                code, body = 200, ENVS
            elif path.endswith("/docker/info"):
                code, body = 200, {"Name": f"host{path.split('/')[3]}", "ServerVersion": "26.1.5"}
            elif path.endswith("/docker/networks"):
                code, body = 200, NETWORKS
            elif path.endswith("/containers/json"):
                code, body = 200, CONTAINERS
            elif "/containers/" in path and path.endswith("/json"):
                code, body = 200, {"RestartCount": 2, "State": {"Health": {"Status": "healthy"}, "StartedAt": "2026-10-01T00:00:00Z", "ExitCode": 3, "Restarting": False}}
            else:
                code, body = 404, {}
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def config(url, key=KEY, lan="192.168.0.5"):
    return {"servers": [{"host": url, "api_key": key, "lan": lan}], "timeout": 5}


def test_manifest_and_output_follow_the_contract(portainer):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    out = validate_output("hypervisor", plugin.fetch(config(portainer)))
    hosts = {h["name"]: h for h in out["hosts"]}
    assert hosts["host1"]["ip"] == "192.168.0.5" and hosts["host1"]["online"] is True        # local socket: the host Portainer runs on
    assert hosts["host2"]["ip"] == "192.168.0.7"                                             # agent: from its tcp:// address
    assert hosts["edge"]["online"] is False and hosts["edge"]["ip"] is None                  # a stopped Edge agent
    assert "k8s" not in hosts                                                                # Kubernetes is skipped
    web = next(g for g in out["guests"] if g["name"] == "web" and g["host_id"].endswith("/1"))
    assert web["status"] == "running" and web["details"]["project"] == "site" and web["details"]["health"] == "healthy" and web["details"]["restarts"] == 2
    assert [p["host_port"] for p in web["details"]["ports"]] == [8080] and web["details"]["exposed"] is True
    lan = next(g for g in out["guests"] if g["name"] == "lan" and g["host_id"].endswith("/1"))
    assert lan["ips"] == ["192.168.0.60"] and lan["macs"] == ["02:42:c0:a8:00:3c"] and lan["details"]["exit_code"] == 3


def test_message_and_refused_token(portainer):
    message = plugin.test(config(portainer))["message"]
    assert "2 Docker environment(s)" not in message and "3 Docker environment(s), 4 container(s), 2 running" in message and "1 Kubernetes or Azure" in message and "1 environment(s) are down" in message
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(portainer, key="wrong"))
    assert caught.value.auth_failed is True


def test_diagnose_has_counts_only(portainer):
    report = plugin.diagnose(config(portainer))
    text = json.dumps(report)
    assert report["servers"][0]["steps"]["environments"]["count"] == 4
    assert "192.168" not in text and "web" not in text and KEY not in text
