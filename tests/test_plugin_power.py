"""Power actions of the hypervisor plugins (restart / stop / start a guest) against fake transports."""

import io
import json
import urllib.error

import pytest

from tests.plugin_modules import load


class Fake:
    """Replaces urllib.request.urlopen of a plugin: records the request, answers with a status (or raises an HTTP error)."""

    def __init__(self, status=204, body=b"{}"):
        self.status, self.body, self.requests = status, body, []

    def __call__(self, request, timeout=None, context=None):
        self.requests.append((request.get_method(), request.full_url, request.data, dict(request.header_items())))
        if self.status >= 300:
            raise urllib.error.HTTPError(request.full_url, self.status, "x", {}, io.BytesIO(b""))
        outer = self

        class Response(io.BytesIO):
            status = outer.status

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return Response(self.body)


def patch(monkeypatch, module, fake):
    monkeypatch.setattr(module.urllib.request, "urlopen", fake)


def test_docker_reset_restarts_the_container_and_explains_a_refusing_proxy(monkeypatch):
    docker = load("docker")
    cfg = {"servers": [{"host": "http://10.0.0.5:2375"}]}
    fake = Fake(204)
    patch(monkeypatch, docker, fake)
    out = docker.power(cfg, {"guest_id": "10.0.0.5:2375/web", "action": "reset"})
    assert out["message"] == "restart sent to web"
    assert fake.requests[0][:2] == ("POST", "http://10.0.0.5:2375/containers/web/restart?t=5")
    docker.power(cfg, {"guest_id": "10.0.0.5:2375/web", "action": "shutdown"})
    assert fake.requests[1][1].endswith("/containers/web/stop?t=20")
    patch(monkeypatch, docker, Fake(304))
    assert "already running" in docker.power(cfg, {"guest_id": "10.0.0.5:2375/web", "action": "start"})["message"]
    patch(monkeypatch, docker, Fake(403))
    with pytest.raises(docker.DockerError, match="ALLOW_RESTARTS"):
        docker.power(cfg, {"guest_id": "10.0.0.5:2375/web", "action": "reset"})
    with pytest.raises(docker.DockerError, match="not in the plugin"):
        docker.power(cfg, {"guest_id": "10.9.9.9:2375/web", "action": "reset"})
    with pytest.raises(ValueError):
        docker.power(cfg, {"guest_id": "10.0.0.5:2375/web", "action": "delete"})


def test_portainer_restarts_a_container_in_its_environment(monkeypatch):
    px = load("portainer")
    cfg = {"servers": [{"host": "https://10.0.0.6:9443", "api_key": "KEY"}]}
    fake = Fake(204)
    patch(monkeypatch, px, fake)
    assert px.power(cfg, {"guest_id": "10.0.0.6:9443/2/web", "action": "reboot"})["message"] == "restart sent to web"
    method, url, _, headers = fake.requests[0]
    assert (method, url) == ("POST", "https://10.0.0.6:9443/api/endpoints/2/docker/containers/web/restart?t=10") and headers["X-api-key"] == "KEY"
    patch(monkeypatch, px, Fake(403))
    with pytest.raises(px.PortainerError, match="may not"):
        px.power(cfg, {"guest_id": "10.0.0.6:9443/2/web", "action": "reset"})


def test_incus_reset_is_a_forced_restart_in_the_project(monkeypatch):
    incus = load("incus")
    server = incus.Server.__new__(incus.Server)
    server.url, server.timeout, server.id, server.context = "https://10.0.0.7:8443", 5.0, "10.0.0.7:8443", None
    monkeypatch.setattr(incus, "parse_servers", lambda config: [server])
    fake = Fake(202, json.dumps({"type": "async", "metadata": {}}).encode())
    patch(monkeypatch, incus, fake)
    assert incus.power({}, {"guest_id": "10.0.0.7:8443/default/web", "action": "reset"})["message"] == "restart sent to web"
    method, url, data, _ = fake.requests[0]
    assert (method, url) == ("PUT", "https://10.0.0.7:8443/1.0/instances/web/state?project=default") and json.loads(data) == {"action": "restart", "force": True, "timeout": 10}


def test_vsphere_calls_the_task_of_the_virtual_machine(monkeypatch):
    vs = load("vsphere")
    calls = []

    class Session:
        id = "esx.test"

        def login(self):
            calls.append("login")

        def call(self, method, inner):
            calls.append((method, inner))

        def logout(self):
            calls.append("logout")

    monkeypatch.setattr(vs, "parse_sessions", lambda config: [Session()])
    out = vs.power({}, {"guest_id": "esx.test/vm-12", "action": "reset", "name": "blueiris"})
    assert out["message"] == "ResetVM sent to blueiris" and calls == ["login", ("ResetVM_Task", '<_this type="VirtualMachine">vm-12</_this>'), "logout"]
    with pytest.raises(vs.VsphereError):
        vs.power({}, {"guest_id": "esx.test/vm-12;drop", "action": "reset"})


def test_hyperv_resets_by_wmi_and_checks_the_id(monkeypatch):
    hv = load("hyperv")
    ran = []

    class Session:
        id = "10.0.0.8:5986"

        def run_powershell(self, script):
            ran.append(script)
            return "ok\n", "", 0

        def close(self):
            ran.append("closed")

    monkeypatch.setattr(hv, "parse_servers", lambda config: [Session()])
    guid = "5CC4F79B-959F-482E-BF60-D8C1C685E3CB"
    assert hv.power({}, {"guest_id": f"10.0.0.8:5986/{guid}", "action": "reset", "name": "AtosVM"})["message"] == "reset sent to AtosVM"
    assert guid in ran[0] and "RequestedState=[uint16]11" in ran[0] and ran[-1] == "closed"
    with pytest.raises(hv.HyperVError):
        hv.power({}, {"guest_id": "10.0.0.8:5986/x'; Remove-VM *", "action": "reset"})
    with pytest.raises(ValueError):
        hv.power({}, {"guest_id": f"10.0.0.8:5986/{guid}", "action": "reboot"})
