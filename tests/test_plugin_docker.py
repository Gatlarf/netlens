"""The Docker plugin against a simulated Docker API: containers, macvlan matching, health, ports and safety."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from app.plugins.matching import match_hypervisor
from tests.fake_docker import FakeDocker, container

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "docker"
spec = importlib.util.spec_from_file_location("docker_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

LAN_MAC = "02:42:c0:a8:00:32"


def containers():
    return [
        container("c1", "web", ports=[{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
                  networks={"bridge": {"NetworkID": "n-bridge", "IPAddress": "172.17.0.2", "MacAddress": "02:42:ac:11:00:02"}},
                  labels={"com.docker.compose.project": "shop", "com.docker.compose.service": "web"}, image="nginx:1.27"),
        container("c2", "app", networks={"lan": {"NetworkID": "n-lan", "IPAddress": "192.168.0.50", "MacAddress": LAN_MAC}}),
        container("c3", "tv", networks={"ipv": {"NetworkID": "n-ipv", "IPAddress": "192.168.0.51", "MacAddress": "aa:bb:cc:dd:ee:01"}}),
        container("c4", "agent", mode="host", networks={"host": {"NetworkID": "n-host", "IPAddress": ""}}),
        container("c5", "old", state="exited"),
        container("c6", "flaky", state="restarting", networks={"bridge": {"NetworkID": "n-bridge", "IPAddress": "172.17.0.3"}}),
        container("c7", "local", ports=[{"IP": "127.0.0.1", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}], networks={"bridge": {"NetworkID": "n-bridge", "IPAddress": "172.17.0.4"}}),
    ]


INSPECT = {
    "c1": {"RestartCount": 0, "State": {"StartedAt": "2026-10-01T10:00:00Z", "Health": {"Status": "healthy"}}},
    "c5": {"RestartCount": 0, "State": {"ExitCode": 137}},
    "c6": {"RestartCount": 14, "State": {"Restarting": True, "StartedAt": "2026-10-10T10:00:00Z"}},
}


@pytest.fixture
def docker():
    with FakeDocker(containers=containers(), inspect=INSPECT) as d:
        yield d


def config(*urls):
    return {"hosts": " ".join(urls), "verify_tls": True, "timeout": 5}


def guests_by_name(output):
    return {g["name"]: g for g in output["guests"]}


def test_manifest_and_output_follow_the_contract(docker):
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    out = validate_output("hypervisor", plugin.fetch(config(docker.url)))
    assert len(out["hosts"]) == 1 and out["hosts"][0]["name"] == "dockerhost" and out["hosts"][0]["ip"] == "127.0.0.1"
    assert len(out["guests"]) == 7 and all(g["kind"] == "container" for g in out["guests"])


def test_bridge_container_is_a_guest_without_lan_address(docker):
    web = guests_by_name(plugin.fetch(config(docker.url)))["web"]
    assert web["ips"] == [] and web["macs"] == []                       # 172.17.x is inside the host, not a LAN address
    d = web["details"]
    assert d["image"] == "nginx:1.27" and d["project"] == "shop" and d["service"] == "web" and d["health"] == "healthy"
    assert d["exposed"] is True and d["network_driver"] == "bridge"
    assert [(p["host_port"], p["container_port"]) for p in d["ports"]] == [(8080, 80)]   # the IPv4 and IPv6 line are one port


def test_macvlan_and_ipvlan_containers_report_their_lan_address(docker):
    guests = guests_by_name(plugin.fetch(config(docker.url)))
    assert guests["app"]["ips"] == ["192.168.0.50"] and guests["app"]["macs"] == [LAN_MAC]
    assert guests["tv"]["ips"] == ["192.168.0.51"] and guests["tv"]["macs"] == []       # ipvlan shares the host's MAC
    assert guests["app"]["details"]["network_driver"] == "macvlan"


def test_host_network_state_restarts_and_exposure(docker):
    guests = guests_by_name(plugin.fetch(config(docker.url)))
    assert guests["agent"]["details"]["network_driver"] == "host" and guests["agent"]["ips"] == []
    assert guests["old"]["status"] == "exited" and guests["old"]["details"]["exit_code"] == 137
    assert guests["flaky"]["status"] == "restarting" and guests["flaky"]["details"]["restarts"] == 14
    assert guests["local"]["details"]["exposed"] is False and guests["web"]["details"]["exposed"] is True    # published on 127.0.0.1 only = not exposed


def test_a_macvlan_container_is_matched_to_the_scanned_device(docker):
    out = validate_output("hypervisor", plugin.fetch(config(docker.url)))
    devices = [{"id": 1, "mac": "aa:aa:aa:aa:aa:01", "ips": ["127.0.0.1"]}, {"id": 2, "mac": LAN_MAC, "ips": ["192.168.0.50"]},
               {"id": 3, "mac": "aa:bb:cc:dd:ee:01", "ips": ["192.168.0.51"]}, {"id": 4, "mac": "bb:bb:bb:bb:bb:09", "ips": ["172.17.0.2"]}]
    matched = match_hypervisor(out, devices)
    by_name = {g["name"]: g for g in matched["guests"]}
    assert matched["hosts"][out["hosts"][0]["id"]] == 1
    assert by_name["app"]["device_id"] == 2 and by_name["tv"]["device_id"] == 3      # macvlan by MAC, ipvlan by IP
    assert by_name["web"]["device_id"] is None                                       # a bridge address never matches a LAN device
    assert by_name["web"]["host_device_id"] == 1


def test_only_get_requests_are_sent(docker):
    plugin.fetch(config(docker.url))
    assert docker.requests and all(method == "GET" for method, _ in docker.requests)


def test_two_hosts_and_one_down(docker):
    with FakeDocker(containers=[container("x1", "solo")], name="second") as other:
        out = plugin.fetch(config(docker.url, other.url))
        assert [h["name"] for h in out["hosts"]] == ["dockerhost", "second"]
        assert {g["host_id"] for g in out["guests"]} == {h["id"] for h in out["hosts"]}
    message = plugin.test(config(docker.url, "http://127.0.0.1:9"))["message"]
    assert "Connected to 1 Docker host" in message and "Not reachable" in message


def test_everything_down_is_an_error():
    with pytest.raises(plugin.DockerError):
        plugin.fetch(config("http://127.0.0.1:9"))


def test_a_proxy_that_forbids_containers_gets_a_helpful_message():
    with FakeDocker(forbid=("/containers",)) as d:
        with pytest.raises(plugin.DockerError, match="CONTAINERS=1"):
            plugin.fetch(config(d.url))


def test_missing_inspect_still_lists_the_container():
    with FakeDocker(containers=[container("z", "plain")], inspect={}) as d:
        guests = plugin.fetch(config(d.url))["guests"]
    assert guests[0]["name"] == "plain" and "health" not in guests[0]["details"]


def test_bad_settings():
    with pytest.raises(ValueError):
        plugin.parse_hosts({"hosts": ""})
    with pytest.raises(plugin.DockerError):
        plugin.parse_hosts({"hosts": "ftp://x"})


def test_diagnose_reports_counts_only(docker):
    text = json.dumps(plugin.diagnose(config(docker.url)))
    assert "dockerhost" not in text and "nginx" not in text and "192.168" not in text
    report = plugin.diagnose(config(docker.url))["hosts"][0]["steps"]
    assert report["containers"]["count"] == 7 and report["networks"]["drivers"]["macvlan"] == 1


# ----------------------------------------------------------------------------- through Netlens
import shutil

from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device
from app.main import create_app


def test_netlens_stores_container_details_and_shows_them(tmp_path):
    data = tmp_path / "data"
    shutil.copytree(ROOT, data / "plugins" / "docker", ignore=shutil.ignore_patterns("__pycache__", "README.md"))
    with FakeDocker(containers=containers(), inspect=INSPECT) as d:
        app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(data)}), db_path=tmp_path / "t.db")
        with TestClient(app, headers={"Authorization": "Bearer t"}) as client:
            conn = connect(tmp_path / "t.db")
            host = get_or_create_device(conn, "aa:aa:aa:aa:aa:01", "127.0.0.1")
            lan = get_or_create_device(conn, LAN_MAC, "192.168.0.50")
            conn.commit()
            conn.close()
            assert client.put("/api/plugins/docker", json={"enabled": True, "config": {"hosts": d.url, "timeout": 5}}).status_code == 200
            r = client.post("/api/plugins/docker/sync")
            assert r.status_code == 200 and r.json().get("error") is None, r.text
            info = client.get(f"/api/devices/{host}").json()["virtualization"]
            names = {g["name"]: g for g in info["guests"]}
            assert len(names) == 7 and names["web"]["details"]["image"] == "nginx:1.27" and names["web"]["details"]["ports"][0]["host_port"] == 8080
            assert names["app"]["device_id"] == lan and names["web"]["device_id"] is None
            guest = client.get(f"/api/devices/{lan}").json()["virtualization"]["guest"]
            assert guest["kind"] == "container" and guest["host_device_id"] == host and guest["details"]["network_driver"] == "macvlan"
