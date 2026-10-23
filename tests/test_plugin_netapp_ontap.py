"""The NetApp ONTAP plugin against a fake cluster that answers the documented REST shapes (no real cluster was available)."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "netapp-ontap"
spec = importlib.util.spec_from_file_location("ontap_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

DATA = {
    "/api/cluster": {"name": "cl1", "uuid": "c-uuid", "version": {"full": "NetApp Release 9.14.1P3", "generation": 9}, "management_interfaces": [{"ip": {"address": "192.168.0.80"}}]},
    "/api/cluster/nodes": {"records": [
        {"name": "cl1-01", "uuid": "n1", "model": "AFF-A250", "serial_number": "SER1", "state": "up", "management_interfaces": [{"ip": {"address": "192.168.0.81"}}],
         "controller": {"failed_fan": {"count": 1}, "failed_power_supply": {"count": 0}, "over_temperature": "normal"}},
        {"name": "cl1-02", "uuid": "n2", "state": "down", "management_interfaces": [{"ip": {"address": "192.168.0.82"}}]}]},
    "/api/network/ethernet/ports": {"records": [{"name": "e0M", "mac_address": "00:A0:98:11:22:33", "node": {"name": "cl1-01"}}, {"name": "e0a", "mac_address": "00:A0:98:11:22:44", "node": {"name": "cl1-01"}}]},
    "/api/storage/aggregates": {"records": [
        {"name": "aggr1", "uuid": "a1", "state": "online", "space": {"block_storage": {"size": 1000, "used": 970, "available": 30}}, "block_storage": {"primary": {"raid_type": "raid_dp"}}},
        {"name": "aggr2", "uuid": "a2", "state": "offline", "space": {"block_storage": {"size": 500, "used": 0, "available": 500}}}]},
    "/api/storage/volumes": {"records": [
        {"name": "vol0", "uuid": "v0", "svm": {"name": "cl1"}, "state": "online"},
        {"name": "data", "uuid": "v1", "svm": {"name": "svm1"}, "state": "online", "type": "rw", "space": {"size": 100, "used": 40}, "nas": {"path": "/data"}, "aggregates": [{"name": "aggr1"}]},
        {"name": "mirror", "uuid": "v2", "svm": {"name": "svm1"}, "state": "online", "type": "dp"}]},
    "/api/storage/luns": {"records": [{"name": "/vol/data/lun1", "uuid": "l1", "svm": {"name": "svm1"}, "status": {"state": "online"}, "space": {"size": 50, "used": 5}}]},
    "/api/storage/disks": {"records": [{"name": "1.0.1", "uuid": "d1", "state": "present", "container_type": "aggregate", "usable_size": 900, "bay": 1, "shelf": {"uid": "5"}},
                                       {"name": "1.0.2", "uuid": "d2", "state": "broken", "container_type": "broken", "bay": 2}, {"name": "1.0.3", "uuid": "d3", "state": "present", "container_type": "spare", "bay": 3}]},
    "/api/protocols/nfs/connected-clients": {"records": [{"client_ip": "10.0.0.20", "svm": {"name": "svm1"}, "volume": {"name": "data"}}, {"client_ip": "10.0.0.20", "svm": {"name": "svm1"}, "volume": {"name": "data"}}]},
    "/api/support/ems/events": {"records": [{"message": {"name": "disk.failed", "severity": "alert"}, "time": "2999-01-01T00:00:00+00:00", "log_message": "Disk 1.0.2 failed"},
                                            {"message": {"name": "old.event", "severity": "error"}, "time": "2020-01-01T00:00:00+00:00", "log_message": "ancient"}]},
}


class Cluster:
    def __init__(self, data=None):
        self.data = data or DATA
        self.seen = []
        fake = self
        auth = "Basic " + base64.b64encode(b"u:p").decode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parts = urlsplit(self.path)
                fake.seen.append(self.path)
                if self.headers.get("Authorization") != auth:
                    return self._send(401, {"error": {"message": "Authentication failed"}})
                body = fake.data.get(parts.path)
                self._send(200, body) if body is not None else self._send(404, {"error": {"message": "entry doesn't exist"}})

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def config(self, password="p"):
        return {"servers": [{"host": self.url, "username": "u", "password": password}]}


@pytest.fixture
def cluster():
    c = Cluster()
    yield c
    c.server.shutdown()


def test_manifest_and_output_are_valid(cluster):
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    out = validate_output("storage", plugin.fetch(cluster.config()))
    assert out["systems"][0]["name"] == "cl1" and out["systems"][0]["vendor"] == "NetApp" and out["systems"][0]["serial"] == "SER1"


def test_nodes_pools_volumes_disks(cluster):
    out = plugin.fetch(cluster.config())
    nodes = {c["name"]: c for c in out["controllers"]}
    assert nodes["cl1-01"]["mac"] == "00:a0:98:11:22:33" and nodes["cl1-01"]["ip"] == "192.168.0.81"      # the e0M port wins
    assert nodes["cl1-02"]["online"] is False and nodes["cl1-02"]["health"] == "critical"
    assert {p["name"]: p["health"] for p in out["pools"]} == {"aggr1": "ok", "aggr2": "critical"}
    names = {v["name"] for v in out["volumes"]}
    assert names == {"svm1:data", "/vol/data/lun1"}                                                     # root and dp volumes are left out
    data = next(v for v in out["volumes"] if v["name"] == "svm1:data")
    assert data["clients"] == ["10.0.0.20", "10.0.0.20"] and data["pool_id"] == "a1" and data["size"] == 100
    assert {d["name"]: d["state"] for d in out["disks"]} == {"1.0.1": "ok", "1.0.2": "failed", "1.0.3": "spare"}
    assert out["disks"][0]["slot"] == "5.1"


def test_health_and_alerts(cluster):
    out = plugin.fetch(cluster.config())
    assert out["systems"][0]["health"] == "critical"
    texts = {a["text"] for a in out["alerts"]}
    assert "Node cl1-01: 1 failed fan(s)" in texts and "Aggregate aggr2 is offline" in texts and "Disk 1.0.2 failed" in texts
    assert "ancient" not in texts                                                                         # events older than a day are ignored


def test_missing_nfs_clients_is_a_note_not_an_error():
    data = {k: v for k, v in DATA.items() if "nfs" not in k}
    c = Cluster(data)
    try:
        assert "NFS clients" in plugin.test(c.config())["message"]
        assert all(v["clients"] == [] for v in plugin.fetch(c.config())["volumes"])
    finally:
        c.server.shutdown()


def test_wrong_password_stops_retrying(cluster):
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(cluster.config(password="bad"))
    assert err.value.auth_failed is True


def test_diagnose_is_private(cluster):
    text = json.dumps(plugin.diagnose(cluster.config()))
    for secret in ("SER1", "00:a0", "00:A0", "192.168.0", "127.0.0.1", "10.0.0.20", "cl1-01", "svm1"):
        assert secret not in text
    assert '"ok": true' in text
