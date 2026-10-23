"""The Ceph plugin against a fake dashboard. The shapes were recorded from a real Ceph 19.2.7 (cephadm) and reduced; the CephFS client
list is the real shape with a client mount added."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "ceph"
spec = importlib.util.spec_from_file_location("ceph_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def stat(n):
    return {"latest": n, "rate": 0.0, "rates": [[1792781478.8, 0.0]]}


FSID = "d9f0bfec-cf11-11f1-8a48-bc2411db66a4"
DATA = {
    "/api/health/minimal": {"health": {"status": "HEALTH_WARN", "checks": [
        {"severity": "HEALTH_WARN", "summary": {"message": "mon playground is low on available space", "count": 1}, "muted": False, "type": "MON_DISK_LOW"},
        {"severity": "HEALTH_ERR", "summary": {"message": "1 osds down", "count": 1}, "muted": False, "type": "OSD_DOWN"},
        {"severity": "HEALTH_WARN", "summary": {"message": "muted one", "count": 1}, "muted": True, "type": "MUTED"}]},
        "df": {"stats": {"total_avail_bytes": 15000, "total_bytes": 25000, "total_used_raw_bytes": 10000}}},
    "/api/monitor": {"mon_status": {"monmap": {"fsid": FSID, "mons": [{"name": "a", "addr": "192.168.0.190:6789/0"}, {"name": "b", "addr": "192.168.0.191:6789/0"}]}}, "in_quorum": [{"name": "a"}]},
    "/api/summary": {"version": "ceph version 19.2.7 (9ec952b9f9668e9fa97e29a4c2b51e951674df2a) squid (stable)"},
    "/api/host": [{"hostname": "ceph1", "addr": "192.168.0.190", "status": ""}, {"hostname": "ceph2", "addr": "192.168.0.192", "status": "maintenance"}],
    "/api/osd": [{"osd": 0, "up": 1, "in": 1, "host": {"name": "ceph1"}, "tree": {"device_class": "hdd"}, "osd_stats": {"statfs": {"total": 8585740288}}},
                 {"osd": 1, "up": 0, "in": 1, "host": {"name": "ceph1"}, "tree": {"device_class": "ssd"}, "osd_stats": {"statfs": {"total": 100}}},
                 {"osd": 2, "up": 1, "in": 0, "host": {"name": "ceph2"}}],
    "/api/pool?stats=true": [{"pool": 2, "pool_name": "rbdpool", "type": "replicated", "size": 3, "stats": {"bytes_used": stat(900), "max_avail": stat(100)}},
                             {"pool": 3, "pool_name": "ec", "type": "erasure", "erasure_code_profile": "k2m1", "stats": {"bytes_used": stat(1), "max_avail": stat(99)}}],
    "/api/cephfs": [{"id": 1, "mdsmap": {"fs_name": "cfs", "info": {"gid_1": {"name": "cfs.a", "state": "up:active"}}}}],
    "/api/cephfs/1/clients": {"status": 0, "data": [
        {"id": 1, "auth_name": {"type": 16, "type_str": "mgr", "id": "x"}, "entity": {"addr": {"addr": "192.168.0.190:0"}}},
        {"id": 2, "auth_name": {"type": 8, "type_str": "client", "id": "admin"}, "entity": {"addr": {"addr": "192.168.0.50:0", "nonce": 5}}},
        {"id": 3, "auth_name": {"type_str": "client"}, "entity": {"addr": {"addr": "192.168.0.50:0", "nonce": 6}}}]},
    "/api/block/image": [{"status": 0, "value": [{"name": "disk1", "pool_name": "rbdpool", "unique_id": "rbdpool/37a2", "size": 1073741824, "total_disk_usage": 4096}], "pool_name": "rbdpool"}],
}


class Dashboard:
    def __init__(self, data=None):
        self.data, self.tokens, self.loggedout = data or DATA, set(), 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if self.path == "/api/auth":
                    if body.get("username") == "u" and body.get("password") == "p":
                        fake.tokens.add("tok")
                        return self._send(201, {"token": "tok", "username": "u"})
                    return self._send(400, {"detail": "Invalid credentials", "code": "invalid_credentials", "component": "auth"})
                if self.path == "/api/auth/logout":
                    fake.loggedout += 1
                    fake.tokens.discard("tok")
                    return self._send(200, {"redirect_url": "#/login"})
                self._send(404, {})

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer tok":
                    return self._send(401, {"detail": "Unauthorized"})
                if self.path == "/api/block/image" and "v2.0" not in (self.headers.get("Accept") or ""):
                    return self._send(415, {"detail": "Incorrect version: endpoint is '2.0', client requested '1.0'"})
                body = fake.data.get(self.path)
                self._send(200, body) if body is not None else self._send(404, {"detail": "not found"})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def config(self, password="p"):
        return {"servers": [{"host": self.url, "username": "u", "password": password}]}


@pytest.fixture
def dash():
    d = Dashboard()
    yield d
    d.server.shutdown()


def test_manifest_and_output_are_valid(dash):
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    out = validate_output("storage", plugin.fetch(dash.config()))
    s = out["systems"][0]
    assert s["id"] == FSID and s["version"] == "19.2.7" and s["health"] == "warning" and dash.loggedout == 1


def test_hosts_monitors_pools(dash):
    out = plugin.fetch(dash.config())
    assert {c["name"]: c["ip"] for c in out["controllers"]} == {"ceph1": "192.168.0.190", "ceph2": "192.168.0.192", "mon.b": "192.168.0.191"}     # mon.a is on ceph1
    pools = {p["name"]: p for p in out["pools"]}
    assert pools["rbdpool"]["total"] == 1000 and pools["rbdpool"]["raid"] == "replica 3" and pools["ec"]["raid"] == "erasure k2m1"
    assert pools["All disks (raw)"]["used"] == 10000


def test_osds_and_checks(dash):
    out = plugin.fetch(dash.config())
    assert {d["name"]: d["state"] for d in out["disks"]} == {"osd.0": "ok", "osd.1": "failed", "osd.2": "degraded"}
    texts = {(a["severity"], a["text"]) for a in out["alerts"]}
    assert ("critical", "1 osds down") in texts and ("warning", "mon playground is low on available space") in texts and ("critical", "osd.1 is down") in texts
    assert not any("muted" in t for _, t in texts)


def test_cephfs_clients_and_rbd_images(dash):
    out = plugin.fetch(dash.config())
    fs = next(v for v in out["volumes"] if v["protocol"] == "cephfs")
    assert fs["clients"] == ["192.168.0.50"]                                  # the manager's own session and duplicates are left out
    rbd = next(v for v in out["volumes"] if v["protocol"] == "rbd")
    assert rbd["size"] == 1073741824 and rbd["pool_id"] == "pool/2"


def test_wrong_password_stops_retrying(dash):
    with pytest.raises(plugin.LoginRefused) as err:
        plugin.fetch(dash.config(password="bad"))
    assert err.value.auth_failed is True


def test_missing_parts_are_noted():
    d = Dashboard({k: v for k, v in DATA.items() if "cephfs" not in k and "block" not in k})
    try:
        msg = plugin.test(d.config())["message"]
        assert "Not available" in msg and "CephFS" in msg
    finally:
        d.server.shutdown()


def test_diagnose_is_private(dash):
    text = json.dumps(plugin.diagnose(dash.config()))
    for secret in (FSID, "192.168.0", "127.0.0.1", "ceph1", "rbdpool", "disk1"):
        assert secret not in text
    assert '"ok": true' in text and dash.loggedout >= 1
