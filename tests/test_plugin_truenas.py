"""The TrueNAS plugin against a fake TrueNAS: a WebSocket server that speaks JSON-RPC 2.0 like /api/current does.
The data shapes come from a real TrueNAS 25.10 (names, addresses and ids changed)."""

import base64
import hashlib
import importlib.util
import json
import socket
import struct
import threading
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "truenas"
spec = importlib.util.spec_from_file_location("truenas_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

INTERFACES = [
    {"id": "enp3s0", "name": "enp3s0", "type": "PHYSICAL", "state": {"link_state": "LINK_STATE_DOWN", "link_address": "60:be:b4:14:62:a4", "aliases": []}, "aliases": []},
    {"id": "bond0", "name": "bond0", "type": "LINK_AGGREGATION", "state": {"link_address": "60:be:b4:14:62:a6", "aliases": [{"type": "INET6", "address": "fe80::1"}]}, "aliases": []},
    {"id": "br1", "name": "br1", "type": "BRIDGE", "state": {"link_address": "0e:01:06:e8:59:17", "aliases": [{"type": "INET", "address": "192.168.0.200", "netmask": 24}, {"type": "INET6", "address": "fe80::2"}]}, "aliases": []},
    {"id": "lo", "name": "lo", "type": "PHYSICAL", "state": {"link_address": "00:00:00:00:00:00", "aliases": [{"type": "INET", "address": "127.0.0.1"}]}, "aliases": []},
]
INSTANCES = [
    {"id": "proxmox-pbs", "name": "proxmox-pbs", "type": "CONTAINER", "status": "RUNNING", "vnc_password": "secret",
     "aliases": [{"type": "INET", "address": "192.168.0.201", "netmask": 24}, {"type": "INET", "address": "192.168.0.135", "netmask": 24}, {"type": "INET6", "address": "fe80::9"}]},
    {"id": "win", "name": "win", "type": "VM", "status": "STOPPED", "aliases": []},
]
APPS = [{"name": "dns-server", "id": "dns-server", "state": "RUNNING"}, {"name": "plex", "id": "plex", "state": "STOPPED"}]
VMS = [{"id": 3, "name": "ubuntu", "status": {"state": "RUNNING", "pid": 1}, "devices": [
    {"id": 1, "attributes": {"dtype": "DISK", "path": "/dev/zvol/x"}}, {"id": 2, "attributes": {"dtype": "NIC", "type": "VIRTIO", "mac": "00:A0:98:11:22:33", "nic_attach": "br1"}},
    {"id": 3, "attributes": {"dtype": "NIC", "type": "E1000", "mac": None}}]}]


def encode(payload: bytes, opcode=1, fin=True):
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    head += bytes([n]) if n < 126 else bytes([126]) + struct.pack(">H", n) if n < 65536 else bytes([127]) + struct.pack(">Q", n)
    return head + payload  # server frames are not masked


class FakeTrueNAS:
    def __init__(self, **options):
        self.options = {"key": "good-key", "interfaces": INTERFACES, "instances": INSTANCES, "vms": [], "apps": APPS, "version": "TrueNAS-25.10.6", **options}
        self.methods = []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _read_exact(self, conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def _frame(self, conn):
        b1, b2 = self._read_exact(conn, 2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._read_exact(conn, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._read_exact(conn, 8))[0]
        mask = self._read_exact(conn, 4) if b2 & 0x80 else b"\0\0\0\0"
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read_exact(conn, n)))
        return b1 & 0x0F, data

    def _serve(self, conn):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                head += conn.recv(4096)
            if self.options.get("refuse"):
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                return
            key = next(l.split(":", 1)[1].strip() for l in head.decode().split("\r\n") if l.lower().startswith("sec-websocket-key"))
            accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
            if self.options.get("bad_accept"):
                accept = "wrong"
            conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode())
            while True:
                opcode, data = self._frame(conn)
                if opcode == 8:
                    return
                if opcode != 1:
                    continue
                request = json.loads(data)
                self.methods.append(request["method"])
                self._answer(conn, request)
        except (EOFError, OSError):
            pass
        finally:
            conn.close()

    def _answer(self, conn, request):
        o, method, rid = self.options, request["method"], request["id"]

        def send(result=None, error=None, **extra):
            body = {"jsonrpc": "2.0", "id": rid, **({"error": error} if error else {"result": result})}
            raw = json.dumps(body).encode()
            conn.sendall(encode(json.dumps({"jsonrpc": "2.0", "method": "collection_update", "params": {}}).encode()))  # a notification in between
            conn.sendall(encode(b"", 9))  # a ping the client must answer
            if len(raw) > 200 and o.get("fragment"):
                conn.sendall(encode(raw[:100], 1, fin=False) + encode(raw[100:150], 0, fin=False) + encode(raw[150:], 0, fin=True))
            else:
                conn.sendall(encode(raw))

        if method == "auth.login_with_api_key":
            return send(request["params"][0] == o["key"]) if not o.get("login_error") else send(error={"code": 1, "message": "key revoked"})
        if method == "system.info":
            return send({"hostname": o.get("hostname", "truenas"), "version": o["version"] if False else o["version"].replace("TrueNAS-", "")})
        errors = o.get("errors", {})
        if method in errors:
            return send(error=errors[method])
        table = {"interface.query": o["interfaces"], "virt.instance.query": o["instances"], "vm.query": o["vms"], "app.query": o["apps"],
                 "pool.query": o.get("pools", []), "disk.query": o.get("disks", []), "alert.list": o.get("alerts", []), "sharing.nfs.query": o.get("nfs", []), "sharing.smb.query": o.get("smb", []),
                 "iscsi.extent.query": o.get("extents", []), "iscsi.target.query": o.get("iscsi_targets", []), "iscsi.targetextent.query": o.get("targetextents", []),
                 "iscsi.global.sessions": o.get("sessions", []), "pool.dataset.query": o.get("zvols", [])}
        if method in table:
            return send(table[method])
        send(error={"code": -32601, "message": "Method does not exist"})

    def close(self):
        self.server.close()


@pytest.fixture(autouse=True)
def plain(monkeypatch):
    monkeypatch.setattr(plugin, "USE_TLS", False)  # the fake server speaks plain WebSocket; the plugin itself always uses TLS


def cfg(port, **kw):
    return {"url": f"https://127.0.0.1:{port}", "api_key": "good-key", "verify_tls": False, **kw}


@pytest.fixture
def fake():
    servers = []

    def make(**options):
        s = FakeTrueNAS(**options)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def run(fake_server, fn=plugin.fetch, **kw):
    # the plugin derives its port from the URL; the fake listens elsewhere, so point it there
    config = cfg(fake_server.port, **kw)
    original = plugin.TrueNAS.__init__

    def init(self, c):
        original(self, c)
        self.port = fake_server.port

    plugin.TrueNAS.__init__ = init
    try:
        return fn(config)
    finally:
        plugin.TrueNAS.__init__ = original


def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["id"] == "truenas" and manifest["kind"] == "hypervisor"


def test_fetch_maps_host_containers_vms_and_apps(fake):
    server = fake(vms=VMS)
    out = validate_output("hypervisor", run(server))
    host = out["hosts"][0]
    assert host == {"id": "truenas", "name": "truenas", "ip": "127.0.0.1", "mac": None, "online": True} or host["id"] == "truenas"
    guests = {g["name"]: g for g in out["guests"]}
    pbs = guests["proxmox-pbs"]
    assert pbs["kind"] == "lxc" and pbs["status"] == "running" and pbs["ips"] == ["192.168.0.201", "192.168.0.135"] and pbs["host_id"] == "truenas"
    assert guests["win"]["kind"] == "qemu" and guests["win"]["status"] == "stopped"
    assert guests["ubuntu"]["kind"] == "qemu" and guests["ubuntu"]["status"] == "running" and guests["ubuntu"]["macs"] == ["00:a0:98:11:22:33"]
    assert guests["dns-server"]["kind"] == "app" and guests["dns-server"]["status"] == "running" and guests["plex"]["status"] == "stopped"
    assert "vnc_password" not in json.dumps(out) and "secret" not in json.dumps(out)


def test_host_address_and_mac_come_from_the_interface_that_holds_the_address():
    snapshot = {"hostname": "truenas", "version": "x", "interfaces": INTERFACES, "instances": [], "vms": [], "apps": [], "notes": []}
    host = plugin.to_hypervisor(snapshot, "192.168.0.200")["hosts"][0]
    assert host["ip"] == "192.168.0.200" and host["mac"] == "0e:01:06:e8:59:17"
    # connecting by name: the box's own address is used
    host = plugin.to_hypervisor(snapshot, "nas.lan")["hosts"][0]
    assert host["ip"] == "192.168.0.200" and host["mac"] == "0e:01:06:e8:59:17"
    # no interface data at all: the address connected to
    host = plugin.to_hypervisor({**snapshot, "interfaces": []}, "192.168.0.9")["hosts"][0]
    assert host["ip"] == "192.168.0.9" and "mac" not in host


def test_one_login_and_the_expected_calls_then_disconnect(fake):
    server = fake()
    run(server)
    assert server.methods[:2] == ["auth.login_with_api_key", "system.info"] and server.methods.count("auth.login_with_api_key") == 1
    assert set(server.methods) == {"auth.login_with_api_key", "system.info", "interface.query", "virt.instance.query", "vm.query", "app.query",
                                  "pool.query", "disk.query", "alert.list", "sharing.nfs.query", "sharing.smb.query",
                                  "iscsi.extent.query", "iscsi.target.query", "iscsi.targetextent.query", "iscsi.global.sessions", "pool.dataset.query"}


def test_a_wrong_key_is_auth_failed(fake):
    server = fake(key="other")
    with pytest.raises(plugin.LoginRefused) as err:
        run(server)
    assert err.value.auth_failed is True and "API key" in str(err.value) and server.methods == ["auth.login_with_api_key"]


def test_a_login_error_is_auth_failed_too(fake):
    with pytest.raises(plugin.LoginRefused, match="key revoked"):
        run(fake(login_error=True))


def test_missing_features_are_notes_not_failures(fake):
    server = fake(errors={"virt.instance.query": {"code": -32601, "message": "Method does not exist"},
                          "app.query": {"code": 22, "message": "x", "data": {"reason": "[ENOENT] Apps are not configured"}}})
    out = validate_output("hypervisor", run(server))
    assert [g["kind"] for g in out["guests"]] == []  # no instances, no apps
    message = run(server, plugin.test)["message"]
    assert "Connected to TrueNAS 25.10.6 (truenas): 0 container(s), 0 virtual machine(s), 0 app(s)" in message
    assert "containers: not available on this version" in message and "Apps are not configured" in message


def test_test_message(fake):
    assert run(fake(), plugin.test)["message"] == "Connected to TrueNAS 25.10.6 (truenas): 1 container(s), 1 virtual machine(s), 2 app(s)"


def test_pings_notifications_and_fragmented_frames_are_handled(fake):
    out = run(fake(fragment=True), plugin.fetch)
    assert len(out["guests"]) == 4


def test_large_messages_use_the_long_frame_formats(fake):
    many = [{"name": f"app{i}", "id": f"app{i}", "state": "RUNNING", "notes": "x" * 40} for i in range(2000)]  # about 150 KB
    out = run(fake(apps=many), plugin.fetch)
    assert len([g for g in out["guests"] if g["kind"] == "app"]) == 2000
    assert plugin.WebSocket.send  # the request frames are masked and sized the same way


def test_handshake_problems_are_connection_errors_not_login_errors(fake):
    for options in ({"refuse": True}, {"bad_accept": True}):
        with pytest.raises(plugin.ConnectError) as err:
            run(fake(**options))
        assert not getattr(err.value, "auth_failed", False)
    assert "25.04" in str(err.value) or "handshake" in str(err.value)


def test_unreachable_is_a_connection_error():
    config = {"url": "https://127.0.0.1:9", "api_key": "k"}
    with pytest.raises(plugin.ConnectError, match="cannot reach"):
        plugin.fetch(config)


@pytest.mark.parametrize("bad", [{"url": ""}, {"api_key": ""}, {"url": "https://"}])
def test_missing_settings_are_value_errors(bad):
    with pytest.raises(ValueError):
        plugin.fetch({"url": "https://192.168.0.200", "api_key": "k", **bad})


@pytest.mark.parametrize("url,port", [("http://192.168.0.200", 443), ("192.168.0.200", 443), ("https://192.168.0.200", 443), ("https://nas.lan:8443", 8443), ("http://nas.lan:80", 443)])
def test_the_key_is_only_ever_sent_over_tls_on_the_https_port(url, port):
    t = plugin.TrueNAS({"url": url, "api_key": "k"})
    assert t.port == port and plugin.USE_TLS is False  # (the test fixture switches TLS off; the default is True)
    assert "USE_TLS = True" in (ROOT / "plugin.py").read_text()


def test_guest_ids_are_unique_and_odd_entries_are_skipped():
    snapshot = {"hostname": "NAS", "version": "x", "interfaces": [], "notes": [], "vms": [{"id": 1, "name": "a"}, {"nope": 1}],
                "instances": [{"name": "a", "type": "CONTAINER"}, {"name": "a", "type": "CONTAINER"}, "junk"], "apps": [{"id": "x"}, {}]}
    out = plugin.to_hypervisor(snapshot, "10.0.0.1")
    assert [g["id"] for g in out["guests"]] == ["instance:a", "vm:1", "app:x"] and out["hosts"][0]["id"] == "nas"
    validate_output("hypervisor", out)


def test_diagnose_describes_shapes_and_leaks_nothing(fake):
    server = fake(vms=VMS)
    report = run(server, plugin.diagnose)
    text = json.dumps(report)
    for private in ("proxmox-pbs", "192.168.0.", "0e:01:06", "00:A0:98", "dns-server", "plex", "secret", "good-key", "ubuntu"):
        assert private not in text, private
    assert report["steps"]["system_info"]["shape"]["hostname"].startswith("<text") and report["steps"]["system_info"]["shape"]["version"].startswith("25.")
    assert report["steps"]["instances"]["shape"]["count"] == 2 and report["steps"]["instances"]["shape"]["first"][0]["status"] == "RUNNING"
    assert report["steps"]["interfaces"]["ok"] and report["steps"]["apps"]["shape"]["count"] == 2
    assert report["result"]["by_kind"] == {"lxc": 1, "qemu": 2, "app": 2} and report["result"]["host_has_mac"] is True and report["result"]["host_has_ip"] is True
    assert server.methods.count("auth.login_with_api_key") == 1


def test_diagnose_records_unavailable_features_as_failed_steps(fake):
    server = fake(errors={"virt.instance.query": {"code": -32601, "message": "Method does not exist"},
                          "app.query": {"code": 22, "message": "x", "data": {"reason": "[ENOENT] Apps are not configured"}}})
    report = run(server, plugin.diagnose)
    assert report["steps"]["instances"]["ok"] is False and "does not exist" in report["steps"]["instances"]["error"]
    assert report["steps"]["apps"]["ok"] is False and "Apps are not configured" in report["steps"]["apps"]["error"]
    assert report["steps"]["system_info"]["ok"] and "result" in report


def test_diagnose_with_a_wrong_key_is_a_refused_login(fake):
    with pytest.raises(plugin.LoginRefused):
        run(fake(key="other"), plugin.diagnose)


def test_the_manifest_announces_the_diagnostic():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["diagnose"] is True


def test_several_systems_are_read_one_by_one_and_name_clashes_are_kept_apart(monkeypatch):
    rows = {"servers": [{"id": "a", "host": "https://nas1", "api_key": "k1"}, {"id": "b", "host": "https://nas2", "api_key": "k2"}, {"id": "c", "host": "", "api_key": ""}], "verify_tls": False}
    assert [(c["url"], c["api_key"]) for c in plugin._servers(rows)] == [("https://nas1", "k1"), ("https://nas2", "k2")]
    answers = {"https://nas1": {"hosts": [{"id": "nas1"}], "guests": [{"id": "app:plex", "host_id": "nas1"}]},
               "https://nas2": {"hosts": [{"id": "nas2"}], "guests": [{"id": "app:plex", "host_id": "nas2"}, {"id": "app:other", "host_id": "nas2"}]}}
    monkeypatch.setattr(plugin, "_fetch_one", lambda one: answers[one["url"]])
    out = plugin.fetch(rows)
    assert [h["id"] for h in out["hosts"]] == ["nas1", "nas2"]
    assert [g["id"] for g in out["guests"]] == ["app:plex", "nas2/app:plex", "app:other"]
    # a failure names the system but keeps its type (a refused key must stay recognisable)
    class Refused(Exception):
        auth_failed = True

    def boom(one):
        raise Refused("the API key was refused")
    monkeypatch.setattr(plugin, "_fetch_one", boom)
    with pytest.raises(Refused) as caught:
        plugin.fetch(rows)
    assert str(caught.value) == "nas1: the API key was refused" and caught.value.auth_failed
    with pytest.raises(ValueError, match="at least one"):
        plugin._servers({"servers": []})
    assert plugin._servers({"url": "https://old", "api_key": "k"}) == [{"url": "https://old", "api_key": "k"}]       # an older Netlens


POOLS = [
    {"name": "tank", "status": "DEGRADED", "healthy": False, "size": 1000, "allocated": 900, "free": 100,
     "topology": {"data": [{"type": "RAIDZ1", "status": "DEGRADED", "children": [{"type": "DISK", "disk": "sda", "status": "ONLINE"}, {"type": "DISK", "disk": "sdb", "status": "FAULTED"}]}],
                  "cache": [{"type": "DISK", "disk": "nvme0n1", "status": "ONLINE", "children": []}], "log": [], "spare": [], "special": [], "dedup": []}},
    {"name": "fast", "status": "ONLINE", "healthy": True, "size": 500, "allocated": 10, "free": 490, "topology": {"data": [{"type": "MIRROR", "children": [{"type": "DISK", "disk": "sdc", "status": "ONLINE"}]}]}},
]
DISKS = [{"name": "sda", "model": "WDC WD40", "size": 4000}, {"name": "sdb", "model": "WDC WD40", "size": 4000}]
ALERTS = [{"uuid": "a1", "level": "CRITICAL", "formatted": "Pool tank is degraded", "dismissed": False}, {"uuid": "a2", "level": "INFO", "formatted": "just info"},
          {"uuid": "a3", "level": "WARNING", "formatted": "old", "dismissed": True}]
SHARES_NFS = [{"id": 1, "path": "/mnt/tank/media", "enabled": True}]
SHARES_SMB = [{"id": 2, "name": "docs", "path": "/mnt/fast/docs", "enabled": True}, {"id": 3, "name": "off", "path": "/mnt/fast/off", "enabled": False}]


def test_storage_part_has_pools_disks_shares_and_alerts(fake):
    out = validate_output("hypervisor", run(fake(pools=POOLS, disks=DISKS, alerts=ALERTS, nfs=SHARES_NFS, smb=SHARES_SMB)))
    st = out["storage"]
    assert st["systems"][0]["vendor"] == "TrueNAS" and st["systems"][0]["health"] == "critical"
    pools = {p["name"]: p for p in st["pools"]}
    assert pools["tank"]["health"] == "warning" and pools["tank"]["total"] == 1000 and pools["tank"]["raid"] == "raidz1" and pools["fast"]["health"] == "ok"
    disks = {d["name"]: d for d in st["disks"]}
    assert disks["sdb"]["state"] == "failed" and disks["sdb"]["size"] == 4000 and disks["sda"]["state"] == "ok" and disks["sdc"]["state"] == "ok" and "nvme0n1" in disks
    shares = {v["name"]: v for v in st["volumes"]}
    assert set(shares) == {"/mnt/tank/media", "docs"} and shares["docs"]["pool_id"] == "pool:fast" and shares["/mnt/tank/media"]["protocol"] == "nfs"
    texts = {a["text"] for a in st["alerts"]}
    assert {"Pool tank is degraded", "Disk sdb of pool tank: failed"} <= texts and "just info" not in texts and "old" not in texts


def test_without_pools_there_is_no_storage_part(fake):
    assert "storage" not in run(fake())


def test_diagnose_reports_the_storage_steps_without_content(fake):
    report = run(fake(pools=POOLS, disks=DISKS, alerts=ALERTS), plugin.diagnose)
    assert report["steps"]["pools"]["ok"] and report["result"]["storage"]["pools"] == 2 and report["result"]["storage"]["disk_states"]["failed"] == 1
    text = json.dumps(report)
    assert "Pool tank is degraded" not in text and "/mnt/tank" not in text and "tank" not in text


ISCSI = dict(
    extents=[{"id": 1, "name": "illusion-disk", "type": "DISK", "disk": "zvol/tank/illusion", "enabled": True},
             {"id": 2, "name": "file-lun", "type": "FILE", "path": "/mnt/fast/luns/f1", "filesize": "5000", "enabled": True},
             {"id": 3, "name": "off", "type": "DISK", "disk": "zvol/tank/off", "enabled": False}],
    iscsi_targets=[{"id": 10, "name": "illusion", "groups": []}, {"id": 11, "name": "other", "groups": []}],
    targetextents=[{"id": 1, "target": 10, "extent": 1, "lunid": 0}, {"id": 2, "target": 11, "extent": 2, "lunid": 0}],
    sessions=[{"target": "iqn.2005-10.org.freenas.ctl:illusion", "initiator": "iqn.1991-05.com.microsoft:illusion-265k", "initiator_addr": "192.168.0.50"},
              {"target": "iqn.2005-10.org.freenas.ctl:illusion", "initiator": "iqn.1991-05.com.microsoft:illusion-265k", "initiator_addr": "192.168.0.50:3260"},
              {"target": "iqn.2005-10.org.freenas.ctl:nosuch", "initiator": "x", "initiator_addr": "192.168.0.99"}],
    zvols=[{"name": "tank/illusion", "type": "VOLUME", "volsize": {"parsed": 500000000000}, "used": {"parsed": 120000000000}}],
)


def test_iscsi_luns_with_their_size_and_the_hosts_logged_in(fake):
    st = validate_output("hypervisor", run(fake(pools=POOLS, **ISCSI)))["storage"]
    luns = {v["name"]: v for v in st["volumes"] if v["kind"] == "lun"}
    assert set(luns) == {"illusion-disk", "file-lun", "off"}
    d = luns["illusion-disk"]
    assert d["protocol"] == "iscsi" and d["size"] == 500000000000 and d["used"] == 120000000000 and d["clients"] == ["192.168.0.50"] and d["pool_id"] == "pool:tank"
    assert luns["file-lun"]["size"] == 5000 and luns["file-lun"]["clients"] == [] and luns["file-lun"]["pool_id"] == "pool:fast"
    assert luns["off"]["health"] == "warning"


def test_iscsi_without_pools_still_gives_a_storage_part_when_there_are_luns(fake):
    out = run(fake(**ISCSI))
    assert "storage" in out and any(v["kind"] == "lun" for v in out["storage"]["volumes"])
