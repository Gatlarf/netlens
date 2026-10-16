"""The Incus plugin against a simulated Incus API over real TLS with a client certificate (shapes recorded from Incus 6.0.4 on 2026-10-16).
The test makes its own throw-away certificates with the openssl program and is skipped where that is missing."""

import importlib.util
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "incus"
spec = importlib.util.spec_from_file_location("incus_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl program")


def make_cert(directory, name):
    key, crt = directory / f"{name}.key", directory / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", f"/CN={name}"], check=True, capture_output=True)
    return crt, key


def instance(name, kind="container", status="Running", nic="eth0", network="incusbr0", addr="10.114.62.82", mac="10:66:6a:bc:64:3a", cfg=None, location="none", project="default"):
    state = {"network": {"lo": {"addresses": [{"family": "inet", "address": "127.0.0.1", "scope": "local"}], "type": "loopback", "hwaddr": ""},
                         nic: {"addresses": [{"family": "inet", "address": addr, "scope": "global"}, {"family": "inet6", "address": "fe80::1", "scope": "link"}], "hwaddr": mac, "type": "broadcast"}}} if status == "Running" else None
    return {"name": name, "type": kind, "status": status, "project": project, "location": location, "state": state,
            "config": {"image.description": "Alpine 3.21 amd64", "image.os": "Alpine", "image.release": "3.21", "volatile.eth0.hwaddr": mac, **(cfg or {})},
            "expanded_devices": {nic: {"type": "nic", "network": network, "name": nic}}}


@pytest.fixture
def incus(tmp_path):
    server_crt, server_key = make_cert(tmp_path, "server")
    client_crt, client_key = make_cert(tmp_path, "client")
    other_crt, other_key = make_cert(tmp_path, "other")
    trusted_der = ssl.PEM_cert_to_DER_cert(client_crt.read_text())
    instances = [instance("web1"), instance("db1", status="Stopped", cfg={"limits.cpu": "2", "limits.memory": "256MiB", "boot.autostart": "true"}, mac="10:66:6a:07:56:54"),
                 instance("lan1", addr="192.168.0.77", network="macvlan-lan", mac="10:66:6a:00:00:01"), instance("vm1", kind="virtual-machine", cfg={"limits.memory": "2GiB"}, mac="10:66:6a:00:00:02", addr="10.114.62.90")]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            trusted = self.connection.getpeercert(binary_form=True) == trusted_der            # like Incus: any certificate may connect, only the trusted one is "trusted"
            path = self.path.split("?")[0]
            if path == "/1.0":
                body = {"auth": "trusted" if trusted else "untrusted", "environment": {"server_version": "6.0.4", "server_name": "inc1", "server_clustered": False, "addresses": ["192.168.0.20:8443", "10.114.62.1:8443"], "driver": "lxc | qemu"}}
            elif not trusted:
                return self.send(403, {"type": "error", "error": "not authorized"})
            elif path == "/1.0/instances":
                body = instances
            elif path == "/1.0/networks":
                body = [{"name": "incusbr0", "managed": True, "config": {"ipv4.nat": "true"}}, {"name": "eth0", "managed": False, "config": {}}]
            else:
                return self.send(404, {"type": "error", "error": "not found"})
            self.send(200, {"type": "sync", "metadata": body})

        def send(self, code, payload):
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(server_crt, server_key)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(client_crt)
    context.load_verify_locations(other_crt)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{httpd.server_address[1]}", client_crt, client_key, tmp_path
    httpd.shutdown()
    httpd.server_close()


def config(incus, flat=False, cert=None):
    url, crt, key, _ = incus
    crt_text, key_text = (cert or crt).read_text(), key.read_text()
    if flat:                                            # a settings field may turn the line breaks into spaces
        crt_text, key_text = " ".join(crt_text.split()), " ".join(key_text.split())
    return {"servers": [{"host": url, "cert": crt_text, "key": key_text}], "timeout": 5}


def test_manifest_and_output_follow_the_contract(incus):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    out = validate_output("hypervisor", plugin.fetch(config(incus, flat=True)))
    assert [(h["name"], h["ip"], h["online"]) for h in out["hosts"]] == [("inc1", "192.168.0.20", True)]            # connected as 127.0.0.1: the server's own LAN address is taken from its list
    guests = {g["name"]: g for g in out["guests"]}
    web = guests["web1"]
    assert web["kind"] == "container" and web["status"] == "running" and web["ips"] == [] and web["macs"] == ["10:66:6a:bc:64:3a"]       # behind NAT: no internal address
    assert guests["lan1"]["ips"] == ["192.168.0.77"]                                                                                        # on the LAN: reported
    db = guests["db1"]
    assert db["status"] == "stopped" and db["macs"] == ["10:66:6a:07:56:54"] and db["details"]["cpus"] == 2 and db["details"]["memory_mb"] == 256 and db["details"]["autostart"] is True
    assert guests["vm1"]["kind"] == "vm" and guests["vm1"]["details"]["memory_mb"] == 2048 and web["details"]["os"] == "Alpine 3.21"


def test_untrusted_certificate_message_and_diagnose(incus):
    other, other_key = incus[3] / "other.crt", incus[3] / "other.key"
    cfg = config(incus)
    assert "4 instance(s) (1 virtual machine(s)), 3 running, 1 with a LAN address" in plugin.test(cfg)["message"]
    bad = {"servers": [{**cfg["servers"][0], "cert": other.read_text(), "key": other_key.read_text()}], "timeout": 5}
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(bad)
    assert caught.value.auth_failed is True and "trust" in str(caught.value)
    text = json.dumps(plugin.diagnose(cfg))
    assert "192.168" not in text and "web1" not in text and '"auth": "trusted"' in text and '"virtual-machine": 1' in text


def test_pem_handling():
    assert plugin.normalize_pem("-----BEGIN CERTIFICATE----- QUJD REVG -----END CERTIFICATE-----", "x") == "-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----\n"
    with pytest.raises(plugin.IncusError):
        plugin.normalize_pem("just text", "client key")
    with pytest.raises(plugin.IncusError):
        plugin.make_context("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n", False)
