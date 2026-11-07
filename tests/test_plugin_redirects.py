"""What a plugin's HTTP request may follow: the worker refuses a redirect to the metadata service or back to http and keeps login details on the same host."""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

WORKER = Path(__file__).resolve().parents[1] / "app" / "plugins" / "worker.py"

SCRIPT = textwrap.dedent('''
    import http.server, importlib.util, json, sys, threading, urllib.request, urllib.error
    spec = importlib.util.spec_from_file_location("w", sys.argv[1]); w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
    w._guard_redirects()
    seen = {}
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path == "/echo":
                seen["auth"] = self.headers.get("Authorization"); self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
            location = {"/same": "/echo", "/other": f"http://localhost:{self.server.server_port}/echo",
                        "/meta": "http://169.254.169.254/latest/", "/file": "file:///etc/passwd"}[self.path]
            self.send_response(302); self.send_header("Location", location); self.end_headers()
    srv = http.server.HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    out = {}
    for name in ("same", "other", "meta", "file"):
        seen.clear()
        req = urllib.request.Request(base + "/" + name, headers={"Authorization": "Bearer s3cret"})
        try:
            urllib.request.urlopen(req, timeout=5).read(); out[name] = ["followed", seen.get("auth")]
        except urllib.error.HTTPError as exc:
            out[name] = ["refused", str(exc.reason)]
    print(json.dumps(out))
''')


def test_the_worker_keeps_the_login_on_the_same_host_and_refuses_dangerous_redirects():
    run = subprocess.run([sys.executable, "-I", "-c", SCRIPT, str(WORKER)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout.strip().splitlines()[-1])
    assert out["same"] == ["followed", "Bearer s3cret"]          # same host: the request continues as it was
    assert out["other"] == ["followed", None]                    # another host name: followed, but without the login
    assert out["meta"][0] == "refused"                           # the cloud metadata address
    assert out["file"][0] == "refused"


def test_plugins_that_read_xml_from_a_device_refuse_a_document_with_entities():
    import importlib.util
    import xml.etree.ElementTree as ET

    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><x>&b;</x>'
    for name in ("hyperv", "paloalto", "qnap", "vsphere"):
        path = Path(__file__).resolve().parents[1] / "plugins" / name / "plugin.py"
        spec = importlib.util.spec_from_file_location(f"xml_{name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            module._parse_xml(bomb)
            raise AssertionError(f"{name} parsed a document with entities")
        except ET.ParseError:
            pass
        assert module._parse_xml(b"<a><b>1</b></a>").tag == "a"
