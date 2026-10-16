"""The HAProxy plugin against canned statistics (CSV recorded from HAProxy 3.4.7 with `stats show-legends` on 2026-10-16)."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "haproxy"
spec = importlib.util.spec_from_file_location("haproxy_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

HEAD = "# pxname,svname,status,addr,mode,"
CSV = "\n".join([HEAD, "fe_web,FRONTEND,OPEN,,http,", "be_who,who1,UP,172.18.0.7:80,http,", "be_who,BACKEND,UP,,http,",
                 "be_files,files1,DOWN,192.168.0.20:8081,http,", "be_files,files2,UP,192.168.0.21:8081,http,", "be_files,BACKEND,UP,,http,",
                 "be_off,off1,MAINT,192.168.0.22:80,http,", "be_off,BACKEND,MAINT,,http,", "be_empty,BACKEND,DOWN,,http,", "be_noaddr,n1,UP,,http,", "be_noaddr,BACKEND,UP,,http,", "stats,FRONTEND,OPEN,,http,", "stats,BACKEND,UP,,http,", ""])
AUTH = "Basic " + base64.b64encode(b"u:p").decode()


@pytest.fixture
def stats():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path != "/stats;csv":
                code, body = 404, b"no"
            elif self.headers.get("Authorization") != AUTH:
                code, body = 401, b"unauthorized"
            else:
                code, body = 200, CSV.encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/stats"
    httpd.shutdown()
    httpd.server_close()


def config(url, password="p", **extra):
    return {"servers": [{"host": url, "username": "u", "password": password, "lan": "192.168.0.4"}], "timeout": 5, **extra}


def test_manifest_and_sites_follow_the_contract(stats):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "proxy"
    out = validate_output("proxy", plugin.fetch(config(stats, domains="be_files=Files.example.com, be_files=files2.example.com; be_who=who.example.com")))
    assert out["proxies"][0]["ip"] == "192.168.0.4"
    sites = {s["name"]: s for s in out["sites"]}
    assert sorted(sites) == ["be_files", "be_noaddr", "be_off", "be_who"]                     # frontends, the statistics listener and empty backends are not sites
    assert (sites["be_files"]["forward_host"], sites["be_files"]["forward_port"]) == ("192.168.0.21", 8081)      # the first server that is UP
    assert sites["be_files"]["domains"] == ["files.example.com", "files2.example.com"] and sites["be_who"]["domains"] == ["who.example.com"]
    assert sites["be_off"]["enabled"] is False and sites["be_noaddr"]["type"] == "dead" and sites["be_who"]["enabled"] is True


def test_message_login_and_diagnose(stats):
    assert "Connected to 1 HAProxy: 4 backend(s), none with a host name" in plugin.test(config(stats))["message"]
    assert "1 backend(s) show no server address" in plugin.test(config(stats))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(stats, password="wrong"))
    assert caught.value.auth_failed is True
    text = json.dumps(plugin.diagnose(config(stats)))
    assert "192.168" not in text and "be_files" not in text and '"backends": 6' in text and '"has_addr_column": true' in text
    with pytest.raises(plugin.HaproxyError):
        plugin.test(config(stats.replace("/stats", "/other")))
