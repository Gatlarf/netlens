"""The Prometheus plugin (kind "metrics") against a simulated store that replays answers recorded from a real Prometheus 3.15.1 + node_exporter
(tests/fake_prometheus.py). The Windows host is synthetic: no Windows host was available."""

import http.server
import importlib.util
import json
import ssl
import threading
from pathlib import Path

import pytest

from app.ingest import pki
from app.plugins.contract import validate_manifest, validate_output
from tests.fake_prometheus import FakeProm

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "prometheus"
spec = importlib.util.spec_from_file_location("prometheus_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


@pytest.fixture
def fake(monkeypatch):
    def make(**kw):
        f = FakeProm(**kw)
        monkeypatch.setattr(plugin, "TRANSPORT_FACTORY", f.factory)
        return f
    return make


def cfg(**extra):
    return {"servers": [{"id": "s1", "host": "https://prom.example.com:9090"}], **extra}


def by_metric(host):
    out = {}
    for r in host["readings"]:
        out.setdefault(r["metric"], {})[r["label"]] = r
    return out


def test_manifest_is_valid():
    manifest = json.loads((ROOT / "plugin.json").read_text())
    assert validate_manifest(manifest)["kind"] == "metrics"


def test_a_linux_host_from_a_real_prometheus(fake):
    fake()
    out = plugin.fetch(cfg())
    assert validate_output("metrics", out)                                   # the Netlens contract accepts it
    assert len(out["hosts"]) == 1
    h = out["hosts"][0]
    assert h["name"] == "web01" and h["ip"] == "10.0.0.5" and h["id"] == "10.0.0.5:9100"
    m = by_metric(h)
    assert set(m) == {"cpu_pct", "load1", "mem_pct", "swap_pct", "disk_pct", "disk_free_b", "net_rx_bps", "net_tx_bps", "uptime_s"}
    assert "/" in m["disk_pct"] and all(0 <= r["value"] <= 100 for k in ("cpu_pct", "mem_pct", "swap_pct", "disk_pct") for r in m[k].values())
    assert m["uptime_s"][""]["value"] > 3600 and m["net_rx_bps"]                    # a real machine that has been up for a while
    first = m["cpu_pct"][""]
    assert len(first["samples"]) >= 2 and first["value"] == first["samples"][-1][1]


def test_the_queries_are_fixed_and_only_get_requests_to_the_api_are_made(fake):
    f = fake()
    plugin.fetch(cfg())
    plugin.test(cfg())
    allowed = {plugin.build_query(t, "") for _m, _l, t in plugin.QUERIES} | {plugin.build_query(t, "") for _n, t in plugin.NAME_QUERIES} | {
        "vector(1)", "count(node_uname_info{})", "count(windows_cs_hostname{})"}
    assert f.requests and all(method == "GET" and path.startswith("/api/v1/") for method, path, _q in f.requests)
    assert {q for _m, _p, q in f.requests if q} <= allowed


def test_a_job_filter_is_checked_and_applied(fake):
    f = fake()
    plugin.fetch(cfg(job="node, my.job-1"))
    assert any('job=~"node|my[.]job-1"' in q for _m, _p, q in f.requests)
    for bad in ('a"} or vector(1) {x="', "a b;c", "x" * 65, "a\\b", "a}"):
        with pytest.raises(ValueError):
            plugin.fetch(cfg(job=bad))
    sent_before = len(f.requests)
    with pytest.raises(ValueError):
        plugin.test(cfg(job='x"y'))
    assert len(f.requests) == sent_before                                        # refused before anything was sent


def test_a_windows_host_next_to_the_linux_one(fake):
    fake(windows=True)
    out = plugin.fetch(cfg())
    assert validate_output("metrics", out)
    hosts = {h["name"]: h for h in out["hosts"]}
    assert set(hosts) == {"web01", "WIN-APP01"}
    w = by_metric(hosts["WIN-APP01"])
    assert hosts["WIN-APP01"]["ip"] == "10.0.0.20" and set(w["disk_pct"]) == {"C:", "D:"} and w["uptime_s"][""]["value"] == 86460


def test_without_history_only_the_newest_value_is_asked(fake):
    f = fake()
    out = plugin.fetch(cfg(history_minutes=0))
    assert validate_output("metrics", out)
    assert all(path == "/api/v1/query" for _m, path, q in f.requests) and all("samples" not in r or not r["samples"] for r in out["hosts"][0]["readings"])


def test_nonsense_numbers_are_dropped(fake):
    fake(nan=True)
    assert plugin.fetch(cfg())["hosts"] == []


def test_the_login_is_sent_as_a_bearer_token_or_basic_and_a_refusal_stops_the_plugin(fake):
    f = fake(token="t0k3n-value-1")
    assert plugin.fetch({"servers": [{"id": "s1", "host": "https://p", "token": "t0k3n-value-1"}]})["hosts"]
    assert f.headers_seen[0]["Authorization"] == "Bearer t0k3n-value-1"
    with pytest.raises(plugin.PromAuthError) as exc:
        plugin.fetch({"servers": [{"id": "s1", "host": "https://p", "token": "wrong"}]})
    assert exc.value.auth_failed is True and "wrong" not in str(exc.value) and "t0k3n-value-1" not in str(exc.value)
    g = fake(basic="reader:s3cret")
    assert plugin.fetch({"servers": [{"id": "s1", "host": "https://p", "username": "reader", "password": "s3cret"}]})["hosts"]
    assert g.headers_seen[0]["Authorization"].startswith("Basic ")


def test_plain_http_is_refused_unless_allowed():
    for host in ("http://prom:9090", "prom:9090/x?query=1"):
        with pytest.raises(ValueError):
            plugin.normalize_base(host)
    assert plugin.normalize_base("prom.example.com:9090") == "https://prom.example.com:9090"
    assert plugin.normalize_base("https://example.com/prometheus/") == "https://example.com/prometheus"
    assert plugin.normalize_base("http://localhost:9090", allow_http=True) == "http://localhost:9090"
    with pytest.raises(ValueError):
        plugin.fetch(cfg() | {"servers": [{"id": "s1", "host": "http://prom:9090"}]})


def test_what_is_not_a_prometheus_and_what_a_prometheus_refuses_are_explained(fake):
    fake(html=True)
    with pytest.raises(plugin.PromError, match="without JSON"):
        plugin.test(cfg())
    fake(status=422, error="parse error: unexpected end of input")
    with pytest.raises(plugin.PromError, match="HTTP 422: parse error"):
        plugin.fetch(cfg())


def test_the_test_message_counts_the_hosts(fake):
    fake()
    assert plugin.test(cfg())["message"] == "Connected to Prometheus 3.15.1: 1 Linux host(s)"


def test_two_servers_do_not_clash_and_the_host_limit_holds(fake):
    fake(windows=True)
    two = {"servers": [{"id": "a", "host": "https://p1"}, {"id": "b", "host": "https://p2"}]}
    out = plugin.fetch(two)
    assert len(out["hosts"]) == 4 and {h["id"].split("/")[0] for h in out["hosts"]} == {"a", "b"}
    assert validate_output("metrics", out)
    assert len(plugin.fetch(cfg(max_hosts=1))["hosts"]) == 1


def test_the_diagnostic_report_holds_no_names_addresses_or_secrets(fake):
    fake(token="tok", windows=True)
    report = plugin.diagnose({"servers": [{"id": "s1", "host": "https://prom.example.com:9090", "token": "tok"}]})
    text = json.dumps(report)
    for leak in ("web01", "WIN-APP01", "10.0.0.5", "10.0.0.20", "prom.example.com", "tok\"", "Bearer"):
        assert leak not in text, leak
    assert report["result"]["hosts"] == 2 and all(s["ok"] for s in report["steps"].values())
    fake(html=True)
    assert "error" in plugin.diagnose(cfg()) or any(not s["ok"] for s in plugin.diagnose(cfg())["steps"].values())


# ------------------------------------------------------------------ the real TLS transport, with a local HTTPS server
@pytest.fixture
def https_server(tmp_path):
    ca, ca_key = pki.create_ca()
    cert, key = pki.issue_server(ca, ca_key, ["127.0.0.1"])
    (tmp_path / "c.pem").write_text(cert)
    (tmp_path / "k.pem").write_text(key)

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"success","data":{"version":"9.9"}}')

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], pki.fingerprint(pki.cert_der(cert))
    srv.shutdown()


def test_certificate_pinning_trusts_exactly_one_certificate(https_server):
    port, fp = https_server
    url = f"https://127.0.0.1:{port}/api/v1/status/buildinfo"
    ok = plugin.make_transport(True, 5, "x", fingerprint=fp)("GET", url, {}, None)
    assert ok[0] == 200
    with pytest.raises(plugin.PromError, match="does not match the fingerprint"):
        plugin.make_transport(True, 5, "x", fingerprint="00" * 32)("GET", url, {}, None)
    with pytest.raises(plugin.PromError, match="could not be verified"):
        plugin.make_transport(True, 5, "x")("GET", url, {}, None)                  # self-signed and not pinned
    assert plugin.make_transport(False, 5, "x")("GET", url, {}, None)[0] == 200    # verification switched off on purpose
    with pytest.raises(ValueError, match="64 hexadecimal"):
        plugin.make_transport(True, 5, "x", fingerprint="abc")
