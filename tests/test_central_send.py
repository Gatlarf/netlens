"""The probe's report to a central Netlens: answers, errors, the pinned certificate, one whole push, and the commands that come back."""
import asyncio
import http.server
import json
import ssl
import subprocess
import threading
import time

import pytest

from app import central
from app.db import connect, get_setting, init_db, set_setting


def serve(handler_class, tls=None):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def replier(code, body=b"{}"):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(code); self.end_headers(); self.wfile.write(body)
    return H


def test_send_answers_and_errors():
    cases = [(200, b'{"events": 3}', None), (401, b"{}", "refused the token"), (429, b"{}", "too many attempts"), (500, b"{}", "error \\(500\\)"), (200, b"not json", "cannot reach")]
    for code, body, error in cases:
        srv = serve(replier(code, body))
        try:
            url = f"http://127.0.0.1:{srv.server_port}"
            if error is None:
                assert central.send(url, "t", {"a": 1}, timeout=5) == {"events": 3}
            else:
                with pytest.raises(central.LinkError, match=error):
                    central.send(url, "t", {"a": 1}, timeout=5)
        finally:
            srv.shutdown()


def test_send_unreachable_and_too_large(monkeypatch):
    with pytest.raises(central.LinkError, match="cannot reach"):
        central.send("http://127.0.0.1:1", "t", {}, timeout=2)
    monkeypatch.setattr(central, "MAX_BODY", 10)
    with pytest.raises(central.LinkError, match="too large"):
        central.send("http://127.0.0.1:1", "t", {"x": "y" * 500})


@pytest.fixture
def tls_pair(tmp_path):
    crt, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return str(crt), str(key)


def test_pinned_certificate(tls_pair):
    srv = serve(replier(200, b'{"ok": true}'), tls=tls_pair)
    try:
        url = f"https://127.0.0.1:{srv.server_port}"
        pin = central.fetch_fingerprint(url, timeout=5)
        assert len(pin.split(":")) == 32
        assert central.send(url, "t", {}, timeout=5, pin=pin) == {"ok": True}                      # exactly the trusted certificate works
        with pytest.raises(central.LinkError, match="not the one you trusted"):
            central.send(url, "t", {}, timeout=5, pin="AA:" * 31 + "AA")                         # any other one does not
        with pytest.raises(central.LinkError, match="not trusted"):
            central.send(url, "t", {}, timeout=5)                                               # without a pin the normal check refuses a self-signed one
    finally:
        srv.shutdown()


def test_fetch_fingerprint_of_nothing():
    with pytest.raises(central.LinkError, match="cannot read the certificate"):
        central.fetch_fingerprint("https://127.0.0.1:1", timeout=2)


def test_skew():
    assert central._skew(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 90))) in range(88, 93)
    assert central._skew("yesterday") is None and central._skew(None) is None


@pytest.fixture
def linked(tmp_path):
    path = str(tmp_path / "p.db")
    conn = connect(path)
    init_db(conn)
    central.set_link(conn, {"url": "http://192.168.0.5:8080", "token": "nlp_x", "enabled": True, "accept_config": True})
    return path, conn


def test_push_once_stores_the_status_and_keeps_only_known_commands(linked, monkeypatch):
    path, conn = linked
    monkeypatch.setattr(central, "send", lambda *a, **k: {"events": 2, "time": "2026-01-01T00:00:00Z", "commands": ["scan", "format_disk", "scan_deep"]})
    status = central.push_once(path)
    assert status["ok"] is True and status["commands"] == ["scan", "scan_deep"] and status["central_events"] == 2
    assert json.loads(get_setting(conn, central.STATUS_KEY))["ok"] is True
    assert get_setting(conn, central.MARK_KEY)


def test_push_once_failure_keeps_the_mark_and_reports_the_reason(linked, monkeypatch):
    path, conn = linked
    def boom(*a, **k): raise central.LinkError("cannot reach the central Netlens: down")
    monkeypatch.setattr(central, "send", boom)
    status = central.push_once(path)
    assert status["ok"] is False and "down" in status["error"] and status["samples"] == 0
    assert get_setting(conn, central.MARK_KEY) is None            # the next report sends the same samples again


def test_push_once_does_nothing_when_it_is_off(linked):
    path, conn = linked
    set_setting(conn, central.LINK_KEY, json.dumps({**json.loads(get_setting(conn, central.LINK_KEY)), "enabled": False}))
    assert central.push_once(path) == {}


def test_commands_start_scans_and_a_busy_scanner_is_not_an_error():
    from app.scanner.orchestrator import ScanBusy

    calls = []

    class Manager:
        async def start(self, kind):
            calls.append(kind)
            if len(calls) == 2: raise ScanBusy("busy")
            if len(calls) == 3: raise RuntimeError("boom")

    started = asyncio.run(central.run_commands({"commands": ["scan", "scan", "scan_deep"]}, Manager()))
    assert calls == ["quick", "quick", "deep"] and started == ["scan"]
