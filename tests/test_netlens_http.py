"""netlens_http: the one HTTP client every plugin uses (timeouts, size limit, TLS rule, redirects, error kinds)."""
import shutil
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import netlens_http as nh


class _Server:
    def __init__(self, handler, tls=None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if tls else "http"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"{self.scheme}://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _answer(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen["body"] = self.rfile.read(n)
            seen["headers"] = dict(self.headers)
            seen["path"] = self.path
            seen.setdefault("calls", []).append(self.path)
            if self.path == "/json":
                body, code = b'{"a": 1}', 200
            elif self.path == "/big":
                body, code = b"x" * 300_000, 200
            elif self.path == "/bigerror":
                body, code = b"e" * 2_000_000, 500
            elif self.path == "/slow":
                time.sleep(1.5)
                body, code = b"late", 200
            elif self.path == "/login":
                self.send_response(200)
                self.send_header("Set-Cookie", "sid=abc; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif self.path == "/loop":
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.end_headers()
                return
            elif self.path == "/meta":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/")
                self.end_headers()
                return
            elif self.path == "/other":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/json")
                self.end_headers()
                return
            else:
                body, code = b"nope", 404
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = _answer

    s = _Server(H)
    s.seen = seen
    yield s
    s.close()


def test_a_normal_answer_and_the_status_of_an_error_answer(server):
    r = nh.request("GET", server.url + "/json")
    assert (r.status, r.ok, r.json()) == (200, True, {"a": 1})
    r = nh.request("GET", server.url + "/missing")
    assert (r.status, r.ok, r.text()) == (404, False, "nope")        # an HTTP error is an answer, not an exception


def test_json_form_and_basic_auth_are_encoded_the_same_way_everywhere(server):
    nh.request("POST", server.url + "/json", json={"x": 1}, headers={"Authorization": nh.basic_auth("u", "p")})
    assert server.seen["body"] == b'{"x": 1}'
    assert server.seen["headers"]["Content-Type"] == "application/json"
    assert server.seen["headers"]["Authorization"] == "Basic dTpw"
    nh.request("POST", server.url + "/json", form={"a": "b c"})
    assert server.seen["body"] == b"a=b+c"
    assert server.seen["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_an_answer_over_the_limit_is_refused_and_an_error_page_is_cut_off(server):
    with pytest.raises(nh.TooLarge):
        nh.request("GET", server.url + "/big", max_bytes=100_000)
    assert len(nh.request("GET", server.url + "/big", max_bytes=400_000).body) == 300_000
    r = nh.request("GET", server.url + "/bigerror")
    assert r.status == 500 and len(r.body) == nh.MAX_ERROR_BODY


def test_timeout_unreachable_and_bad_address_are_different_errors(server):
    with pytest.raises(nh.NetTimeout):
        nh.request("GET", server.url + "/slow", timeout=0.3)
    free = _Server(BaseHTTPRequestHandler)
    port = free.port
    free.close()
    with pytest.raises(nh.Unreachable) as err:
        nh.request("GET", f"http://127.0.0.1:{port}/", timeout=2)
    assert "127.0.0.1" not in str(err.value).split("(")[0] and err.value.host == "127.0.0.1"
    for bad in ("file:///etc/passwd", "ftp://x/", "not a url", "http://"):
        with pytest.raises(nh.BadUrl):
            nh.request("GET", bad)


def test_cookies_are_kept_only_when_asked_for(server):
    s = nh.Session(cookies=True)
    s.request("GET", server.url + "/login")
    assert s.cookie("sid") == "abc"
    s.request("GET", server.url + "/json")
    assert "sid=abc" in server.seen["headers"]["Cookie"]
    nh.request("GET", server.url + "/login")
    nh.request("GET", server.url + "/json")
    assert "Cookie" not in server.seen["headers"]


def test_redirects_are_limited_and_dangerous_ones_come_back_as_the_3xx_answer(server):
    assert nh.request("GET", server.url + "/loop").status == 302            # more than 3 hops: the redirect answer itself
    assert nh.request("GET", server.url + "/meta").status == 302            # the cloud metadata service is never contacted
    nh.request("GET", server.url + "/other", headers={"Authorization": "Bearer s3cret", "X-Api-Key": "k"})
    assert "Authorization" not in server.seen["headers"] and "X-Api-Key" not in server.seen["headers"]      # another host name: no login details


def test_the_environment_proxy_is_ignored(server, monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    assert nh.request("GET", server.url + "/json").status == 200


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl program")
def test_tls_is_checked_unless_the_admin_turned_it_off(tmp_path, server):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    tls = _Server(type("H", (server.httpd.RequestHandlerClass,), {}), tls=(str(cert), str(key)))
    try:
        with pytest.raises(nh.CertificateError):
            nh.request("GET", tls.url + "/json", timeout=5)
        assert nh.request("GET", tls.url + "/json", timeout=5, verify_tls=False).json() == {"a": 1}
        with pytest.raises(nh.CertificateError):                                # a plain-text device is not the same as a bad certificate
            nh.connect("127.0.0.1", tls.port, tls=True, timeout=5)
        nh.connect("127.0.0.1", tls.port, tls=True, verify_tls=False, timeout=5).close()
    finally:
        tls.close()


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl program")
def test_a_pinned_certificate_is_checked_before_anything_is_sent(tmp_path, server):
    import hashlib

    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    good = hashlib.sha256(der).hexdigest()
    seen = []
    handler = type("H", (server.httpd.RequestHandlerClass,), {"log_message": lambda *a: None})
    orig = handler._answer
    handler._answer = lambda self: (seen.append(self.path), orig(self))
    handler.do_GET = handler.do_POST = handler._answer
    tls = _Server(handler, tls=(str(cert), str(key)))
    try:
        pretty = ":".join(good[i:i + 2] for i in range(0, 64, 2)).upper()
        assert nh.request("GET", tls.url + "/json", fingerprint=pretty, timeout=5).json() == {"a": 1}      # a self-signed certificate is fine when pinned
        before = len(seen)
        with pytest.raises(nh.CertificateError):
            nh.request("GET", tls.url + "/json", fingerprint="00" * 32, timeout=5, headers={"Authorization": "Bearer s3cret"})
        assert len(seen) == before                                                                        # the request never reached the server
        with pytest.raises(nh.CertificateError):
            nh.connect("127.0.0.1", tls.port, tls=True, fingerprint="00" * 32, timeout=5)
        nh.connect("127.0.0.1", tls.port, tls=True, fingerprint=good, timeout=5).close()
    finally:
        tls.close()
    with pytest.raises(ValueError):
        nh.normalize_fingerprint("12:34")


def test_the_context_checks_the_hostname_with_the_chain():
    ctx = nh.ssl_context(True)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    off = nh.ssl_context(False)
    assert off.verify_mode == ssl.CERT_NONE and not off.check_hostname


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl program")
def test_a_certificate_authority_added_by_the_administrator_is_trusted_with_the_host_name_still_checked(tmp_path, server):
    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=tmp_path)

    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Test CA")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=device")
    (tmp_path / "ext.cnf").write_text("subjectAltName=IP:127.0.0.1\n")
    run("x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem", "-days", "2", "-extfile", "ext.cnf")
    tls = _Server(type("H", (server.httpd.RequestHandlerClass,), {}), tls=(str(tmp_path / "srv.pem"), str(tmp_path / "srv.key")))
    try:
        with pytest.raises(nh.CertificateError):
            nh.request("GET", tls.url + "/json", timeout=5)                         # not trusted yet
        nh.trust((tmp_path / "ca.pem").read_text())
        assert nh.request("GET", tls.url + "/json", timeout=5).json() == {"a": 1}  # trusted now, no switch turned off
        with pytest.raises(nh.CertificateError):
            nh.request("GET", tls.url.replace("127.0.0.1", "localhost") + "/json", timeout=5)      # the name is not in the certificate: still refused
    finally:
        nh.trust("")
        tls.close()
