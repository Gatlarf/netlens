"""A live ingest listener on free ports (own thread and loop) and a client that speaks to it like a collector would."""

from __future__ import annotations

import asyncio
import gzip
import http.client
import json
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.ingest import server as srv


_handed_out: set[int] = set()


def free_port() -> int:
    """A port nobody listens on, never the same one twice in a run (two calls in a row could otherwise get the same number)."""
    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in _handed_out:
            _handed_out.add(port)
            return port


class Live:
    def __init__(self, db_path: str) -> None:
        self.control = srv.Control(db_path)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def __enter__(self) -> "Live":
        self.thread.start()
        return self

    def apply(self) -> None:
        asyncio.run_coroutine_threadsafe(self.control.apply(), self.loop).result(20)

    def __exit__(self, *a) -> None:
        self.loop.call_soon_threadsafe(self.control.stop)
        time.sleep(0.05)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def new_key(kind: str = "ec"):
    return ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(65537, 3072)


def key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def csr_pem(key, cn: str = "whatever") -> str:
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def client_context(ca_pem: str, cert_pem: str | None = None, key: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False                      # tests connect to 127.0.0.1; the certificate names are checked in their own test
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca_pem)
    if cert_pem:
        d = Path(tempfile.mkdtemp())
        (d / "c.pem").write_text(cert_pem)
        (d / "k.pem").write_text(key)
        ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx


def request(port: int, ctx: ssl.SSLContext, method: str, path: str, body: bytes | str = b"", headers: dict | None = None, conn: http.client.HTTPSConnection | None = None):
    c = conn or http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
    if isinstance(body, str):
        body = body.encode()
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    if conn is None:
        c.close()
    return r.status, data, dict(r.getheaders())


def post_json(port, ctx, path, doc, gz=False, conn=None):
    raw = json.dumps(doc).encode()
    headers = {"Content-Type": "application/json"}
    if gz:
        raw = gzip.compress(raw)
        headers["Content-Encoding"] = "gzip"
    return request(port, ctx, "POST", path, raw, headers, conn)


def attr(k, v):
    return {"key": k, "value": {"stringValue": v}}


def otlp_doc(ts: float, idle: float, total: float, used: int = 600, free: int = 400, host: str = "web01", fs_used=900_000_000, fs_free=100_000_000, rx=1_000_000, tx=2_000_000) -> dict:
    """What the OpenTelemetry Collector hostmetrics receiver sends (the parts Netlens uses)."""
    ns = str(int(ts * 1e9))

    def dp(value, *attrs, integer=False):
        d = {"attributes": [attr(k, v) for k, v in attrs], "timeUnixNano": ns}
        d["asInt" if integer else "asDouble"] = str(int(value)) if integer else value
        return d

    cpu = [dp(idle, ("cpu", "cpu0"), ("state", "idle")), dp(total - idle, ("cpu", "cpu0"), ("state", "user"))]
    metrics = [
        {"name": "system.cpu.time", "sum": {"dataPoints": cpu}},
        {"name": "system.memory.usage", "sum": {"dataPoints": [dp(used, ("state", "used"), integer=True), dp(free, ("state", "free"), integer=True)]}},
        {"name": "system.filesystem.usage", "sum": {"dataPoints": [
            dp(fs_used, ("device", "/dev/sda1"), ("mountpoint", "/"), ("type", "ext4"), ("state", "used"), integer=True),
            dp(fs_free, ("device", "/dev/sda1"), ("mountpoint", "/"), ("type", "ext4"), ("state", "free"), integer=True),
            dp(5_000_000, ("device", "tmpfs"), ("mountpoint", "/run"), ("type", "tmpfs"), ("state", "used"), integer=True)]}},
        {"name": "system.network.io", "sum": {"dataPoints": [dp(rx, ("device", "eth0"), ("direction", "receive"), integer=True),
                                                             dp(tx, ("device", "eth0"), ("direction", "transmit"), integer=True)]}},
        {"name": "system.cpu.load_average.1m", "gauge": {"dataPoints": [dp(0.5)]}},
        {"name": "system.uptime", "gauge": {"dataPoints": [dp(1234)]}},
        {"name": "process.cpu.time", "sum": {"dataPoints": [dp(1.0)]}},
    ]
    return {"resourceMetrics": [{"resource": {"attributes": [attr("host.name", host)]}, "scopeMetrics": [{"metrics": metrics}]}]}
