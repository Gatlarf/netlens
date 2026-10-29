"""Built-in HTTPS: certificates made and installed safely, the key never shown, and a real HTTPS server answering with them."""

import json
import os
import socket
import ssl
import stat
import threading
import time
import urllib.request

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app import licence, secpolicy, tls
from app.config import load_settings
from app.main import create_app
from tests.fake_cyberark import Pki

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture(autouse=True)
def no_env(monkeypatch):
    monkeypatch.delenv("NETLENS_TLS_CERT", raising=False)
    monkeypatch.delenv("NETLENS_TLS_KEY", raising=False)


def test_a_self_signed_certificate_has_the_names_and_the_key_is_private(tmp_path):
    data = tls.make_self_signed(tmp_path, ["netlens.example.com", "192.168.1.10"], 30)
    assert data["configured"] and data["self_signed"] and set(data["names"]) == {"netlens.example.com", "192.168.1.10"} and 28 <= data["days_left"] <= 30
    key = tmp_path / "tls" / "server.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and b"PRIVATE KEY" in key.read_bytes()
    assert "PRIVATE" not in json.dumps(data) and key.read_text().splitlines()[1] not in json.dumps(data)
    for bad in ([], [""], ["a b"], ["x;rm"], ["ok"] * 21):
        with pytest.raises(tls.TlsError):
            tls.make_self_signed(tmp_path, bad)
    with pytest.raises(tls.TlsError):
        tls.make_self_signed(tmp_path, ["ok"], 0)


def pem_pair(days=10, names=("netlens.test",)):
    pki = Pki()
    return pki.server, __import__("tests.fake_cyberark", fromlist=["_pem_key"])._pem_key(pki.server_key), pki


def test_an_uploaded_certificate_must_match_its_key_and_the_key_must_be_unencrypted(tmp_path):
    cert, key, pki = pem_pair()
    data = tls.install(tmp_path, cert + pki.ca, key)
    assert data["valid"] and not data["self_signed"] and "Test CA" in data["issuer"]
    other_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    with pytest.raises(tls.TlsError, match="does not belong"):
        tls.install(tmp_path, cert, other_key)
    locked = ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")).decode()
    with pytest.raises(tls.TlsError, match="password"):
        tls.install(tmp_path, cert, locked)
    for bad in (("garbage", key), (cert, "garbage"), ("", ""), (cert * 1000, key)):
        with pytest.raises(tls.TlsError):
            tls.install(tmp_path, *bad)
    assert tls.info(tmp_path)["fingerprint"]                                                # a refused upload left the good one in place


def test_environment_files_win_and_a_broken_pair_falls_back_to_plain_http(tmp_path, monkeypatch):
    assert tls.paths(tmp_path) is None and tls.uvicorn_options(tmp_path) == {}
    tls.make_self_signed(tmp_path, ["a.test"])
    assert tls.paths(tmp_path)[0].name == "server.crt" and tls.source(tmp_path) == "settings"
    opts = tls.uvicorn_options(tmp_path)
    assert opts["ssl_certfile"].endswith("server.crt")
    monkeypatch.setenv("NETLENS_TLS_CERT", "/nonexistent/c.pem")
    monkeypatch.setenv("NETLENS_TLS_KEY", "/nonexistent/k.pem")
    assert tls.paths(tmp_path)[0].as_posix() == "/nonexistent/c.pem" and tls.source(tmp_path) == "environment"
    assert tls.uvicorn_options(tmp_path) == {}                                              # cannot be loaded: starts on http, logs why
    assert tls.info(tmp_path)["valid"] is False


def test_a_real_https_server_answers_with_the_made_certificate(tmp_path):
    tls.make_self_signed(tmp_path, ["localhost", "127.0.0.1"], 5)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "t.db")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", **tls.uvicorn_options(tmp_path)))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.1)
        context = ssl.create_default_context(cafile=str(tmp_path / "tls" / "server.crt"))          # the self-signed certificate is its own CA
        with urllib.request.urlopen(f"https://localhost:{port}/api/health", context=context, timeout=5) as r:
            assert r.status == 200
            assert "max-age" in (r.headers.get("Strict-Transport-Security") or "")                     # https: HSTS is sent
        with pytest.raises(Exception):
            urllib.request.urlopen(f"https://localhost:{port}/api/health", timeout=5)               # an unknown certificate is not trusted by default
        from app import healthcheck

        os.environ["NETLENS_BIND"] = f"127.0.0.1:{port}"
        assert healthcheck.main() == 0
    finally:
        os.environ.pop("NETLENS_BIND", None)
        server.should_exit = True
        thread.join(timeout=5)


def test_the_api_makes_installs_removes_and_never_returns_the_key(tmp_path, monkeypatch):
    real = licence.allows
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True if feature == "privileged" else real(conn, feature, now))
    secpolicy.forget()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path / "data")}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        assert c.get("/api/tls", headers=ADMIN).json()["configured"] is False
        r = c.post("/api/tls/self-signed", json={"names": ["netlens.test"]}, headers=ADMIN)
        assert r.status_code == 200 and r.json()["configured"] and r.json()["restart_needed"] is True and r.json()["running"] is False
        key_line = (tmp_path / "data" / "tls" / "server.key").read_text().splitlines()[1]
        assert key_line not in r.text and key_line not in c.get("/api/tls", headers=ADMIN).text
        assert c.post("/api/tls/self-signed", json={"names": ["bad name"]}, headers=ADMIN).status_code == 422
        cert, key, pki = pem_pair()
        assert c.post("/api/tls/upload", json={"certificate": cert, "key": "nope"}, headers=ADMIN).status_code == 422
        assert c.post("/api/tls/upload", json={"certificate": cert, "key": key}, headers=ADMIN).json()["issuer"].startswith("CN=Test CA")
        audit = " ".join(r["action"] for r in c.get("/api/audit", headers=ADMIN).json()["entries"])
        assert "self-signed" in audit and "never shown" in audit and key.splitlines()[1] not in audit
        assert c.delete("/api/tls", headers=ADMIN).json()["configured"] is False
        monkeypatch.setenv("NETLENS_TLS_CERT", "/x")
        assert c.post("/api/tls/self-signed", json={"names": ["a"]}, headers=ADMIN).status_code == 409
        monkeypatch.delenv("NETLENS_TLS_CERT")
        viewer = TestClient(app)
        c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=ADMIN)
        viewer.post("/api/login", json={"username": "vera", "password": "longenough1"})
        assert viewer.get("/api/tls").status_code == 403
