"""What a stranger on the internet can and cannot do: the API map, the version, HSTS, and the login throttle behind a reverse proxy."""

import pytest
from fastapi.testclient import TestClient

from app.auth import client_ip
from app.config import ConfigError, load_settings
from app.main import create_app

PROXY = "10.1.1.1"


def make(tmp_path, **env):
    settings = load_settings({"NETLENS_TOKEN": "t" * 64, **env})
    return create_app(settings, db_path=tmp_path / "t.db")


def test_the_api_map_is_off_unless_asked_for(tmp_path):
    with TestClient(make(tmp_path)) as c:
        assert [c.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")] == [404, 404, 404]
    with TestClient(make(tmp_path, NETLENS_API_DOCS="on")) as c:
        assert [c.get(p).status_code for p in ("/docs", "/redoc", "/openapi.json")] == [200, 200, 200]
    with pytest.raises(ConfigError):
        load_settings({"NETLENS_TOKEN": "x", "NETLENS_API_DOCS": "maybe"})


def test_only_a_logged_in_visitor_learns_the_version(tmp_path):
    with TestClient(make(tmp_path)) as c:
        assert c.get("/api/health").json() == {"status": "ok"}
        assert "version" in c.get("/api/health", headers={"Authorization": "Bearer " + "t" * 64}).json()


def test_hsts_is_sent_over_https_only(tmp_path):
    with TestClient(make(tmp_path)) as c:
        assert "strict-transport-security" not in c.get("/api/health").headers
        assert c.get("/api/health", headers={"X-Forwarded-Proto": "https"}).headers["strict-transport-security"].startswith("max-age=")


class Conn:
    def __init__(self, peer, xff=None, trusted=(PROXY,)):
        from types import SimpleNamespace
        self.client = SimpleNamespace(host=peer)
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.app = SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(trusted_proxies=trusted)))


def test_the_real_client_is_only_believed_behind_a_trusted_proxy():
    assert client_ip(Conn(PROXY, "203.0.113.9")) == "203.0.113.9"
    assert client_ip(Conn(PROXY, "6.6.6.6, 203.0.113.9")) == "203.0.113.9"                  # earlier entries are the client's own claim
    assert client_ip(Conn(PROXY, "203.0.113.9, 10.1.1.1")) == "203.0.113.9"                 # a second trusted hop is skipped
    assert client_ip(Conn("198.51.100.7", "203.0.113.9")) == "198.51.100.7"                 # not from the proxy: the header is ignored
    assert client_ip(Conn(PROXY, "203.0.113.9", trusted=())) == PROXY                       # nothing configured: unchanged behaviour
    assert client_ip(Conn(PROXY, "not-an-address")) == PROXY and client_ip(Conn(PROXY)) == PROXY
    assert client_ip(Conn("::ffff:10.1.1.1", "203.0.113.9", trusted=("10.0.0.0/8",))) == "203.0.113.9"


def test_one_attacker_behind_the_proxy_does_not_lock_everybody_out(tmp_path):
    with TestClient(make(tmp_path, NETLENS_TRUSTED_PROXIES=PROXY), client=(PROXY, 5000)) as c:
        def attempt(ip, token="wrong"):
            return c.post("/api/login", json={"token": token}, headers={"X-Forwarded-For": ip}).status_code

        assert [attempt("203.0.113.9") for _ in range(6)] == [401] * 5 + [429]
        assert attempt("203.0.113.10", "t" * 64) == 200                      # somebody else, same proxy: fine


def test_without_the_setting_everybody_shares_the_proxys_address(tmp_path):
    with TestClient(make(tmp_path)) as c:
        for _ in range(5):
            c.post("/api/login", json={"token": "wrong"}, headers={"X-Forwarded-For": "203.0.113.9"})
        assert c.post("/api/login", json={"token": "t" * 64}, headers={"X-Forwarded-For": "203.0.113.10"}).status_code == 429       # the known weakness the setting fixes


def test_a_wrong_password_for_the_owner_is_not_an_easy_lockout(tmp_path):
    with TestClient(make(tmp_path, NETLENS_TRUSTED_PROXIES=PROXY), client=(PROXY, 5000)) as c:
        codes = [c.post("/api/login", json={"username": "bert", "password": "x"}, headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code for i in range(1, 22)]
        assert codes[:20] == [401] * 20 and codes[20] == 429                  # many addresses: the per-name budget is 20, not 5


def test_trusted_proxy_setting_is_checked():
    assert load_settings({"NETLENS_TOKEN": "x", "NETLENS_TRUSTED_PROXIES": "10.0.0.1, 192.168.0.0/24"}).trusted_proxies == ("10.0.0.1/32", "192.168.0.0/24")
    with pytest.raises(ConfigError):
        load_settings({"NETLENS_TOKEN": "x", "NETLENS_TRUSTED_PROXIES": "banana"})
