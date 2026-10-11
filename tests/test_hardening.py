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


def events(tmp_path, kind="login_failed"):
    from app.db import connect
    conn = connect(tmp_path / "t.db")
    try:
        return [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = ?", (kind,))]
    finally:
        conn.close()


def test_a_burst_of_wrong_logins_raises_one_alarm_per_block(tmp_path):
    with TestClient(make(tmp_path, NETLENS_TRUSTED_PROXIES=PROXY), client=(PROXY, 5000)) as c:
        def attempt(body, ip="203.0.113.9"):
            return c.post("/api/login", json=body, headers={"X-Forwarded-For": ip}).status_code

        assert [attempt({"username": "bert\x00\n", "password": "x"}) for _ in range(4)] == [401] * 4
        assert events(tmp_path) == []                                           # a few typos are no alarm
        assert attempt({"username": "bert", "password": "x"}) == 401
        [text] = events(tmp_path)
        assert "5 wrong sign-in attempts from 203.0.113.9" in text and "\x00" not in text
        assert [attempt({"token": "nope"}) for _ in range(3)] == [429] * 3        # blocked: no further alarms for the same burst
        assert len(events(tmp_path)) == 1
        assert [attempt({"token": "nope"}, ip="203.0.113.50") for _ in range(5)] == [401] * 5
        assert any("wrong access tokens from 203.0.113.50" in t for t in events(tmp_path))


def test_a_slow_attack_on_one_user_name_is_noticed_too(tmp_path):
    with TestClient(make(tmp_path, NETLENS_TRUSTED_PROXIES=PROXY), client=(PROXY, 5000)) as c:
        for i in range(20):
            c.post("/api/login", json={"username": "bert", "password": "x"}, headers={"X-Forwarded-For": f"198.51.100.{i}"})
        assert any("20 wrong passwords for the user 'bert'" in t for t in events(tmp_path))


def test_the_alarm_can_be_sent_to_a_channel():
    from app.notify import channels
    assert "login_failed" in channels.EVENT_LABELS and "login_failed" in channels.DEFAULT_EVENTS
    line = channels._line({"kind": "login_failed", "detail": "5 wrong sign-in attempts", "name": "", "ip": "", "ts": "2026-10-11T12:00:00Z"})
    assert "Login attack? 5 wrong sign-in attempts" in line
