import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.config import ConfigError, load_settings
from app.main import create_app
from app.terminal.access import classify, parse_mode

AUTH = {"Authorization": "Bearer t"}


def req(headers=None, client=("192.168.0.20", 5000)):
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()], "client": client}
    return Request(scope)


def test_direct_local_connections_are_allowed():
    assert classify(req(), "off")[0] is True
    assert classify(req(client=("127.0.0.1", 1)), "off")[0] is True
    assert classify(req(client=("100.64.1.2", 1)), "off")[0] is True        # Tailscale / CGNAT
    assert classify(req(client=None), "off")[0] is True                    # a unix socket


def test_public_peers_and_proxied_requests_are_refused_by_default():
    assert classify(req(client=("8.8.8.8", 1)), "off")[0] is False
    for header in ("X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP", "Forwarded", "CF-Connecting-IP", "Via"):
        assert classify(req({header: "192.168.0.5"}), "off")[0] is False, header


def test_lan_mode_trusts_the_last_forwarded_address_only():
    assert classify(req({"X-Forwarded-For": "192.168.0.5"}), "lan")[0] is True
    assert classify(req({"X-Forwarded-For": "203.0.113.9"}), "lan")[0] is False
    # a client cannot make itself local by sending its own X-Forwarded-For: the proxy appends the real address at the end
    assert classify(req({"X-Forwarded-For": "192.168.0.5, 203.0.113.9"}), "lan")[0] is False
    assert classify(req({"X-Forwarded-Proto": "https"}), "lan")[0] is False   # a proxy that does not say who the client is
    assert classify(req({"X-Forwarded-For": "[fd00::5]:1234"}), "lan")[0] is True
    assert classify(req({"X-Forwarded-For": "203.0.113.9"}, client=("8.8.8.8", 1)), "lan")[0] is False


def test_any_mode_allows_everything():
    assert classify(req({"X-Forwarded-For": "203.0.113.9"}, client=("8.8.8.8", 1)), "any")[0] is True


def test_configuration():
    assert parse_mode(None) == "off" and parse_mode("LAN") == "lan" and parse_mode("nonsense") == "off"
    assert load_settings({"NETLENS_TOKEN": "t"}).terminal_remote == "off"
    assert load_settings({"NETLENS_TOKEN": "t", "NETLENS_TERMINAL_REMOTE": "LAN"}).terminal_remote == "lan"
    with pytest.raises(ConfigError):
        load_settings({"NETLENS_TOKEN": "t", "NETLENS_TERMINAL_REMOTE": "yes"})


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_config_says_whether_the_terminal_is_available_here(client):
    cfg = client.get("/api/config").json()
    assert cfg["terminal_available"] is True and cfg["terminal_remote"] == "off"
    behind_proxy = client.get("/api/config", headers={"X-Forwarded-Proto": "https"}).json()
    assert behind_proxy["terminal_enabled"] is True and behind_proxy["terminal_available"] is False
    assert "reverse proxy" in behind_proxy["terminal_here"]


def test_terminal_routes_refuse_proxied_requests(client):
    r = client.delete("/api/devices/1/hostkey", headers={"X-Forwarded-Proto": "https"})
    assert r.status_code == 403 and "not available here" in r.json()["detail"]
    with pytest.raises(Exception):
        with client.websocket_connect("/api/terminal/1/ws?proto=ssh", headers={"X-Forwarded-For": "203.0.113.9"}):
            pass


def test_the_terminal_switch_cannot_be_flipped_from_outside(client):
    outside = {"X-Forwarded-For": "203.0.113.9"}
    assert client.put("/api/config/general", json={"terminal_enabled": False}, headers=outside).status_code == 403
    # saving other settings from outside still works (the form always sends the terminal value too)
    assert client.put("/api/config/general", json={"terminal_enabled": True, "quick_interval": 600}, headers=outside).status_code == 200
    assert client.put("/api/config/general", json={"terminal_enabled": False}).status_code == 200      # locally it works
    assert client.put("/api/config/general", json={"terminal_enabled": True}, headers=outside).status_code == 403
