import time
import types
from typing import List, Optional

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.auth import COOKIE_NAME, LoginLimiter, is_authorized, require_auth, session_value


def test_session_value_deterministic():
    assert session_value("token1") == session_value("token1")


def test_session_value_is_64_hex_chars():
    value = session_value("token1")
    assert len(value) == 64
    assert all(c in "0123456789abcdef" for c in value)


def test_session_value_differs_per_token():
    assert session_value("token1") != session_value("token2")


def test_is_authorized_true_with_right_cookie():
    token = "secret"
    cookie = session_value(token)
    assert is_authorized(token, cookie, None)


def test_is_authorized_true_with_bearer_secret():
    token = "secret"
    assert is_authorized(token, None, "Bearer secret")


def test_is_authorized_false_with_wrong_cookie():
    token = "secret"
    wrong_cookie = session_value("wrong")
    assert not is_authorized(token, wrong_cookie, None)


def test_is_authorized_false_with_wrong_bearer():
    token = "secret"
    assert not is_authorized(token, None, "Bearer wrong")


def test_is_authorized_false_with_basic_secret():
    token = "secret"
    assert not is_authorized(token, None, "Basic secret")


def test_is_authorized_false_with_none_none():
    token = "secret"
    assert not is_authorized(token, None, None)


def test_is_authorized_does_not_raise_for_non_ascii_input():
    token = "secret"
    non_ascii = "café"
    assert not is_authorized(token, non_ascii, None)
    assert not is_authorized(token, None, "Bearer " + non_ascii)


def test_login_limiter_5_failures_block():
    clock_values = [0.0]
    limiter = LoginLimiter(max_failures=5, window=60.0, clock=lambda: clock_values[0])
    key = "user1"
    for _ in range(5):
        limiter.record_failure(key)
    assert not limiter.allowed(key)


def test_login_limiter_4_failures_do_not_block():
    clock_values = [0.0]
    limiter = LoginLimiter(max_failures=5, window=60.0, clock=lambda: clock_values[0])
    key = "user1"
    for _ in range(4):
        limiter.record_failure(key)
    assert limiter.allowed(key)


def test_login_limiter_failures_expire_after_window():
    clock_values = [0.0]
    limiter = LoginLimiter(max_failures=5, window=60.0, clock=lambda: clock_values[0])
    key = "user1"
    for _ in range(5):
        limiter.record_failure(key)
    assert not limiter.allowed(key)
    clock_values[0] = 61.0
    assert limiter.allowed(key)


def test_login_limiter_reset_clears():
    clock_values = [0.0]
    limiter = LoginLimiter(max_failures=5, window=60.0, clock=lambda: clock_values[0])
    key = "user1"
    for _ in range(5):
        limiter.record_failure(key)
    assert not limiter.allowed(key)
    limiter.reset(key)
    assert limiter.allowed(key)


def test_login_limiter_keys_are_independent():
    clock_values = [0.0]
    limiter = LoginLimiter(max_failures=5, window=60.0, clock=lambda: clock_values[0])
    key1 = "user1"
    key2 = "user2"
    for _ in range(5):
        limiter.record_failure(key1)
    assert not limiter.allowed(key1)
    assert limiter.allowed(key2)


def test_require_auth_401_with_wrong_bearer():
    app = FastAPI()
    app.state.settings = types.SimpleNamespace(token="secret")

    @app.get("/p", dependencies=[Depends(require_auth)])
    def endpoint():
        return {"ok": True}

    client = TestClient(app, headers={"Authorization": "Bearer wrong"})
    response = client.get("/p")
    assert response.status_code == 401
    assert response.json()["detail"] == "authentication required"


def test_require_auth_200_with_correct_bearer():
    app = FastAPI()
    app.state.settings = types.SimpleNamespace(token="secret")

    @app.get("/p", dependencies=[Depends(require_auth)])
    def endpoint():
        return {"ok": True}

    client = TestClient(app, headers={"Authorization": "Bearer secret"})
    response = client.get("/p")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_require_auth_200_with_correct_cookie():
    app = FastAPI()
    app.state.settings = types.SimpleNamespace(token="secret")

    @app.get("/p", dependencies=[Depends(require_auth)])
    def endpoint():
        return {"ok": True}

    client = TestClient(app)
    client.cookies.set(COOKIE_NAME, session_value("secret"))
    response = client.get("/p")
    assert response.status_code == 200
    assert response.json() == {"ok": True}