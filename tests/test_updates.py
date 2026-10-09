import json

import pytest
from fastapi.testclient import TestClient

from app import updates
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.index import PluginIndexError
from app.stats import summary

AUTH = {"Authorization": "Bearer secret"}


class Registry:
    def __init__(self, tags):
        self.tags, self.calls, self.fail = tags, [], None

    def __call__(self, url, *, max_bytes, headers=None, timeout=20.0):
        self.calls.append(url)
        if self.fail:
            raise PluginIndexError(self.fail)
        if "token" in url:
            return 200, json.dumps({"token": "T"}).encode(), {}
        assert headers["Authorization"] == "Bearer T"
        return 200, json.dumps({"name": "x", "tags": self.tags}).encode(), {}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    return c


def test_latest_is_the_highest_version_tag_not_latest_or_sha():
    reg = Registry(["latest", "sha-abc123", "0.2.9", "0.2.44", "0.2.10", "0.3", "0.2.44-rc1", "main"])
    assert updates.fetch_latest(reg) == "0.2.44"  # numeric, not alphabetical
    with pytest.raises(PluginIndexError, match="no version tags"):
        updates.fetch_latest(Registry(["latest"]))


def test_unexpected_answers_are_handled():
    def odd(url, *, max_bytes, headers=None, timeout=20.0):
        return 200, b"<html>", {}

    with pytest.raises(PluginIndexError, match="unexpected"):
        updates.fetch_latest(odd)


def test_check_flags_a_newer_version_and_caches_for_a_day(conn):
    reg = Registry(["0.2.44", "0.2.46"])
    r = updates.check(conn, getter=reg, now="2026-03-10T12:00:00Z", current="0.2.44")
    assert r["available"] is True and r["latest"] == "0.2.46" and r["current"] == "0.2.44" and r["error"] is None
    calls = len(reg.calls)
    updates.check(conn, getter=reg, now="2026-03-10T20:00:00Z", current="0.2.44")
    assert len(reg.calls) == calls  # inside a day: no new request
    updates.check(conn, getter=reg, now="2026-03-11T13:00:00Z", current="0.2.44")
    assert len(reg.calls) > calls
    assert updates.check(conn, force=True, getter=reg, now="2026-03-11T13:05:00Z", current="0.2.46")["available"] is False  # up to date
    assert updates.status(conn, "0.2.50")["available"] is False  # ahead of the registry (a build from source): no nag


def test_failure_keeps_the_last_answer(conn):
    reg = Registry(["0.2.46"])
    updates.check(conn, getter=reg, now="2026-03-10T12:00:00Z", current="0.2.44")
    reg.fail = "cannot reach the server (timed out)"
    r = updates.check(conn, force=True, getter=reg, now="2026-03-12T12:00:00Z", current="0.2.44")
    assert r["available"] is True and "cannot reach" in r["error"]


def test_turning_the_check_off_stops_all_requests(conn):
    updates.set_enabled(conn, False)
    reg = Registry(["0.2.46"])
    r = updates.check(conn, force=True, getter=reg, current="0.2.44")
    assert reg.calls == [] and r["enabled"] is False and r["available"] is False


def test_development_builds_are_never_told_to_update(conn):
    updates.check(conn, getter=Registry(["0.2.46"]), now="2026-03-10T12:00:00Z", current="0.2.0-dev")
    assert updates.status(conn, "0.2.0-dev")["available"] is True  # a plain dev build is older than 0.2.46: that is correct
    assert updates.status(conn, "0.3.0-dev")["available"] is False


def test_summary_and_metrics_carry_the_update_state(conn):
    updates.check(conn, getter=Registry(["99.0.1"]), now="2026-03-10T12:00:00Z")
    doc = summary(conn, "2026-03-10T12:00:00Z")
    assert doc["update"]["available"] is True and doc["update"]["latest"] == "99.0.1" and doc["update"]["plugin_updates"] == 0
    from app.metrics import render_metrics

    assert "netlens_update_available 1" in render_metrics(conn, "2026-03-10T12:00:00Z")


def test_api(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    app.state.update_getter = Registry(["99.0.1"])
    with TestClient(app, headers=AUTH) as client:
        body = client.get("/api/update").json()
        assert body["available"] is True and body["latest"] == "99.0.1" and body["changelog_url"].endswith("CHANGELOG.md")
        n = len(app.state.update_getter.calls)
        client.get("/api/update")
        assert len(app.state.update_getter.calls) == n
        client.get("/api/update", params={"refresh": "true"})
        assert len(app.state.update_getter.calls) > n
        assert client.put("/api/update", json={"enabled": False}).json()["available"] is False
        assert client.get("/api/update").json()["enabled"] is False
        assert client.get("/api/update", headers={"Authorization": "Bearer no"}).status_code == 401
        assert client.put("/api/update", json={}, headers={"Authorization": "Bearer no"}).status_code == 401
