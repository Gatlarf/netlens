"""A plugin whose host is simply off is not failing; one that fails while its host is up is."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import dashboard, stats
from app.db import connect, get_or_create_device, init_db
from app.plugins import reach
from app.plugins.runner import PluginRunError
from app.plugins.service import PluginService, get_status, save_state, set_status
from tests.plugin_helpers import fake, make_runner, write_plugin

NO_ROUTE = "cannot reach 10.0.0.9:5986: [Errno 113] No route to host"


def host_plugin(tmp_path, error):
    def fetch(cfg):
        raise PluginRunError(error)

    return write_plugin(tmp_path, "dock", "hypervisor", manifest={"config": [{"key": "host", "type": "text", "label": "Address", "default": ""}]}), fake(fetch=fetch)


@pytest.fixture
def world(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    return conn, path


def put_device(conn, ip, online):
    d = get_or_create_device(conn, "aa:00:00:00:00:%02d" % int(ip.split(".")[-1]), ip)
    conn.execute("UPDATE devices SET online = ? WHERE id = ?", (online, d))
    conn.commit()
    return d


def test_classify_offline_host_is_not_a_plugin_failure(world):
    conn, _ = world
    d = put_device(conn, "10.0.0.9", 0)
    out = reach.classify(conn, {"host": "https://10.0.0.9:5986"}, NO_ROUTE)
    assert out["reason"] == reach.HOST_DOWN and out["device_id"] == d and out["host"] == "10.0.0.9"


def test_classify_host_that_is_up_is_a_failure(world):
    conn, _ = world
    put_device(conn, "10.0.0.9", 1)
    assert reach.classify(conn, {"host": "10.0.0.9"}, "cannot reach 10.0.0.9:5986: connection refused")["reason"] == reach.FAILED


def test_classify_refused_login_and_certificate_problems_are_failures_even_when_the_device_is_off(world):
    conn, _ = world
    put_device(conn, "10.0.0.9", 0)
    assert reach.classify(conn, {"host": "10.0.0.9"}, NO_ROUTE, auth_failed=True)["reason"] == reach.FAILED
    assert reach.classify(conn, {"host": "10.0.0.9"}, "cannot reach 10.0.0.9: certificate verify failed")["reason"] == reach.FAILED
    assert reach.classify(conn, {"host": "10.0.0.9"}, "http 500 from 10.0.0.9")["reason"] == reach.FAILED


def test_classify_without_a_device_only_a_private_address_counts_as_down(world):
    conn, _ = world
    assert reach.classify(conn, {"host": "10.0.0.50"}, "timed out")["reason"] == reach.HOST_DOWN
    assert reach.classify(conn, {"host": "api.example.com"}, "timed out")["reason"] == reach.FAILED
    assert reach.classify(conn, {"host": "8.8.8.8"}, "timed out")["reason"] == reach.FAILED


def test_classify_finds_the_host_in_the_servers_of_the_config_and_by_name(world):
    conn, _ = world
    d = put_device(conn, "10.0.0.9", 0)
    conn.execute("UPDATE devices SET hostname = 'hv1' WHERE id = ?", (d,))
    conn.commit()
    assert reach.classify(conn, {"servers": [{"host": "https://hv1.lan:5986", "password": "x"}]}, "timed out")["device_id"] == d


@pytest.mark.asyncio
async def test_a_sync_against_an_offline_host_waits_and_a_sync_against_a_live_one_fails(world, tmp_path):
    conn, path = world
    d = put_device(conn, "10.0.0.9", 0)
    plugin, runner_fake = host_plugin(tmp_path, NO_ROUTE)
    save_state(conn, "dock", True, {"host": "https://10.0.0.9:5986"})
    svc = PluginService(str(path), tmp_path, make_runner(dock=runner_fake))
    for _ in range(5):                                        # far more than the grace
        await svc.sync("dock")
    status = get_status(conn, "dock")
    assert status["reason"] == "host_down" and status["host_device_id"] == d
    doc = [p for p in stats._plugin_status(conn) if p["id"] == "dock"][0]
    assert doc["host_down"] and not doc["failing"] and not doc["stale"]
    assert not [i for i in dashboard.build(conn, stats.summary(conn))["attention"] if "dock" in i["text"]]
    assert conn.execute("SELECT COUNT(*) FROM plugin_runs").fetchone()[0] == 0          # a switched-off host does not spoil the plugin's own heartbeat
    conn.execute("UPDATE devices SET online = 1 WHERE id = ?", (d,))
    conn.commit()
    for _ in range(3):                                        # the host is up now, so the same error is the plugin's problem
        await svc.sync("dock")
    status = get_status(conn, "dock")
    assert status["reason"] == "failed" and status["fails"] == 3
    assert [i for i in dashboard.build(conn, stats.summary(conn))["attention"] if "Plugin dock is failing" in i["text"]]


def test_a_host_that_stays_off_for_days_gets_one_quiet_hint(world):
    conn, _ = world
    save_state(conn, "dock", True, {})
    set_status(conn, "dock", ok=False, error="timed out", reason="host_down", host="10.0.0.9", host_device_id=None, host_name="hv1")
    status = get_status(conn, "dock")
    status["first_failed"] = (datetime.now(timezone.utc) - timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE settings SET value = ? WHERE key = 'plugin.dock.status'", (json.dumps(status),))
    conn.commit()
    items = [i for i in dashboard.build(conn, stats.summary(conn))["attention"] if "dock" in i["text"]]
    assert len(items) == 1 and items[0]["level"] == "warn" and "no answer from hv1 for 9 days" in items[0]["text"]


def test_retry_is_hourly_while_the_host_is_off_and_immediate_when_it_is_back(world):
    conn, _ = world
    d = put_device(conn, "10.0.0.9", 0)
    status = {"ts": (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"), "host_device_id": d}
    assert not reach.due_again(conn, status)
    status["ts"] = (datetime.now(timezone.utc) - timedelta(minutes=61)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert reach.due_again(conn, status)
    status["ts"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE devices SET online = 1 WHERE id = ?", (d,))
    conn.commit()
    assert reach.due_again(conn, status)
