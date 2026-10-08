"""The real subprocess runner: isolation, time limit and error reporting."""

import os
import textwrap

import pytest

from app.plugins.registry import discover
from app.plugins.runner import PluginRunError, run_subprocess
from tests.plugin_helpers import write_plugin


def plugin(tmp_path, py, **kw):
    write_plugin(tmp_path, "demo", py=textwrap.dedent(py), **kw)
    return discover(tmp_path)["demo"]


def test_a_plugin_runs_in_its_own_process_with_its_config(tmp_path):
    p = plugin(tmp_path, """
        import os
        def test(config):
            return {"message": "pid %s host %s" % (os.getpid(), config["host"])}
        def fetch(config):
            return {"nodes": [], "clients": []}
    """)
    msg = run_subprocess(p, "test", {"host": "r.lan"})["message"]
    assert "host r.lan" in msg and f"pid {os.getpid()} " not in msg
    assert run_subprocess(p, "fetch", {}) == {"nodes": [], "clients": []}


def test_the_plugin_sees_no_netlens_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("NETLENS_TOKEN", "super-secret")
    monkeypatch.setenv("NETLENS_DATA_DIR", "/data")
    p = plugin(tmp_path, """
        import os
        def test(config):
            return {"message": ",".join(sorted(k for k in os.environ if k.startswith("NETLENS")))}
        def fetch(config):
            return {}
    """)
    assert run_subprocess(p, "test", {})["message"] == ""


def test_the_plugin_cannot_import_netlens_code(tmp_path):
    p = plugin(tmp_path, """
        def test(config):
            import app.db
            return {}
        def fetch(config):
            return {}
    """)
    with pytest.raises(PluginRunError, match="app"):
        run_subprocess(p, "test", {})


def test_exceptions_become_messages_and_auth_failures_are_flagged(tmp_path):
    p = plugin(tmp_path, """
        class Refused(Exception):
            auth_failed = True
        def test(config):
            raise Refused("login refused")
        def fetch(config):
            raise ValueError("boom")
    """)
    with pytest.raises(PluginRunError) as exc:
        run_subprocess(p, "test", {})
    assert str(exc.value) == "login refused" and exc.value.auth_failed is True
    with pytest.raises(PluginRunError) as exc:
        run_subprocess(p, "fetch", {})
    assert str(exc.value) == "boom" and exc.value.auth_failed is False


def test_prints_do_not_corrupt_the_result(tmp_path):
    p = plugin(tmp_path, """
        def test(config):
            print("debug noise")
            return {"message": "fine"}
        def fetch(config):
            return {}
    """)
    assert run_subprocess(p, "test", {}) == {"message": "fine"}


def test_timeout_crash_and_garbage(tmp_path):
    slow = plugin(tmp_path, """
        import time
        def test(config):
            time.sleep(30)
        def fetch(config):
            return {}
    """)
    with pytest.raises(PluginRunError, match="did not answer within 1 seconds"):
        run_subprocess(slow, "test", {}, timeout=1)

    (tmp_path / "b").mkdir()
    crash = plugin(tmp_path / "b", """
        import os
        def test(config):
            os._exit(3)
        def fetch(config):
            return {}
    """)
    with pytest.raises(PluginRunError, match="crashed"):
        run_subprocess(crash, "test", {})

    (tmp_path / "c").mkdir()
    bad = plugin(tmp_path / "c", """
        def test(config):
            return {1, 2}
        def fetch(config):
            return {}
    """)
    with pytest.raises(PluginRunError, match="not JSON"):
        run_subprocess(bad, "test", {})


def test_syntax_error_at_import_is_reported(tmp_path):
    p = plugin(tmp_path, "def test(config:\n    pass\n")
    with pytest.raises(PluginRunError):
        run_subprocess(p, "test", {})


def test_a_missing_function_is_reported(tmp_path):
    p = plugin(tmp_path, "def fetch(config):\n    return {}\n")
    with pytest.raises(PluginRunError, match="no test"):
        run_subprocess(p, "test", {})


def test_a_broken_plugin_is_not_run(tmp_path):
    p = plugin(tmp_path, "x = 1")
    p.manifest = None
    p.problem = "plugin.json: broken"
    with pytest.raises(PluginRunError, match="broken"):
        run_subprocess(p, "test", {})


def test_builtin_plugins_run_through_the_worker():
    # no credentials: the Proxmox plugin refuses with a helpful message instead of trying the network
    with pytest.raises(PluginRunError, match="API token"):
        run_subprocess(discover(None)["proxmox"], "test", {"url": "https://pve.invalid:8006"})
    with pytest.raises(PluginRunError, match="router address"):
        run_subprocess(discover(None)["asus"], "fetch", {})
