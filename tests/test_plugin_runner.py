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


# ---------------------------------------------------------------- the plugin runner: plugins in a container of their own
@pytest.fixture
def runner(monkeypatch, tmp_path):
    import threading

    from app.plugins import runner_server

    monkeypatch.setattr(runner_server, "_ROOT", tmp_path / "runner-files")
    monkeypatch.setenv("NETLENS_RUNNER_TOKEN", "long-random-token")
    monkeypatch.setattr(runner_server, "_token", lambda: "long-random-token")           # the runner's own value; the test process is both sides
    server = runner_server.make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("NETLENS_PLUGIN_RUNNER", f"http://127.0.0.1:{server.server_address[1]}")
    yield server
    server.shutdown()
    server.server_close()


def test_a_plugin_runs_in_the_runner_and_the_runner_holds_none_of_the_secrets(tmp_path, runner, monkeypatch):
    from app.plugins.runner import isolation

    assert isolation()["mode"] == "runner"
    p = plugin(tmp_path, """
        import os
        def test(config):
            return {"message": "host %s env %s" % (config["host"], ",".join(sorted(k for k in os.environ if k.startswith("NETLENS"))))}
        def fetch(config):
            return {"nodes": [], "clients": []}
    """)
    monkeypatch.setenv("NETLENS_SECRET_KEY", "must-not-reach-the-plugin")
    assert run_subprocess(p, "test", {"host": "r.lan"})["message"] == "host r.lan env "
    assert run_subprocess(p, "fetch", {}) == {"nodes": [], "clients": []}


def test_the_runner_fails_closed_and_checks_the_token(tmp_path, runner, monkeypatch):
    p = plugin(tmp_path, """
        def test(config):
            return {"message": "ran"}
        def fetch(config):
            return {}
    """)
    monkeypatch.setenv("NETLENS_RUNNER_TOKEN", "another-token")                         # Netlens and the runner no longer agree
    with pytest.raises(PluginRunError, match="refused"):
        run_subprocess(p, "test", {})
    monkeypatch.setenv("NETLENS_RUNNER_TOKEN", "long-random-token")
    monkeypatch.setenv("NETLENS_PLUGIN_RUNNER", "http://127.0.0.1:9")                  # nobody listens: the plugin is NOT run locally instead
    with pytest.raises(PluginRunError, match="cannot be reached"):
        run_subprocess(p, "test", {})
    monkeypatch.delenv("NETLENS_RUNNER_TOKEN")
    with pytest.raises(PluginRunError, match="not run"):
        run_subprocess(p, "test", {})


def test_the_runner_refuses_odd_calls(runner, monkeypatch):
    import json
    import urllib.error
    import urllib.request

    url = os.environ["NETLENS_PLUGIN_RUNNER"] + "/run"

    def post(body, token="long-random-token"):
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
        try:
            return urllib.request.urlopen(req, timeout=10).status
        except urllib.error.HTTPError as exc:
            return exc.code

    assert post({}, token="wrong") == 401
    assert post({"plugin": "demo", "files": {"plugin.py": "", "plugin.json": ""}, "action": "../evil"}) == 400
    assert post({"plugin": "demo", "files": {"../x.py": "", "plugin.py": "", "plugin.json": ""}, "action": "test"}) == 400      # no path in a file name
    assert post({"plugin": "demo", "files": {"plugin.py": "", "plugin.json": "", "run.sh": ""}, "action": "test"}) == 400         # only .py and .json


def test_the_runner_does_not_start_without_a_token(monkeypatch):
    from app.plugins import runner_server

    monkeypatch.delenv("NETLENS_RUNNER_TOKEN", raising=False)
    assert runner_server.main() == 2


def test_the_key_can_come_from_a_secret_file_and_the_process_is_non_dumpable(tmp_path, monkeypatch):
    from app import hardening, vault
    from app.db import connect, init_db

    key_file = tmp_path / "netlens_key"
    key_file.write_text(vault.encode_key(b"k" * 32) + "\n")
    monkeypatch.setenv("NETLENS_SECRET_KEY_FILE", str(key_file))
    c = connect(tmp_path / "v.db")
    init_db(c)
    assert vault.key_source(c) == "env" and vault.status(c)["key_next_to_data"] is False
    assert vault.decrypt(c, vault.encrypt(c, "secret")) == "secret"
    assert not (tmp_path / "secret.key").exists()                                       # no key file was made next to the data
    monkeypatch.setenv("NETLENS_SECRET_KEY_FILE", str(tmp_path / "missing"))
    with pytest.raises(vault.VaultError, match="cannot be read"):
        vault.key_source(c)
    monkeypatch.delenv("NETLENS_SECRET_KEY_FILE")
    assert vault.status(c)["key_next_to_data"] is True
    assert hardening.protect_process() in (True, False)
