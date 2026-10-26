"""Runs a plugin function in a separate process with a time limit, so a broken plugin cannot hang or crash Netlens."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from app.plugins.registry import Plugin

WORKER = Path(__file__).resolve().parent / "worker.py"
MAX_OUTPUT = 8 * 1024 * 1024


class PluginRunError(Exception):
    """The plugin failed; the message is meant for the user."""

    def __init__(self, message: str, auth_failed: bool = False):
        super().__init__(message)
        self.auth_failed = auth_failed


def _clean_env() -> dict[str, str]:
    # no NETLENS_* variables, no tokens: the plugin gets its own configuration and nothing else
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8"}
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "TZ"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


RUNNER_ENV = "NETLENS_PLUGIN_RUNNER"            # http://host:port of the plugin runner (a separate container, see docs/PLUGIN-RUNNER.md)
RUNNER_TOKEN_ENV = "NETLENS_RUNNER_TOKEN"
PLUGIN_FILES = (".py", ".json")
MAX_PLUGIN_BYTES = 2 * 1024 * 1024


def runner_url() -> str:
    return os.environ.get(RUNNER_ENV, "").strip().rstrip("/")


def isolation() -> dict:
    """Where plugins run: "runner" (a separate container that holds none of Netlens' secrets) or "local" (a process of the same container: it can read everything Netlens can)."""
    url = runner_url()
    return {"mode": "runner" if url else "local", "runner": url or None}


def execute(cmd: list[str], payload: bytes, timeout: float, cwd: str) -> tuple[bytes, bytes]:
    """Run the worker process; returns (stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True, timeout=timeout, env=_clean_env(), cwd=cwd)
    except subprocess.TimeoutExpired as exc:
        raise PluginRunError(f"the plugin did not answer within {int(timeout)} seconds") from exc
    except OSError as exc:
        raise PluginRunError(f"could not start the plugin: {exc}") from exc
    return proc.stdout, proc.stderr


def _files_of(plugin: Plugin) -> dict[str, str]:
    import base64

    files: dict[str, str] = {}
    total = 0
    for item in sorted(plugin.path.iterdir()):
        if item.is_file() and item.suffix in PLUGIN_FILES:
            data = item.read_bytes()
            total += len(data)
            files[item.name] = base64.b64encode(data).decode()
    if total > MAX_PLUGIN_BYTES:
        raise PluginRunError("the plugin files are too large to send to the plugin runner")
    return files


def _remote(plugin: Plugin, action: str, request: bytes, timeout: float) -> tuple[bytes, bytes]:
    """The same call, made by the plugin runner. The runner is told which files to run (the plugin never needs a volume of Netlens)."""
    import urllib.error
    import urllib.request

    token = os.environ.get(RUNNER_TOKEN_ENV, "")
    if not token:
        raise PluginRunError(f"{RUNNER_ENV} is set but {RUNNER_TOKEN_ENV} is not: plugins are not run")
    body = json.dumps({"plugin": plugin.id, "action": action, "timeout": timeout, "files": _files_of(plugin), "input": request.decode()}).encode()
    req = urllib.request.Request(runner_url() + "/run", data=body, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout + 15) as resp:
            answer = json.loads(resp.read(MAX_OUTPUT * 2).decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise PluginRunError(f"the plugin runner refused the call (HTTP {exc.code})") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # fail closed: a plugin is never run inside Netlens' own container when a runner was asked for
        raise PluginRunError(f"the plugin runner cannot be reached ({exc}); the plugin was not run") from exc
    if answer.get("timeout"):
        raise PluginRunError(f"the plugin did not answer within {int(timeout)} seconds")
    return str(answer.get("stdout") or "").encode(), str(answer.get("stderr") or "").encode()


def run_subprocess(plugin: Plugin, action: str, config: dict, timeout: float | None = None, payload=None):
    """Call plugin.<action>(config) (or <action>(config, payload) when there is one) and return its result (blocking)."""
    if plugin.manifest is None:
        raise PluginRunError(plugin.problem or "the plugin is broken")
    timeout = timeout or plugin.manifest["timeout"]
    request = json.dumps({"config": config, **({"payload": payload} if payload is not None else {})}).encode()
    if runner_url():
        stdout, stderr = _remote(plugin, action, request, timeout)
    else:
        cmd = [sys.executable, "-I", str(WORKER), str(plugin.path), "builtin" if plugin.builtin else "user", action]
        stdout, stderr = execute(cmd, request, timeout, str(plugin.path))
    out = stdout[:MAX_OUTPUT + 1]
    if len(out) > MAX_OUTPUT:
        raise PluginRunError("the plugin returned too much data")
    lines = out.decode("utf-8", errors="replace").strip().splitlines()
    if not lines:
        tail = stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["no output"]
        raise PluginRunError(f"the plugin crashed ({tail[0][:200]})")
    try:
        payload = json.loads(lines[-1])
    except ValueError as exc:
        raise PluginRunError("the plugin returned something that is not JSON") from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise PluginRunError("the plugin returned an unexpected answer")
    if not payload["ok"]:
        raise PluginRunError(str(payload.get("error") or "the plugin failed"), bool(payload.get("auth_failed")))
    return payload.get("result")
