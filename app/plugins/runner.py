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


def run_subprocess(plugin: Plugin, action: str, config: dict, timeout: float | None = None):
    """Call plugin.<action>(config) and return its result (blocking)."""
    if plugin.manifest is None:
        raise PluginRunError(plugin.problem or "the plugin is broken")
    timeout = timeout or plugin.manifest["timeout"]
    cmd = [sys.executable, "-I", str(WORKER), str(plugin.path), "builtin" if plugin.builtin else "user", action]
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps({"config": config}).encode(),
            capture_output=True,
            timeout=timeout,
            env=_clean_env(),
            cwd=str(plugin.path),
        )
    except subprocess.TimeoutExpired as exc:
        raise PluginRunError(f"the plugin did not answer within {int(timeout)} seconds") from exc
    except OSError as exc:
        raise PluginRunError(f"could not start the plugin: {exc}") from exc
    out = proc.stdout[:MAX_OUTPUT + 1]
    if len(out) > MAX_OUTPUT:
        raise PluginRunError("the plugin returned too much data")
    lines = out.decode("utf-8", errors="replace").strip().splitlines()
    if not lines:
        tail = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["no output"]
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
