"""The plugin runner: a small server that runs plugins for Netlens in a container of its own.

Why: a plugin is code from somebody else. Run inside the Netlens container it would be a process of the same user on the same filesystem and could read the encryption key,
the database and the environment of Netlens, and send them anywhere. In this container there is none of that: no data volume, no key, no database. It receives the plugin's files and
its configuration with each call, runs the worker as before (a stripped environment, a time limit), and returns what the worker printed.

    python -m app.plugins.runner_server          NETLENS_RUNNER_TOKEN is required; NETLENS_RUNNER_BIND is host:port (default 0.0.0.0:8099)

Netlens uses it when NETLENS_PLUGIN_RUNNER (http://host:port) and the same NETLENS_RUNNER_TOKEN are set. See docs/PLUGIN-RUNNER.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.plugins.runner import MAX_OUTPUT, MAX_PLUGIN_BYTES, PLUGIN_FILES, PluginRunError, WORKER, execute

MAX_REQUEST = 6 * 1024 * 1024
MAX_PARALLEL = 8
SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_gate = threading.BoundedSemaphore(MAX_PARALLEL)
_ROOT = Path(os.environ.get("NETLENS_RUNNER_DIR") or tempfile.gettempdir()) / "netlens-plugins"


def _directory(plugin_id: str, files: dict) -> Path:
    """The plugin's files under a folder named by their hash: the same files are written once, other files never replace them."""
    if not SAFE_NAME.match(plugin_id or "") or not isinstance(files, dict) or "plugin.py" not in files or "plugin.json" not in files:
        raise ValueError("the call has to name the plugin and send plugin.py and plugin.json")
    blobs: dict[str, bytes] = {}
    for name, text in files.items():
        if not SAFE_NAME.match(name) or Path(name).suffix not in PLUGIN_FILES:
            raise ValueError(f"file {name!r} is not allowed")
        blobs[name] = base64.b64decode(str(text), validate=True)
    if sum(len(b) for b in blobs.values()) > MAX_PLUGIN_BYTES:
        raise ValueError("the plugin files are too large")
    digest = hashlib.sha256()
    for name in sorted(blobs):
        digest.update(name.encode() + b"\0" + blobs[name] + b"\0")
    target = _ROOT / plugin_id / digest.hexdigest()[:16]
    if not (target / "plugin.py").is_file():
        staging = Path(tempfile.mkdtemp(dir=_ROOT_ready()))
        for name, data in blobs.items():
            (staging / name).write_bytes(data)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            staging.rename(target)
        except OSError:                                   # another call wrote the same files first
            shutil.rmtree(staging, ignore_errors=True)
        else:
            for old in target.parent.iterdir():           # one version per plugin is enough
                if old != target:
                    shutil.rmtree(old, ignore_errors=True)
    return target


def _ROOT_ready() -> Path:
    _ROOT.mkdir(parents=True, exist_ok=True)
    return _ROOT


def run_call(call: dict) -> dict:
    directory = _directory(str(call.get("plugin") or ""), call.get("files"))
    action = str(call.get("action") or "")
    if not SAFE_NAME.match(action):
        raise ValueError("no such action")
    timeout = min(max(float(call.get("timeout") or 30), 1.0), 900.0)
    cmd = [sys.executable, "-I", str(WORKER), str(directory), "user", action]
    try:
        stdout, stderr = execute(cmd, str(call.get("input") or "{}").encode(), timeout, str(directory))
    except PluginRunError as exc:
        if "did not answer" in str(exc):
            return {"timeout": True}
        raise
    return {"stdout": stdout[:MAX_OUTPUT].decode("utf-8", errors="replace"), "stderr": stderr[-4000:].decode("utf-8", errors="replace")}


def _token() -> str:
    return os.environ.get("NETLENS_RUNNER_TOKEN", "")


class Handler(BaseHTTPRequestHandler):
    server_version = "netlens-runner"

    def log_message(self, *args) -> None:        # no access log: the bodies hold plugin configurations
        pass

    def _send(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        token = _token()
        given = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        if not token or not hmac.compare_digest(given.encode(), token.encode()):
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = -1
        if not 0 < size <= MAX_REQUEST:
            return self._send(413, {"error": "bad size"})
        if not _gate.acquire(blocking=False):
            return self._send(429, {"error": "busy"})
        try:
            self._send(200, run_call(json.loads(self.rfile.read(size))))
        except (ValueError, KeyError) as exc:
            self._send(400, {"error": str(exc)[:200]})
        except Exception as exc:  # noqa: BLE001 - the caller gets a sentence, the container keeps running
            self._send(500, {"error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        finally:
            _gate.release()


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main() -> int:
    if not os.environ.get("NETLENS_RUNNER_TOKEN"):
        print("NETLENS_RUNNER_TOKEN is not set: the plugin runner would accept calls from anybody, so it does not start", file=sys.stderr)
        return 2
    from app import hardening

    hardening.protect_process()                 # a plugin in this container cannot read the runner's token from /proc
    host, _, port = (os.environ.get("NETLENS_RUNNER_BIND") or "0.0.0.0:8099").rpartition(":")
    print(f"plugin runner listening on {host or '0.0.0.0'}:{port}", flush=True)
    make_server(host or "0.0.0.0", int(port)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
