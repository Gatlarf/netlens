"""Runs one plugin call in its own process: `python -I worker.py <plugin dir> <builtin|user> <test|fetch>`.

Reads {"config": {...}} as JSON on stdin and prints one JSON line {"ok": true, "result": ...} or
{"ok": false, "error": "...", "auth_failed": bool}. The process gets no database path and a stripped
environment, and only the plugin's own folder (plus the Netlens code for built-in plugins) is importable.
"""

import importlib
import importlib.util
import json
import sys
from pathlib import Path


def _guard_redirects() -> None:
    """A plugin talks to a device it was given and to nothing else: a redirect to a file, to the cloud metadata service or from https back to http is refused, and the
    login details (Authorization, cookies, API keys) are not sent along to another host. Stdlib only: this process cannot import Netlens code (see app/safenet.py)."""
    import ipaddress
    import urllib.error
    import urllib.parse
    import urllib.request

    original = urllib.request.HTTPRedirectHandler.redirect_request
    secret_headers = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-api-token", "csrftoken", "x-csrf-token", "private-token"}

    def refused(req, fp, code, headers, why):
        return urllib.error.HTTPError(req.full_url, code, f"redirect refused: {why}", headers, fp)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        source = urllib.parse.urlsplit(req.full_url)
        if target.scheme.lower() not in ("http", "https"):
            raise refused(req, fp, code, headers, "not a web address")
        if source.scheme.lower() == "https" and target.scheme.lower() == "http":
            raise refused(req, fp, code, headers, "from https back to http")
        host = (target.hostname or "").lower()
        if host in ("metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.azure.internal"):
            raise refused(req, fp, code, headers, "the metadata service of a cloud provider")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and (ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
            raise refused(req, fp, code, headers, "that address is not allowed")
        new = original(self, req, fp, code, msg, headers, newurl)
        if new is not None and (target.hostname or "").lower() != (source.hostname or "").lower():
            for store in (new.headers, new.unredirected_hdrs):
                for name in [k for k in store if k.lower() in secret_headers]:
                    del store[name]
        return new

    urllib.request.HTTPRedirectHandler.redirect_request = redirect_request


def _load(plugin_dir: Path, builtin: bool):
    sys.path.insert(0, str(plugin_dir))        # nothing is built in any more: every plugin is loaded from its own folder
    spec = importlib.util.spec_from_file_location("netlens_user_plugin", plugin_dir / "plugin.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["netlens_user_plugin"] = module      # a @dataclass in the plugin looks its own module up here
    spec.loader.exec_module(module)
    return module


def main() -> int:
    out = sys.stdout
    sys.stdout = sys.stderr  # whatever the plugin prints must not corrupt the result line
    _guard_redirects()
    try:
        plugin_dir, mode, action = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
        request = json.loads(sys.stdin.read() or "{}")
        config = request.get("config", {})
        payload_in = request.get("payload")
        module = _load(plugin_dir, mode == "builtin")
        function = getattr(module, action, None)
        if not callable(function):
            raise RuntimeError(f"the plugin has no {action}(config) function")
        result = function(config) if payload_in is None else function(config, payload_in)
        payload = {"ok": True, "result": result}
    except BaseException as exc:  # noqa: BLE001 - everything the plugin raises is reported, not crashed on
        payload = {
            "ok": False,
            "error": (str(exc) or exc.__class__.__name__)[:500],
            "auth_failed": bool(getattr(exc, "auth_failed", False)),
        }
    try:
        text = json.dumps(payload)
    except (TypeError, ValueError) as exc:
        text = json.dumps({"ok": False, "error": f"the plugin returned data that is not JSON: {exc}", "auth_failed": False})
    out.write(text + "\n")
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
