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


def _load(plugin_dir: Path, builtin: bool):
    if builtin:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        return importlib.import_module(f"app.plugins.builtin.{plugin_dir.name}.plugin")
    sys.path.insert(0, str(plugin_dir))
    spec = importlib.util.spec_from_file_location("netlens_user_plugin", plugin_dir / "plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    out = sys.stdout
    sys.stdout = sys.stderr  # whatever the plugin prints must not corrupt the result line
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
