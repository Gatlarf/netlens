"""Load the code of a plugin that lives in plugins/<id>/plugin.py (Proxmox and the ASUS router are ordinary plugins now)."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "plugins"


def load(plugin_id: str):
    name = f"plugin_under_test_{plugin_id}"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / plugin_id / "plugin.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
