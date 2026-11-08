"""Every plugin that ships with Netlens talks to its device through netlens_http: no own certificate switch, no own HTTP client, no unlimited read."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugin-index" / "tools"))

import static_scan  # noqa: E402


def _plugins():
    return sorted(p for p in (ROOT / "plugins").iterdir() if (p / "plugin.py").exists())


def test_no_plugin_makes_its_own_http_or_tls_decisions():
    problems = []
    for folder in _plugins():
        source = (folder / "plugin.py").read_text()
        for flag in static_scan.scan_source(source, f"{folder.name}/plugin.py"):
            if flag.rule in static_scan.NETWORK_RULES:
                problems.append(str(flag))
    assert not problems, "use netlens_http (app/plugins/lib):\n" + "\n".join(problems)
