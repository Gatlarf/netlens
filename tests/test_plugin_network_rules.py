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


def test_a_plugin_version_that_uses_the_helper_is_released_for_a_netlens_that_has_it():
    import json

    NEEDS = (0, 4, 366)
    wrong = []
    for folder in _plugins():
        if "netlens_http" not in (folder / "plugin.py").read_text():
            continue
        version = json.loads((folder / "plugin.json").read_text())["version"]
        entry = json.loads((ROOT / "plugin-index" / "plugins" / f"{folder.name}.json").read_text())
        release = next((r for r in entry["releases"] if r["version"] == version), None)
        if release is None or tuple(int(x) for x in release["min_netlens"].split(".")) < NEEDS:
            wrong.append(folder.name)
    assert not wrong, f"release missing or min_netlens below 0.4.366: {wrong}"
