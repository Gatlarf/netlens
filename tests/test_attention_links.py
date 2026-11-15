"""Every "needs attention" line leads somewhere that exists, and a page that takes a ?focus= / ?kind= / ?trusted= hint understands it."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "app"
JS = ROOT / "static" / "js"


def _routes() -> set[str]:
    return set(re.findall(r'"(#/[a-z-]*)":', (JS / "app.js").read_text()))


def _settings_keys() -> set[str]:
    return set(re.findall(r'key: "([a-z0-9_-]+)"', (JS / "pages" / "settings.js").read_text()))


def test_every_attention_link_has_a_page():
    source = (ROOT / "dashboard.py").read_text()
    routes, keys = _routes(), _settings_keys()
    links = set(re.findall(r'f?"(#/[^"]+)"', source))
    assert len(links) > 30
    for link in links:
        path = re.sub(r"\{[^}]*\}", "1", link.split("?")[0])
        if path.startswith("#/device/"):
            assert re.fullmatch(r"#/device/\d+(/[a-z]+(/[a-z-]+)?)?", path), link
        elif path.startswith("#/settings/"):
            key = path.split("/")[2]
            assert key in keys or key.startswith("plugin-"), link
        else:
            assert path in routes, link


def test_pages_understand_their_hints():
    for page, hint in [("stats", "focus="), ("devices", "trusted="), ("scans", "kind="), ("uptime", "focus="), ("storage", "focus="), ("backups", "focus=")]:
        assert hint in (JS / "pages" / f"{page}.js").read_text(), page
    assert "wantedCard" in (JS / "pages" / "device.js").read_text()
