import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import dashboard
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


def _summary_stub(**over):
    s = {
        "services": {"total": 0, "up": 0, "down": 0}, "plugins": [], "scans": {"last": None, "last_ok_age_s": 60}, "backup": {"last_ok": True},
        "containers": {"unhealthy": 0, "restarting": 0}, "sites": {"down": 0}, "devices": {"flapping": 0, "unknown": 0},
        "dns": {"conflicts": 0}, "netchecks": {"untrusted": 0}, "update": {"available": False, "latest": None, "plugin_updates": 0},
    }
    s.update(over)
    return s


def test_nothing_wrong_means_an_empty_attention_list():
    assert dashboard._attention(_summary_stub(), [], 0, []) == []


def test_attention_lists_problems_worst_first_with_a_link_each():
    s = _summary_stub(
        devices={"flapping": 2, "unknown": 1}, update={"available": True, "latest": "9.9", "plugin_updates": 0},
        plugins=[{"id": "docker", "enabled": True, "ok": False, "error": "refused"}],
    )
    items = dashboard._attention(s, [{"name": "a.example", "days": 3}], 4, ["nas"])
    levels = [i["level"] for i in items]
    assert levels == sorted(levels, key=["bad", "warn", "info"].index)
    texts = " | ".join(i["text"] for i in items)
    for part in ("service", "nas", "docker", "refused", "a.example", "3 days", "up and down", "failed sign-ins", "9.9"):
        assert part in texts, part
    assert all(i["href"].startswith("#/") for i in items)


@pytest.fixture
def demo(tmp_path):
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_DEMO": "on"})
    with TestClient(create_app(settings)) as c:
        assert c.post("/api/login", json={"username": "demo", "password": "netlens-demo"}).status_code == 200
        yield c


def test_dashboard_endpoint_has_everything_the_cards_use(demo):
    data = demo.get("/api/dashboard").json()
    assert {"summary", "attention", "events", "worst", "trend", "new_devices", "certificates", "services_down", "login_failed_24h", "maintenance", "speed"} <= data.keys()
    assert data["summary"]["devices"]["total"] == 46
    assert data["events"] and data["trend"] and data["certificates"]
    assert all({"level", "text", "href"} <= a.keys() for a in data["attention"])


def test_dashboard_works_on_an_empty_install(tmp_path):
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path)})
    conn = connect(tmp_path / "x.db")
    init_db(conn)
    from app.stats import summary

    data = dashboard.build(conn, summary(conn))
    assert data["events"] == [] and data["worst"] == [] and data["attention"] == []
    assert settings is not None


def test_every_card_id_is_unique_and_the_default_cards_exist():
    text = (STATIC / "js" / "pages" / "dashboard.js").read_text(encoding="utf-8")
    ids = re.findall(r'^\s*\{ id: "([a-z]+)"', text, re.M)
    assert len(ids) == len(set(ids)) >= 20
    assert {"devices", "uptime", "attention", "events", "minimap"} <= set(ids)


def test_start_page_and_menu_groups_are_wired():
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    assert '"#/": "dashboard"' in app_js
    for route in ("dashboard", "map", "devices", "hierarchy", "uptime", "services", "stats", "scans", "settings"):
        assert f'data-route="{route}"' in index, route
    assert index.count('class="menu-wrap topnav-group"') == 2
    # the coffee link stays reachable on a small screen: it is in the account menu
    assert index.count("buymeacoffee.com") == 2


def test_top_bar_group_class_does_not_clash_with_the_settings_menu():
    """The Settings side menu has its own `.nav-group` headings; the top bar's groups use another class, or
    the nav highlight code throws on every Settings route change and the menu stops working."""
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'class="menu-wrap nav-group"' not in index
    for name in ("app.js", "topbar.js"):
        assert 'querySelectorAll(".nav-group")' not in (STATIC / "js" / name).read_text(encoding="utf-8")
