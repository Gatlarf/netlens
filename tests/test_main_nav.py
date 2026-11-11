"""The page menu (static/js/mainnav.js) is a model of headings and tabs: it must stay in step with the routes of app.js and the optional pages of /api/features."""
import re
from pathlib import Path

from app.api.features import FEATURES

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
NAV = (JS / "mainnav.js").read_text()
APP = (JS / "app.js").read_text()

# pages that were seen to answer "this needs an administrator" for a read-only user
ADMIN_PAGES = {"dns", "network_health", "vulnerabilities", "backups", "storage", "smarthome", "insights", "remediation", "remote", "settings"}
NOT_IN_MENU = {"overview", "wizard", "hierarchy", "device", "login-user", "administrator"}


def items():
    return re.findall(r'\{ route: "([a-z_]+)", href: "([^"]+)", label: "[^"]+"([^}]*)\}', NAV)


def test_every_page_route_is_in_the_menu_or_knowingly_left_out():
    routes = set(re.findall(r':\s*"([a-z_]+)",?\s*$', APP[APP.index("const ROUTES = {"):APP.index("let currentCleanup")], re.M))
    listed = {route for route, _href, _rest in items()}
    assert sorted(routes - listed - NOT_IN_MENU) == [], "a page that is in no heading of the menu"


def test_an_optional_page_is_hidden_without_its_plugin():
    named = {route: re.search(r'feature: "([a-z_]+)"', rest) for route, _href, rest in items()}
    for feature in FEATURES:
        pages = [r for r, m in named.items() if m and m.group(1) == feature]
        assert pages, f"{feature} has no page in the menu"
    assert all(m.group(1) in FEATURES for m in named.values() if m)


def test_pages_that_need_an_administrator_are_marked_so():
    marked = {route for route, _href, rest in items() if "admin: true" in rest}
    assert ADMIN_PAGES <= marked, sorted(ADMIN_PAGES - marked)


def test_the_hud_gives_its_menu_up_after_a_while():
    assert "HUD_DELAY" in NAV and 'current === "hud"' in NAV and "side-peek" in NAV
