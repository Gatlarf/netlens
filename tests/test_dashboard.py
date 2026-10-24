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
        plugins=[{"id": "docker", "enabled": True, "ok": False, "failing": True, "error": "refused"}],
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
    for route in ("dashboard", "map", "devices", "hierarchy", "uptime", "services", "stats", "scans", "insights", "remediation", "settings"):
        assert f'data-route="{route}"' in index, route
    assert index.count('class="side-group') == 6                       # the side menu: start pages, Network, Monitoring, Analysis, Automation, Configuration
    assert 'class="side-group admin-only"' in index                    # Automation and Configuration are for administrators
    assert 'data-route="overview"' in index and '"#/overview": "overview"' in app_js
    # the coffee link stays reachable on a small screen: it is in the account menu
    assert index.count("buymeacoffee.com") == 2


def test_top_bar_group_class_does_not_clash_with_the_settings_menu():
    """The Settings side menu has its own `.nav-group` headings; the main side menu's groups use another class, or
    the nav highlight code throws on every Settings route change and the menu stops working."""
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'class="menu-wrap nav-group"' not in index
    for name in ("app.js", "topbar.js"):
        assert 'querySelectorAll(".nav-group")' not in (STATIC / "js" / name).read_text(encoding="utf-8")


# ---- the layout is kept per user on the server ----
NONE = {"order": None, "custom": []}
def test_every_user_keeps_their_own_layout_and_a_viewer_may_arrange_theirs(tmp_path):
    from tests.test_users import ADMIN, make, sign_in

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        make(c, "alice", "admin")
        make(c, "vera", "viewer")
        alice, vera = sign_in(app, "alice"), sign_in(app, "vera")
        assert alice.get("/api/dashboard/layout").json() == NONE and vera.get("/api/dashboard/layout").json() == NONE
        assert alice.put("/api/dashboard/layout", json={"order": ["uptime", "devices", "uptime"]}).json() == {"order": ["uptime", "devices"], "custom": []}    # no duplicates
        assert vera.put("/api/dashboard/layout", json={"order": ["events"]}).status_code == 200                                                  # a viewer arranges their own
        # another browser or device of the same user sees the same layout; other users see theirs
        assert sign_in(app, "alice").get("/api/dashboard/layout").json() == {"order": ["uptime", "devices"], "custom": []}
        assert vera.get("/api/dashboard/layout").json() == {"order": ["events"], "custom": []}
        assert c.get("/api/dashboard/layout", headers=ADMIN).json() == NONE                                                           # the access token has its own
        assert vera.delete("/api/dashboard/layout").json() == NONE and vera.get("/api/dashboard/layout").json() == NONE
        assert alice.get("/api/dashboard/layout").json()["order"] == ["uptime", "devices"]
        # a viewer still cannot change anything else
        assert vera.put("/api/map-settings", json={"domain_suffix": "x"}).status_code == 403


@pytest.mark.parametrize("order", [["Bad Id"], [""], ["x" * 81], [1], [f"c{i}" for i in range(101)]])
def test_layout_validation(tmp_path, order):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        assert c.put("/api/dashboard/layout", json={"order": order}).status_code == 422


# ---- cards of your own ----
def _put(c, order, custom):
    return c.put("/api/dashboard/layout", json={"order": order, "custom": custom})


VALUE = {"id": "c-abc123", "type": "value", "title": "Line speed", "source": "speed.down_mbps", "format": "mbps", "display": "gauge", "unit": "", "decimals": 0,
         "direction": "below", "warn": 300, "bad": 150, "min": 0, "max": 1000, "href": "#/speedtest"}


@pytest.fixture
def admin(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        yield c


def test_cards_of_your_own_are_saved_with_the_layout(admin):
    cards = [VALUE, {"id": "c-dev001", "type": "device", "title": "", "device_id": 3}, {"id": "c-grp001", "type": "group", "group": "Cameras"},
             {"id": "c-svc001", "type": "service", "check_id": 2},
             {"id": "c-note01", "type": "notes", "title": "Links", "text": "Hello\nworld", "links": [{"label": "Grafana", "url": "https://grafana.example.net"}, {"label": "Map", "url": "#/map"}]}]
    saved = _put(admin, ["uptime", "c-abc123", "c-note01", "c-ghost1"], cards).json()
    assert saved["order"] == ["uptime", "c-abc123", "c-note01"]                    # a card of your own that does not exist is dropped
    assert [c["id"] for c in saved["custom"]] == [c["id"] for c in cards] and saved["custom"][0]["warn"] == 300
    assert admin.get("/api/dashboard/layout").json() == saved
    assert admin.delete("/api/dashboard/layout").json() == {"order": None, "custom": []}


@pytest.mark.parametrize("card", [
    {**VALUE, "source": "a b"}, {**VALUE, "source": "x" * 130}, {**VALUE, "source": "../../etc"}, {**VALUE, "format": "html"}, {**VALUE, "display": "iframe"}, {**VALUE, "warn": "red"},
    {**VALUE, "href": "https://evil.example"}, {**VALUE, "href": "javascript:alert(1)"}, {**VALUE, "decimals": 9}, {**VALUE, "id": "abc"},
    {"id": "c-dev001", "type": "device", "device_id": 0}, {"id": "c-dev001", "type": "device", "device_id": True}, {"id": "c-grp001", "type": "group", "group": ""},
    {"id": "c-note01", "type": "notes", "text": ""}, {"id": "c-note01", "type": "notes", "text": "x" * 2001},
    {"id": "c-note01", "type": "notes", "text": "x", "links": [{"label": "bad", "url": "javascript:alert(1)"}]},
    {"id": "c-note01", "type": "notes", "text": "x", "links": [{"label": "bad", "url": "data:text/html,<script>"}]},
    {"id": "c-note01", "type": "notes", "text": "x", "links": [{"label": "l", "url": "https://a.example"}] * 9},
    {"id": "c-x0000", "type": "script", "code": "alert(1)"},
])
def test_cards_of_your_own_are_checked(admin, card):
    assert _put(admin, [], [card]).status_code == 422


def test_unknown_fields_of_a_card_are_dropped(admin):
    saved = _put(admin, ["c-abc123"], [{**VALUE, "html": "<script>alert(1)</script>", "onclick": "x"}]).json()
    assert "html" not in saved["custom"][0] and "onclick" not in saved["custom"][0]


def test_at_most_forty_cards_of_your_own(admin):
    many = [{"id": f"c-n{i:04d}", "type": "notes", "text": "x"} for i in range(41)]
    assert _put(admin, [], many).status_code == 422 and _put(admin, [], many[:40]).status_code == 200


# ---- cards from plugins ----
def test_dashboard_has_the_extra_data_custom_cards_read(demo):
    data = demo.get("/api/dashboard").json()
    assert data["service_checks"] and {"id", "name", "state"} <= data["service_checks"][0].keys()
    first = data["summary"]["device_list"][0]["id"]
    assert str(first) in data["devices_uptime"] or first in data["devices_uptime"]
    cards = {(c["plugin"], c["id"]): c for c in data["plugin_cards"]}
    assert ("proxmox", "status") in cards and ("proxmox", "guests") in cards and ("docker", "status") in cards
    guests = {r["label"]: r for r in cards[("proxmox", "guests")]["rows"]}
    assert guests["Running"]["value"] > 0 and guests["Virtual machines"]["value"] > 0


def test_plugin_cards_are_validated():
    from app.plugin_cards import validate_cards
    from app.plugins.contract import ContractError

    ok = [{"id": "g", "title": "Guests", "rows": [{"label": "Running", "count": "guests", "where": {"status": ["running"]}}, {"label": "Last sync", "value": "status.ts"}]}]
    assert validate_cards(ok)[0]["rows"][0]["where"] == {"status": ["running"]} and validate_cards(None) == []
    for bad in ([{"id": "status", "title": "x", "rows": [{"label": "a", "value": "status.ok"}]}],                       # reserved
                [{"id": "g", "title": "x", "rows": [{"label": "a", "count": "devices"}]}],                           # unknown source
                [{"id": "g", "title": "x", "rows": [{"label": "a", "count": "guests", "where": {"name; DROP TABLE x": "1"}}]}],    # a column that is not allowed
                [{"id": "g", "title": "x", "rows": [{"label": "a", "count": "guests", "value": "status.ok"}]}],       # both
                [{"id": "g", "title": "x", "rows": [{"label": "a", "value": "settings.password"}]}],
                [{"id": "g", "title": "x", "href": "https://evil.example", "rows": [{"label": "a", "value": "status.ok"}]}],
                [{"id": "g", "title": "x", "rows": []}]):
        with pytest.raises(ContractError):
            validate_cards(bad)


# ---- the dashboard an administrator sets for everybody ----
def test_administrator_default_dashboard(tmp_path):
    from tests.test_users import make, sign_in

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        make(c, "alice", "admin")
        make(c, "vera", "viewer")
        alice, vera = sign_in(app, "alice"), sign_in(app, "vera")
        assert vera.get("/api/dashboard/default").json() == NONE
        note = {"id": "c-abc123", "type": "notes", "title": "Links", "text": "Hello", "links": []}
        assert alice.put("/api/dashboard/default", json={"order": ["uptime", "c-abc123", "c-gone99"], "custom": [note]}).json() == {"order": ["uptime", "c-abc123"], "custom": [note]}
        # everybody can read it, only an administrator can change or remove it
        assert vera.get("/api/dashboard/default").json()["order"] == ["uptime", "c-abc123"]
        assert vera.put("/api/dashboard/default", json={"order": ["events"]}).status_code == 403
        assert vera.delete("/api/dashboard/default").status_code == 403
        assert alice.put("/api/dashboard/default", json={"order": ["Bad Id"]}).status_code == 422
        # a user's own layout is separate and untouched
        assert vera.get("/api/dashboard/layout").json() == NONE
        assert alice.delete("/api/dashboard/default").json() == NONE and vera.get("/api/dashboard/default").json() == NONE


def test_default_dashboard_is_in_the_page_and_in_the_demo_guard(demo):
    text = (STATIC / "js" / "pages" / "dashboard.js").read_text(encoding="utf-8")
    assert "/api/dashboard/default" in text and "Use as default for everyone" in text
    assert demo.put("/api/dashboard/default", json={"order": ["uptime"]}).status_code in (403, 405)       # nobody changes the demo


@pytest.mark.parametrize("plugin", ["docker", "npm", "truenas", "hyperv"])
def test_every_plugin_in_the_repository_declares_valid_dashboard_cards(plugin):
    import json

    from app import plugin_cards

    manifest = json.loads((Path(__file__).resolve().parent.parent / "plugins" / plugin / "plugin.json").read_text())
    cards = plugin_cards.validate_cards(manifest["dashboard"])
    assert cards and all(card["rows"] for card in cards)


def test_attention_separates_core_and_other_devices():
    s = _summary_stub(devices={"flapping": 3, "unknown": 0}, core={"devices": 4, "flapping": 1})
    texts = [(i["level"], i["text"]) for i in dashboard._attention(s, [], 0, [], [{"id": 7, "name": "nas"}])]
    assert ("bad", "nas should always be online but is not answering") in texts
    assert ("warn", "1 always-on device keep going up and down") in texts
    assert ("info", "2 other devices keep going up and down") in texts
    # nothing marked: all flapping devices stay a warning, as before
    plain = dashboard._attention(_summary_stub(devices={"flapping": 2, "unknown": 0}), [], 0, [])
    assert plain == [{"level": "warn", "text": "2 other devices keep going up and down", "href": "#/uptime"}]


def test_shared_cards_are_available_to_every_user(tmp_path):
    from tests.test_users import make, sign_in

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        make(c, "vera", "viewer")
        vera = sign_in(app, "vera")
        assert vera.get("/api/dashboard/shared").json() == {"cards": []}
        assert vera.put("/api/dashboard/shared", json={"cards": [VALUE]}).status_code == 403            # only an administrator shares
        assert c.put("/api/dashboard/shared", json={"cards": [VALUE, {"id": "c-bad", "type": "nope"}]}).status_code == 422
        saved = c.put("/api/dashboard/shared", json={"cards": [VALUE]}).json()["cards"]
        assert [x["id"] for x in saved] == [VALUE["id"]]
        assert [x["id"] for x in vera.get("/api/dashboard/shared").json()["cards"]] == [VALUE["id"]]
        # a user may put a shared card on their own dashboard without having made it
        mine = vera.put("/api/dashboard/layout", json={"order": ["uptime", VALUE["id"]], "custom": []}).json()
        assert mine["order"] == ["uptime", VALUE["id"]]
        # a card that is neither theirs nor shared is still dropped
        assert vera.put("/api/dashboard/layout", json={"order": ["uptime", "c-ghost1"], "custom": []}).json()["order"] == ["uptime"]
        # unshared: it silently leaves the layouts when they are saved again
        c.put("/api/dashboard/shared", json={"cards": []})
        assert vera.put("/api/dashboard/layout", json={"order": ["uptime", VALUE["id"]], "custom": []}).json()["order"] == ["uptime"]


def test_storage_problems_lead_to_the_storage_page():
    s = _summary_stub()
    s["storage"] = {"unhealthy": 1, "failed_disks": 2, "pools_filling": 1, "alerts": 3}
    items = [i for i in dashboard._attention(s, [], 0, []) if "storage" in i["text"]]
    assert len(items) == 4 and all(i["href"] == "#/storage?focus=problems" for i in items)
