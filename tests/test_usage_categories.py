"""Categories for the traffic statistics: what is stored, redirects for privacy, rewriting history, the API."""

import sqlite3

import pytest

from app import usagecat, usagecfg
from app.db import init_db
from app.plugins.contract import validate_output
from app.plugins.enrich import record_usage
from app.stats import _applications

NOW = "2026-10-22T12:00:00Z"
MAC = "02:00:00:00:00:01"


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (1, ?, '10.0.0.5', 'laptop', 1, 'x', 'x')", (MAC,))
    usagecfg.set_enabled(c, True)
    c.commit()
    return c


APPS = (("www.youtube.com", 10, 900), ("i.instagram.com", 1, 100), ("cdn.pornhub.com", 5, 400), ("odd.example.org", 2, 50), ("rr1.googlevideo.com", 3, 300))


def feed(conn, day="2026-10-22"):
    apps = [{"name": n, "tx_bytes": t, "rx_bytes": r} for n, t, r in APPS]
    data = validate_output("topology", {"nodes": [], "clients": [], "usage": [{"day": day, "applications": apps, "clients": [{"mac": MAC, "tx_bytes": 1, "rx_bytes": 1, "applications": apps}]}]})
    record_usage(conn, "asus", data, NOW)


def names(conn, table="app_usage"):
    return {r[0] for r in conn.execute(f"SELECT name FROM {table}")}


def test_the_catalogue_and_own_rules_decide_the_category(conn):
    p = usagecat.Policy(conn)
    assert p.category("www.YouTube.com") == "Streaming" and p.category("rr1.googlevideo.com") == "Streaming"
    assert p.category("i.instagram.com") == "Social media" and p.category("odd.example.org") == "Uncategorised"
    assert p.category("captive.portal") == "Uncategorised"          # no loose word fragments
    usagecat.add_rule(conn, "*.example.org", "Gaming")
    assert usagecat.Policy(conn).category("odd.example.org") == "Gaming" and usagecat.Policy(conn).category("example.org") == "Gaming"


def test_categories_only_never_stores_a_name(conn):
    usagecat.set_detail(conn, "categories")
    feed(conn)
    assert names(conn) == {"Streaming", "Social media", "Adult", "Uncategorised"}
    assert names(conn, "client_app_usage") == names(conn)
    got = _applications(conn, 7)
    assert got["detail"] == "categories" and {a["name"] for a in got["categories"]} == names(conn)
    assert next(a for a in got["applications"] if a["name"] == "Streaming")["rx"] == 1200       # two domains added together


def test_names_mode_groups_by_category_when_read(conn):
    usagecat.set_detail(conn, "names")
    feed(conn)
    assert "www.youtube.com" in names(conn)
    got = _applications(conn, 7)
    assert got["categories"][0]["name"] == "Streaming" and got["categories_total"] == 4


def test_a_redirect_hides_the_names_everywhere_and_rewrites_history(conn):
    usagecat.set_detail(conn, "names")
    feed(conn, "2026-10-21")
    assert "cdn.pornhub.com" in names(conn)
    usagecat.set_redirect(conn, "Adult", "Others")
    usagecat.set_redirect(conn, "Social media", "Others")
    feed(conn)
    for table in ("app_usage", "client_app_usage"):
        assert "cdn.pornhub.com" not in names(conn, table) and "i.instagram.com" not in names(conn, table) and "Others" in names(conn, table)
    dump = "\n".join(conn.iterdump())
    assert "pornhub" not in dump.split("usage_rules")[0].replace("INSERT INTO usage_redirects", "") and "instagram" not in dump
    got = _applications(conn, 7)
    others = next(a for a in got["categories"] if a["name"] == "Others")
    assert others["rx"] == 2 * (400 + 100)                           # both days, both categories, one label
    assert "Adult" not in {a["name"] for a in got["categories"]}


def test_a_rule_that_moves_a_name_into_a_redirected_category_rewrites_it(conn):
    usagecat.set_detail(conn, "names")
    feed(conn)
    usagecat.set_redirect(conn, "Gaming", "Others")
    usagecat.add_rule(conn, "odd.example.org", "Gaming")
    assert "odd.example.org" not in names(conn) and "Others" in names(conn)


def test_the_default_is_names_for_an_install_that_has_data_and_categories_for_a_new_one(conn):
    assert usagecat.detail(conn) == "categories"
    other = sqlite3.connect(":memory:")
    other.row_factory = sqlite3.Row
    init_db(other)
    other.execute("INSERT INTO app_usage (day, source, name, rx_bytes, tx_bytes, updated) VALUES ('2026-10-01', 'x', 'Netflix', 1, 1, 'x')")
    assert usagecat.detail(other) == "names"


def test_bad_input_is_refused():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_db(c)
    for call in (lambda: usagecat.add_rule(c, "*.", "Gaming"), lambda: usagecat.add_rule(c, "", "Gaming"), lambda: usagecat.set_redirect(c, "Adult", "x" * 60), lambda: usagecat.set_detail(c, "all")):
        with pytest.raises(ValueError):
            call()


def test_the_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect
    from app.main import create_app

    monkeypatch.setenv("NETLENS_TOKEN", "secret")
    monkeypatch.setenv("NETLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NETLENS_RANGES", "192.168.250.0/30")
    with TestClient(create_app(load_settings())) as c:
        auth = {"Authorization": "Bearer secret"}
        assert c.put("/api/usage", json={"enabled": True}, headers=auth).status_code == 200
        state = c.get("/api/usage", headers=auth).json()
        assert state["detail"] == "categories" and "Adult" in state["categories"]
        assert c.put("/api/usage/redirects/Adult", json={"label": "Others"}, headers=auth).json()["redirects"] == [{"category": "Adult", "label": "Others"}]
        assert c.put("/api/usage/redirects/Adult", json={"label": "x" * 80}, headers=auth).status_code == 422
        rule = c.post("/api/usage/rules", json={"pattern": "*.corp.example", "category": "Gaming"}, headers=auth).json()["rules"][0]
        assert c.delete(f"/api/usage/rules/{rule['id']}", headers=auth).json()["rules"] == []
        assert c.delete("/api/usage/rules/999", headers=auth).status_code == 422
        assert c.delete("/api/usage/redirects/Adult", headers=auth).json()["redirects"] == []
        assert c.put("/api/usage/detail", json={"detail": "names"}, headers=auth).json()["detail"] == "names"
        assert c.put("/api/usage/detail", json={"detail": "bogus"}, headers=auth).status_code == 422
        viewer = {"Authorization": "Bearer secret"}
        assert connect(tmp_path / "netlens.db").execute("SELECT COUNT(*) FROM audit_log WHERE path LIKE '/api/usage/%'").fetchone()[0] >= 5
