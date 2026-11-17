"""Saved views of the Devices and Events tables, and the extra device columns they can show."""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import tableviews, tsdb
from app.config import load_settings
from app.db import connect
from app.main import create_app

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"


@pytest.fixture
def client(tmp_path):
    tsdb.forget_all()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        yield c, tmp_path
    tsdb.forget_all()


def test_a_view_only_asks_for_columns_that_exist_and_keeps_the_locked_ones_first():
    v = tableviews.clean_view("devices", {"name": "  Wi-Fi   clients ", "columns": ["wifi_band", "bogus", "mac", "wifi_band", "name"], "widths": {"mac": 300, "bogus": 90, "vendor": 5, "name": "wide"},
                                          "sort": {"key": "wifi_signal", "dir": "desc"}, "filters": {"type": "ap", "group": "", "evil": "x", "q": "x" * 200}})
    assert v["name"] == "Wi-Fi clients" and v["columns"] == ["status", "name", "wifi_band", "mac"]          # locked first, a column once, unknown ones gone
    assert v["widths"] == {"mac": 300} and v["sort"] == {"key": "wifi_signal", "dir": "desc"} and v["filters"] == {"type": "ap"}
    assert re.fullmatch(r"[a-z0-9]{3,16}", v["id"])
    with pytest.raises(ValueError):
        tableviews.clean_view("devices", {"columns": ["name"]})                                                   # a view needs a name
    with pytest.raises(ValueError):
        tableviews.clean_view("nothing", {"name": "x"})
    assert tableviews.clean_view("devices", {"name": "x", "sort": {"key": "bogus"}})["sort"] is None


def test_my_views_are_kept_per_user_and_shared_ones_by_an_administrator(client):
    c, _tmp = client
    first = c.get("/api/me/table-views/devices").json()
    assert first["views"] == [] and first["shared"] == [] and "wifi_band" in first["columns"] and first["locked"] == ["status", "name"]
    saved = c.put("/api/me/table-views/devices", json={"views": [{"name": "Access points", "columns": ["name", "wifi_band"], "filters": {"type": "ap"}}], "active": "builtin:network"}).json()
    vid = saved["views"][0]["id"]
    assert saved["active"] == "builtin:network" and saved["views"][0]["columns"] == ["status", "name", "wifi_band"]
    assert c.put("/api/me/table-views/devices", json={"views": saved["views"], "active": vid}).json()["active"] == vid
    assert c.put("/api/me/table-views/devices", json={"views": [], "active": "not a view!"}).status_code == 422
    assert c.put("/api/me/table-views/devices", json={"views": [{"columns": []}], "active": None}).status_code == 422
    assert c.get("/api/me/table-views/nothing").status_code == 404
    shared = c.put("/api/table-views/devices/shared", json={"views": [{"name": "For everyone", "columns": ["name", "mac"]}]}).json()["shared"]
    assert shared[0]["name"] == "For everyone" and c.get("/api/me/table-views/devices").json()["shared"] == shared
    assert c.put("/api/me/table-views/devices", json={"views": [], "active": f"shared:{shared[0]['id']}"}).status_code == 200


def test_everybody_may_keep_views_but_only_an_administrator_may_share_them():
    from app import auth

    assert auth.ME_WRITABLE.match("/api/me/table-views/devices") and auth.ME_WRITABLE.match("/api/me/preferences")
    assert not auth.ME_WRITABLE.match("/api/table-views/devices/shared") and not auth.ME_WRITABLE.match("/api/me/table-views/../x")
    assert not auth.VIEWER_READABLE.match("/api/table-views/devices/shared")


def populate(path, n):
    conn = connect(path)
    for i in range(1, n + 1):
        conn.execute("INSERT INTO devices (id, primary_ip, mac, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, '2026-10-01T00:00:00Z', '2026-11-16T00:00:00Z')",
                     (i, f"10.0.0.{i}", f"aa:00:00:00:{i // 256:02x}:{i % 256:02x}", f"host{i}"))
        conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps, rx_mbps) VALUES (?, '2026-11-16T10:00:00Z', 'Hall AP', '5 GHz', -55, 400, 300)", (i,))
        conn.execute("INSERT INTO client_links (device_id, plugin_id, node_mac, node_name, port, medium, updated, source, node_device_id) VALUES (?, 'p', 'aa', 'Hall AP', 'wifi0', 'wifi', '2026-11-16T10:00:00Z', 'plugin', 1)", (i,)) if i > 1 else None
    conn.commit()
    conn.close()


def test_the_extra_columns_arrive_only_when_asked_for(client):
    c, tmp = client
    populate(tmp / "netlens.db", 6)
    plain = c.get("/api/devices").json()
    assert all("link" not in d and "wifi" not in d and "uptime_7d" not in d for d in plain)
    rich = {d["id"]: d for d in c.get("/api/devices?extra=link,wifi,uptime").json()}
    assert rich[2]["wifi"]["band"] == "5 GHz" and rich[2]["wifi"]["rssi"] == -55 and rich[2]["uptime_7d"] is None and rich[2]["rtt_24h"] is None   # no checks yet: nothing to say
    assert set(rich[2]["link"]) == {"parent_id", "parent", "port", "medium"}
    assert [k for k in c.get("/api/devices?extra=bogus").json()[0] if k in ("link", "wifi")] == []


def test_the_extra_columns_cost_the_same_number_of_statements_however_many_devices(tmp_path):
    import sqlite3
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    import dbbench

    counts = {}
    for name, n in (("small", 5), ("large", 60)):
        folder = tmp_path / name
        folder.mkdir()
        tsdb.forget_all()
        app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(folder)}), db_path=folder / "netlens.db")
        with TestClient(app) as c:
            pass
        populate(folder / "netlens.db", n)
        counted, real = dbbench.counting_connect()
        sqlite3.connect = counted
        try:
            app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(folder)}), db_path=folder / "netlens.db")
            with TestClient(app) as c:
                dbbench.state["delay"], dbbench.state["n"] = 0.0, 0
                assert c.get("/api/devices?extra=link,wifi,uptime", headers={"Authorization": "Bearer t"}).status_code == 200
                counts[name] = dbbench.state["n"]
        finally:
            sqlite3.connect = real
    assert counts["large"] - counts["small"] <= 2, counts


def test_the_column_lists_of_the_server_and_of_the_pages_are_the_same():
    text = (JS / "pages" / "devices_columns.js").read_text(encoding="utf-8")
    catalog = re.findall(r'\{\s*key: "([a-z0-9_]+)"', text.split("export const BUILTIN_VIEWS")[0])
    assert tuple(catalog) == tableviews.COLUMNS["devices"], set(catalog) ^ set(tableviews.COLUMNS["devices"])       # the same keys in the same order
    views = text.split("export const BUILTIN_VIEWS")[1]
    for columns in re.findall(r'columns: \[([^\]]*)\]', views):
        used = re.findall(r'"([a-z0-9_]+)"', columns)
        assert used[:2] == ["status", "name"] and set(used) <= set(catalog)                                          # a built-in view only names columns that exist
        assert len(used) == len(set(used))
    assert re.search(r'id: "standard"', views)


@pytest.mark.parametrize("table", ["services", "scans", "vulns", "audit", "speedtests", "smarthome"])
def test_the_other_tables_list_the_same_columns_on_the_server_and_in_the_pages(table):
    text = (JS / "tables" / f"{table}.js").read_text(encoding="utf-8")
    catalog = re.findall(r'\{\s*key: "([a-z0-9_]+)"', text.split("export const BUILTIN_VIEWS")[0])
    assert tuple(catalog) == tableviews.COLUMNS[table], set(catalog) ^ set(tableviews.COLUMNS[table])
    locked = tableviews.LOCKED[table]
    views = text.split("export const BUILTIN_VIEWS")[1]
    for columns in re.findall(r'columns: \[([^\]]*)\]', views):
        used = re.findall(r'"([a-z0-9_]+)"', columns)
        assert tuple(used[:len(locked)]) == locked and set(used) <= set(catalog) and len(used) == len(set(used))
    assert re.search(r'id: "standard"', views)
