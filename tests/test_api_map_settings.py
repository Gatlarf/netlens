import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_default_is_free_and_choice_is_saved(client):
    assert client.get("/api/map-settings").json() == {"default_layout": "free", "layouts": ["free", "tree", "horizontal"], "domain_suffix": "", "show_guests": False}
    r = client.put("/api/map-settings", json={"default_layout": "horizontal"})
    assert r.status_code == 200 and r.json()["default_layout"] == "horizontal"
    assert client.get("/api/map-settings").json()["default_layout"] == "horizontal"


@pytest.mark.parametrize("body", [{}, {"default_layout": "circle"}, {"default_layout": None}])
def test_invalid_layout_rejected(client, body):
    assert client.put("/api/map-settings", json=body).status_code == 422
    assert client.get("/api/map-settings").json()["default_layout"] == "free"


def test_requires_auth(client):
    assert client.get("/api/map-settings", headers={"Authorization": "Bearer no"}).status_code == 401
    assert client.put("/api/map-settings", json={"default_layout": "tree"}, headers={"Authorization": "Bearer no"}).status_code == 401


def test_corrupt_stored_value_falls_back(client, tmp_path):
    from app.db import connect, set_setting

    conn = connect(tmp_path / "t.db")
    set_setting(conn, "map_default_layout", "garbage")
    conn.close()
    assert client.get("/api/map-settings").json()["default_layout"] == "free"


def test_domain_suffix_is_cleaned_saved_and_independent_of_layout(client):
    r = client.put("/api/map-settings", json={"domain_suffix": "  .Home.CodeShrimp.com. "})
    assert r.status_code == 200 and r.json()["domain_suffix"] == "home.codeshrimp.com"
    assert r.json()["default_layout"] == "free"
    client.put("/api/map-settings", json={"default_layout": "tree"})
    assert client.get("/api/map-settings").json()["domain_suffix"] == "home.codeshrimp.com"
    assert client.put("/api/map-settings", json={"domain_suffix": ""}).json()["domain_suffix"] == ""


@pytest.mark.parametrize("value", ["bad suffix", "a..b", "-x.com", "x_y.com", "a" * 300])
def test_bad_domain_suffix_rejected(client, value):
    assert client.put("/api/map-settings", json={"domain_suffix": value}).status_code == 422


def test_containers_on_the_map_are_an_option(tmp_path):
    import json

    from app.db import connect, get_or_create_device

    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer t"}) as c:
        conn = connect(path)
        host = get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.5")
        own = get_or_create_device(conn, "aa:00:00:00:00:02", "10.0.0.6")
        for gid, name, kind, status, device in (("h/web", "web", "container", "running", None), ("h/off", "off", "container", "exited", None),
                                                ("h/own", "own", "container", "running", own), ("pve/100", "vm", "qemu", "running", None),
                                                ("h/sick", "sick", "container", "running", None), ("h/app", "app", "app", "running", None)):
            conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated, details, device_id, host_device_id) VALUES ('docker', ?, ?, ?, 'h', ?, 'now', ?, ?, ?)",
                         (gid, name, kind, status, json.dumps({"health": "unhealthy", "image": "x:1"}) if name == "sick" else "{}", device, host))
        conn.commit()
        conn.close()
        assert c.get("/api/map-settings").json()["show_guests"] is False
        plain = c.get("/api/map").json()
        assert not any(n.get("virtual") for n in plain["nodes"])                       # off: the map is what it was
        shown = c.get("/api/map?guests=true").json()
        virtual = {n["label"]: n for n in shown["nodes"] if n.get("virtual")}
        assert set(virtual) == {"web", "sick", "app"}                                  # not stopped, not a device already, not a virtual machine
        assert virtual["sick"]["health"] == "unhealthy" and virtual["web"]["parent_id"] == host and virtual["web"]["online"] is True
        edge = next(e for e in shown["edges"] if e["to"] == virtual["web"]["id"])
        assert edge["from"] == host and edge["kind"] == "parent"
        assert c.put("/api/map-settings", json={"show_guests": True}).json()["show_guests"] is True
        assert c.put("/api/map-settings", json={"show_guests": False}).json()["show_guests"] is False
