import pytest
from fastapi.testclient import TestClient

from app import groups
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=ADMIN) as c:
        conn = connect(path)
        c.ids = [get_or_create_device(conn, f"aa:bb:cc:00:00:0{i}", f"10.0.0.{i}") for i in (1, 2, 3)]
        conn.close()
        c.app_ = app
        c.path = path
        yield c


def test_group_crud_and_defaults(client):
    r = client.post("/api/groups", json={"name": "Living room"})
    assert r.status_code == 201
    g = r.json()["groups"][0]
    assert g["name"] == "Living room" and g["color"].startswith("#") and g["count"] == 0
    client.post("/api/groups", json={"name": "Garage", "color": "#ABCDEF"})
    assert {x["name"]: x["color"] for x in client.get("/api/groups").json()["groups"]}["Garage"] == "#abcdef"
    assert client.post("/api/groups", json={"name": "living ROOM"}).status_code == 409  # names are unique, case-insensitively
    for bad in ({"name": ""}, {"name": "x" * 41}, {"name": "ok", "color": "red"}, {"name": "ok", "color": "#12"}):
        assert client.post("/api/groups", json=bad).status_code == 422
    gid = g["id"]
    r = client.patch(f"/api/groups/{gid}", json={"name": "Lounge", "color": "#112233"})
    assert r.status_code == 200 and {x["name"] for x in r.json()["groups"]} == {"Lounge", "Garage"}
    assert client.patch(f"/api/groups/{gid}", json={"name": "Garage"}).status_code == 409
    assert client.patch("/api/groups/999", json={"name": "x"}).status_code == 404
    assert client.delete(f"/api/groups/{gid}").status_code == 200 and client.delete(f"/api/groups/{gid}").status_code == 404


def test_assigning_a_device_shows_in_list_detail_and_map(client):
    gid = client.post("/api/groups", json={"name": "Office", "color": "#16a34a"}).json()["id"]
    d = client.ids[0]
    r = client.patch(f"/api/devices/{d}", json={"group_id": gid})
    assert r.status_code == 200 and r.json()["group_id"] == gid and r.json()["group"] == "Office" and r.json()["group_color"] == "#16a34a"
    row = next(x for x in client.get("/api/devices").json() if x["id"] == d)
    assert row["group"] == "Office"
    assert next(x for x in client.get("/api/devices").json() if x["id"] == client.ids[1])["group"] is None
    node = next(n for n in client.get("/api/map").json()["nodes"] if n["id"] == d)
    assert node["group"] == "Office" and node["group_color"] == "#16a34a"
    assert next(x for x in client.get("/api/stats/summary").json()["device_list"] if x["id"] == d)["group"] == "Office"
    assert client.get("/api/groups").json()["groups"][0]["count"] == 1
    assert client.patch(f"/api/devices/{d}", json={"group_id": 999}).status_code == 422
    assert client.patch(f"/api/devices/{d}", json={"group_id": None}).json()["group"] is None


def test_deleting_a_group_ungroups_its_devices(client):
    gid = client.post("/api/groups", json={"name": "Temp"}).json()["id"]
    client.post("/api/devices/group", json={"ids": client.ids, "group_id": gid})
    client.delete(f"/api/groups/{gid}")
    assert all(x["group_id"] is None and x["group"] is None for x in client.get("/api/devices").json())


def test_bulk_assign(client):
    gid = client.post("/api/groups", json={"name": "Kids"}).json()["id"]
    assert client.post("/api/devices/group", json={"ids": client.ids[:2], "group_id": gid}).json() == {"changed": 2}
    assert [x["group"] for x in client.get("/api/devices").json()].count("Kids") == 2
    assert client.post("/api/devices/group", json={"ids": client.ids[:1], "group_id": None}).json() == {"changed": 1}
    assert client.post("/api/devices/group", json={"group_id": gid}).json() == {"changed": 3}  # no ids: everything
    assert client.post("/api/devices/group", json={"ids": [1], "group_id": 999}).status_code == 422


def test_viewers_read_groups_but_change_nothing(client):
    client.post("/api/groups", json={"name": "Hall"})
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    vera = TestClient(client.app_)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.get("/api/groups").status_code == 200
    assert vera.post("/api/groups", json={"name": "x"}).status_code == 403
    assert vera.post("/api/devices/group", json={"group_id": None}).status_code == 403
    assert vera.get("/api/devices").json()[0]["group"] is None


def test_migration_adds_the_column_to_an_old_database(tmp_path):
    conn = connect(tmp_path / "old.db")
    init_db(conn)
    conn.execute("DROP TABLE device_groups")
    conn.execute("ALTER TABLE devices DROP COLUMN group_id")
    conn.execute("UPDATE schema_version SET version = 11")
    conn.commit()
    init_db(conn)
    assert groups.list_groups(conn) == []
    assert conn.execute("SELECT group_id FROM devices").fetchall() == []
