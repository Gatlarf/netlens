import pytest
from fastapi.testclient import TestClient

from app import licence, shares
from app.config import load_settings
from app.db import add_event, connect, get_or_create_device
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture(autouse=True)
def licensed(monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture
def env(tmp_path):
    shares._cache.clear()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        conn = connect(path)
        ids = {}
        for n, (mac, ip, name) in enumerate([("aa:bb:cc:00:00:01", "10.0.0.1", "Router"), ("aa:bb:cc:00:00:02", "10.0.0.2", "Camera"), ("aa:bb:cc:00:00:03", "10.0.0.3", "Laptop")]):
            ids[name] = get_or_create_device(conn, mac, ip)
            conn.execute("UPDATE devices SET custom_name = ?, vendor = 'Acme', online = ? WHERE id = ?", (name, 1 if n != 1 else 0, ids[name]))
        conn.execute("INSERT INTO device_groups (name, color) VALUES ('Home', '#111111'), ('Office', '#222222')")
        groups = {r["name"]: r["id"] for r in conn.execute("SELECT id, name FROM device_groups")}
        conn.execute("UPDATE devices SET group_id = ? WHERE id IN (?, ?)", (groups["Home"], ids["Router"], ids["Camera"]))
        conn.execute("UPDATE devices SET group_id = ? WHERE id = ?", (groups["Office"], ids["Laptop"]))
        conn.execute("INSERT INTO service_checks (name, kind, host, port, enabled, device_id, created) VALUES ('Web', 'tcp', '10.0.0.1', 80, 1, ?, 't'), ('Printer', 'tcp', '10.0.0.3', 9100, 1, ?, 't')", (ids["Router"], ids["Laptop"]))
        add_event(conn, "device_offline", "10.0.0.2 went away", device_id=ids["Camera"])
        add_event(conn, "port_opened", "10.0.0.2:22 opened", device_id=ids["Camera"])
        conn.commit()
        conn.close()
        yield c, app, path, ids, groups


def new(c, **kw):
    r = c.post("/api/shares", json={"name": "Family", **kw}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["links"][0]


def data(app, link, **headers):
    return TestClient(app).get(f"/share-api/{link['token']}", headers=headers)


def test_sections_decide_what_is_sent(env):
    c, app, *_ = env
    link = new(c, options={"sections": ["services"]})
    d = data(app, link).json()
    assert d["sections"] == ["services"] and "devices" not in d and "devices_total" not in d and d["services"]
    assert link["mode"] == "status"
    assert new(c, options={"sections": ["map"]})["mode"] == "view"


def test_old_links_keep_their_preset(env):
    c, app, path, *_ = env
    link = new(c)
    conn = connect(path)
    conn.execute("UPDATE share_links SET options = '{}'")        # a link made before options existed
    conn.commit()
    conn.close()
    d = data(app, link).json()
    assert d["sections"] == ["summary", "services", "map", "devices"] and len(d["devices"]) == 3


def test_group_scope_limits_devices_counts_services_and_events(env):
    c, app, _, ids, groups = env
    link = new(c, options={"sections": ["summary", "services", "devices", "events"], "group_ids": [groups["Home"]]})
    d = data(app, link).json()
    assert {x["name"] for x in d["devices"]} == {"Router", "Camera"}
    assert (d["devices_total"], d["devices_online"], d["devices_offline"]) == (2, 1, 1)
    assert [s["name"] for s in d["services"]] == ["Web"]
    assert [e["text"] for e in d["events"]] == ["Camera went offline"]
    other = new(c, options={"sections": ["devices", "events"], "group_ids": [groups["Office"]]})
    assert data(app, other).json()["events"] == []


def test_events_never_carry_details(env):
    c, app, *_ = env
    link = new(c, options={"sections": ["events"]})
    text = str(data(app, link).json())
    assert "10.0.0" not in text and "opened" not in text and "went offline" in text


def test_chosen_services_and_hidden_names(env):
    c, app, path, ids, _ = env
    conn = connect(path)
    printer = conn.execute("SELECT id FROM service_checks WHERE name = 'Printer'").fetchone()["id"]
    conn.close()
    link = new(c, options={"sections": ["services", "devices"], "service_ids": [printer], "generic_names": True})
    d = data(app, link).json()
    assert [s["name"] for s in d["services"]] == ["Printer"]
    assert {x["name"] for x in d["devices"]} == {f"Device {i}" for i in ids.values()}


def test_device_fields_are_chosen(env):
    c, app, *_ = env
    link = new(c, options={"sections": ["devices"], "fields": ["vendor"]})
    row = data(app, link).json()["devices"][0]
    assert row["vendor"] == "Acme" and "type" not in row and "last_seen" not in row


def test_uptime_section(env):
    c, app, *_ = env
    d = data(app, new(c, options={"sections": ["uptime"], "uptime_days": 30})).json()
    assert d["uptime"]["days"] == 30 and len(d["uptime"]["daily"]) == 30


def test_message_title_and_look(env):
    c, app, *_ = env
    link = new(c, options={"title": "Our network", "message": "Back on Tuesday", "theme": "dark", "brand": "Acme IT", "accent": "#112233"})
    d = data(app, link).json()
    assert (d["name"], d["message"], d["theme"], d["brand"], d["accent"]) == ("Our network", "Back on Tuesday", "dark", "Acme IT", "#112233")


@pytest.mark.parametrize("options", [{"sections": []}, {"sections": ["secrets"]}, {"group_ids": [999]}, {"service_ids": [999]}, {"accent": "red"}, {"theme": "pink"},
                                     {"event_limit": 0}, {"uptime_days": 5}, {"fields": ["mac"]}])
def test_bad_options_rejected(env, options):
    c, *_ = env
    assert c.post("/api/shares", json={"name": "x", "options": options}, headers=ADMIN).status_code == 422


def test_pin_locks_the_data_until_unlocked(env):
    c, app, *_ = env
    link = new(c, pin="1234")
    assert link["has_pin"] is True
    anon = TestClient(app)
    locked = anon.get(f"/share-api/{link['token']}")
    assert locked.status_code == 401 and locked.json()["locked"] is True and "devices" not in locked.json()
    assert anon.get(f"/share-api/{link['token']}", headers={"X-Share-Key": "guess"}).status_code == 401
    assert c.get("/api/shares", headers=ADMIN).json()["links"][0]["views"] == 0       # a locked visit is not a view
    assert anon.post(f"/share-api/{link['token']}/unlock", json={"pin": "0000"}).status_code == 403
    key = anon.post(f"/share-api/{link['token']}/unlock", json={"pin": "1234"}).json()["key"]
    assert anon.get(f"/share-api/{link['token']}", headers={"X-Share-Key": key}).status_code == 200
    assert "pin_hash" not in str(c.get("/api/shares", headers=ADMIN).json())


def test_wrong_pins_are_limited(env):
    c, app, *_ = env
    link = new(c, pin="1234")
    anon = TestClient(app)
    codes = [anon.post(f"/share-api/{link['token']}/unlock", json={"pin": str(n)}).status_code for n in range(7)]
    assert codes == [403] * 5 + [429] * 2
    assert anon.post(f"/share-api/{link['token']}/unlock", json={"pin": "1234"}).status_code == 429


def test_changing_pin_or_address_drops_old_keys(env):
    c, app, *_ = env
    link = new(c, pin="1234")
    anon = TestClient(app)
    key = anon.post(f"/share-api/{link['token']}/unlock", json={"pin": "1234"}).json()["key"]
    c.patch(f"/api/shares/{link['id']}", json={"pin": "5678"}, headers=ADMIN)
    assert anon.get(f"/share-api/{link['token']}", headers={"X-Share-Key": key}).status_code == 401
    c.patch(f"/api/shares/{link['id']}", json={"pin": ""}, headers=ADMIN)
    assert anon.get(f"/share-api/{link['token']}").status_code == 200


@pytest.mark.parametrize("pin", ["123", "x" * 65])
def test_pin_length(env, pin):
    c, *_ = env
    assert c.post("/api/shares", json={"name": "x", "pin": pin}, headers=ADMIN).status_code == 422


def test_edit_changes_options_and_keeps_the_rest(env):
    c, app, *_ = env
    link = new(c, show_ips=True, expires_days=7)
    res = c.patch(f"/api/shares/{link['id']}", json={"name": "Landlord", "options": {"sections": ["summary"]}}, headers=ADMIN)
    assert res.status_code == 200
    kept = res.json()["links"][0]
    assert kept["name"] == "Landlord" and kept["token"] == link["token"] and kept["show_ips"] is True and kept["expires"] == link["expires"]
    assert data(app, kept).json()["sections"] == ["summary"]
    c.patch(f"/api/shares/{link['id']}", json={"expires_days": None}, headers=ADMIN)
    assert c.get("/api/shares", headers=ADMIN).json()["links"][0]["expires"] is None
    assert c.patch("/api/shares/999", json={"name": "x"}, headers=ADMIN).status_code == 404
    assert c.patch(f"/api/shares/{link['id']}", json={"name": " "}, headers=ADMIN).status_code == 422


def test_new_address_revokes_the_old_one(env):
    c, app, *_ = env
    link = new(c)
    res = c.patch(f"/api/shares/{link['id']}", json={"new_token": True}, headers=ADMIN).json()["links"][0]
    assert res["token"] != link["token"]
    assert data(app, link).status_code == 404 and data(app, res).status_code == 200


def test_start_date(env):
    c, app, *_ = env
    link = new(c, valid_from="2999-01-01T00:00:00Z")
    assert link["waiting"] is True and data(app, link).status_code == 404
    c.patch(f"/api/shares/{link['id']}", json={"valid_from": None}, headers=ADMIN)
    assert data(app, link).status_code == 200
    assert c.post("/api/shares", json={"name": "x", "valid_from": "tomorrow"}, headers=ADMIN).status_code == 422


def test_scope_and_branding_need_a_licence_but_keep_working(env, monkeypatch):
    c, app, _, _, groups = env
    paid = {"group_ids": [groups["Home"]]}
    link = new(c, options=paid)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "sharing")
    assert c.get("/api/shares", headers=ADMIN).json()["sharing_allowed"] is False
    assert c.post("/api/shares", json={"name": "x", "options": paid}, headers=ADMIN).status_code == 402
    assert c.post("/api/shares", json={"name": "x", "options": {"brand": "Mine"}}, headers=ADMIN).status_code == 402
    assert c.post("/api/shares", json={"name": "x", "options": {"accent": "#112233"}}, headers=ADMIN).status_code == 402
    assert c.patch(f"/api/shares/{link['id']}", json={"options": {"group_ids": [groups["Office"]]}}, headers=ADMIN).status_code == 402
    assert c.patch(f"/api/shares/{link['id']}", json={"name": "Renamed", "options": {**paid, "sections": ["summary"]}}, headers=ADMIN).status_code == 200   # unchanged scope: fine
    assert len(data(app, link).json().get("devices", [])) == 0 and data(app, link).json()["devices_total"] == 2                                         # still scoped
    assert new(c, options={"sections": ["summary", "events", "uptime"], "message": "Hi", "theme": "dark"})                                              # the rest stays free
