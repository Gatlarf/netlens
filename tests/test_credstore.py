"""The credential store: private by default, shared by choice, secrets encrypted and never returned, old saved logins moved in."""

import json

import pytest

from app import credstore
from app.db import connect, init_db, set_setting


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    yield c
    c.close()


def test_a_login_is_private_to_its_owner_until_it_is_shared(conn):
    made = credstore.create(conn, "anna", "Web servers", "login", {"username": "root", "password": "s3cret"})
    assert made["has_secret"] and "password" not in made and "s3cret" not in json.dumps(made)
    assert [c["name"] for c in credstore.listing(conn, "anna")] == ["Web servers"]
    assert credstore.listing(conn, "bob") == []
    with pytest.raises(credstore.CredentialError):
        credstore.resolve(conn, "bob", made["id"])
    credstore.update(conn, "anna", made["id"], {"shared": True}, True)
    assert credstore.resolve(conn, "bob", made["id"], "test")["password"] == "s3cret"
    assert credstore.listing(conn, "bob")[0]["last_used"] and credstore.listing(conn, "bob")[0]["used_for"] == "test"


def test_the_secret_is_stored_encrypted_and_a_blank_secret_keeps_the_old_one(conn):
    made = credstore.create(conn, "anna", "NAS", "login", {"username": "admin", "password": "first-pw"})
    stored = conn.execute("SELECT value FROM settings WHERE key = 'credstore.entries'").fetchone()[0]
    assert stored.startswith("enc:v1:") and "first-pw" not in stored
    credstore.update(conn, "anna", made["id"], {"username": "root", "password": ""}, True)
    assert credstore.resolve(conn, "anna", made["id"])["password"] == "first-pw"
    credstore.update(conn, "anna", made["id"], {"password": "second-pw"}, True)
    assert credstore.resolve(conn, "anna", made["id"])["password"] == "second-pw"


def test_validation_and_deleting(conn):
    with pytest.raises(credstore.CredentialError):
        credstore.create(conn, "anna", "", "login", {"username": "u", "password": "p"})
    with pytest.raises(credstore.CredentialError):
        credstore.create(conn, "anna", "x", "login", {"username": "u"})                     # no secret
    with pytest.raises(credstore.CredentialError):
        credstore.create(conn, "anna", "x", "magic", {"username": "u", "password": "p"})
    made = credstore.create(conn, "anna", "Key", "ssh_key", {"username": "u", "private_key": "-----BEGIN-----"})
    with pytest.raises(credstore.CredentialError):
        credstore.create(conn, "anna", "key", "login", {"username": "u", "password": "p"})   # same name, any case
    with pytest.raises(credstore.CredentialError):
        credstore.delete(conn, "bob", made["id"], True)                                      # not visible to bob
    credstore.delete(conn, "anna", made["id"], True)
    assert credstore.listing(conn, "anna") == []


def test_the_api_is_for_administrators_and_never_returns_a_secret(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        made = c.post("/api/credentials", json={"name": "Lab", "kind": "login", "username": "u", "password": "pw-1", "shared": True}).json()
        assert "pw-1" not in json.dumps(made) and made["shared"]
        assert "pw-1" not in c.get("/api/credentials").text
        assert c.put(f"/api/credentials/{made['id']}", json={"name": "Lab 2"}).json()["name"] == "Lab 2"
        assert c.post("/api/credentials", json={"name": "Lab 2", "kind": "login", "username": "u", "password": "x"}).status_code == 422
        assert c.delete(f"/api/credentials/{made['id']}").json() == {"deleted": True}
        audit = [r["action"] for r in c.get("/api/audit?limit=50").json().get("rows", [])] if c.get("/api/audit?limit=50").status_code == 200 else []
        assert not any("pw-1" in a for a in audit)
    assert TestClient(app).get("/api/credentials").status_code == 401


def test_logins_saved_by_an_older_version_move_into_the_store(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    db = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(db)
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.5', 'pc1', 1, 'x', 'x')")
        set_setting(conn, "remote.credentials", json.dumps({"1:rdp": {"username": "bert", "password": "old-pw", "domain": "HOME"}}))
        conn.commit()
        conn.close()
        c.get("/api/remote")                                                                 # reading the saved logins moves them
        listed = c.get("/api/credentials").json()["credentials"]
        assert [(e["name"], e["username"], e["domain"], e["shared"]) for e in listed] == [("RDP pc1", "bert", "HOME", True)]
        conn = connect(db)
        raw = conn.execute("SELECT value FROM settings WHERE key = 'remote.credentials'").fetchone()[0]
        conn.close()
        assert "old-pw" not in raw


def test_a_monitor_can_use_a_stored_login_and_follows_it_when_it_changes(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.hostmetrics import service as hm
    from app.main import create_app

    db = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(db)
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.5', 'srv', 1, 'x', 'x')")
        conn.commit()
        made = c.post("/api/credentials", json={"name": "Servers", "kind": "login", "username": "monitor", "password": "pw-one"}).json()
        saved = c.put("/api/devices/1/monitor", json={"method": "ssh", "credential_id": made["id"]}).json()["monitor"]
        assert saved["credential_id"] == made["id"] and saved["username"] == "monitor" and "pw-one" not in json.dumps(saved)
        assert c.put("/api/devices/1/monitor", json={"method": "ssh", "credential_id": "nope"}).status_code == 422
        row = hm.get_monitor(conn, 1)
        assert hm.load_secret(conn, row)["password"] == "pw-one" and "pw-one" not in str(hm.raw_secret(conn, row))
        c.put(f"/api/credentials/{made['id']}", json={"password": "pw-two"})
        assert hm.load_secret(conn, hm.get_monitor(conn, 1))["password"] == "pw-two"
        conn.close()


def test_logins_typed_into_monitors_move_into_the_store_once_and_are_shared_between_equal_ones(tmp_path):
    from app.hostmetrics import service as hm

    conn = connect(tmp_path / "m.db")
    init_db(conn)
    for i in (1, 2, 3):
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, 'x', 'x')", (i, f"aa:bb:cc:dd:ee:0{i}", f"192.168.1.{i}", f"h{i}"))
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "192.168.1.1", "username": "root", "password": "same"})
    hm.save_monitor(conn, 2, {"method": "ssh", "address": "192.168.1.2", "username": "root", "password": "same"})
    hm.save_monitor(conn, 3, {"method": "ssh", "address": "192.168.1.3", "username": "root", "password": "other"})
    assert credstore.migrate_monitors(conn) == 3
    assert len(credstore.listing(conn, "anyone")) == 2                                  # shared: visible to every administrator
    assert hm.load_secret(conn, hm.get_monitor(conn, 2))["password"] == "same"
    assert "same" not in str(hm.raw_secret(conn, hm.get_monitor(conn, 1)))
    assert credstore.migrate_monitors(conn) == 0
