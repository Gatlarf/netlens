"""A start page per role: used until somebody chooses their own."""
import pytest
from fastapi.testclient import TestClient

from app import preferences, roles
from app.auth import Principal
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "netlens.db")
    init_db(c)
    c.execute("INSERT INTO users (id, username, password_hash, role, created) VALUES (7, 'ann', 'x', 'viewer', '2026-01-01T00:00:00Z')")
    c.commit()
    yield c
    c.close()


def who(role="viewer", uid=7):
    return Principal(username="ann", role=role, user_id=uid)


def test_a_role_has_its_own_start_page_and_a_person_may_choose_another(conn):
    assert preferences.effective(conn, who()) is None
    preferences.set_role_page(conn, "viewer", "#/uptime")
    assert preferences.effective(conn, who()) == "#/uptime" and preferences.role_default(conn, who()) == "#/uptime"
    assert preferences.effective(conn, who("operator", 8)) is None                     # another role is not affected
    preferences.set_start_page(conn, who(), "#/map")
    assert preferences.effective(conn, who()) == "#/map"                                # their own choice wins
    preferences.set_start_page(conn, who(), None)
    assert preferences.effective(conn, who()) == "#/uptime"
    preferences.set_role_page(conn, "viewer", None)
    assert preferences.effective(conn, who()) is None and preferences.role_pages(conn) == {}


def test_a_custom_role_wins_over_its_base_and_an_unfit_page_is_refused(conn):
    saved = roles.save(conn, "Auditor", "viewer", [])
    rid = saved["id"] if isinstance(saved, dict) else [r for r in roles.load(conn) if r["name"] == "Auditor"][0]["id"]
    conn.execute("UPDATE users SET custom_role = ? WHERE id = 7", (rid,))
    conn.commit()
    preferences.set_role_page(conn, "viewer", "#/devices")
    preferences.set_role_page(conn, rid, "#/reports")
    assert preferences.effective(conn, who()) == "#/reports"
    with pytest.raises(ValueError):
        preferences.set_role_page(conn, "viewer", "#/remote")                           # an administrators-only page for a viewer
    with pytest.raises(ValueError):
        preferences.set_role_page(conn, "viewer", "#/nowhere")
    with pytest.raises(ValueError):
        preferences.set_role_page(conn, "nobody", "#/map")
    preferences.set_role_page(conn, "admin", "#/remote")                                # for an administrator it is fine
    assert preferences.effective(conn, who("admin", 1)) == "#/remote"


def test_the_session_and_the_api_report_it(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        got = c.get("/api/roles/start-pages").json()
        assert [r["key"] for r in got["roles"][:3]] == ["admin", "operator", "viewer"] and got["start_pages"] == {} and any(p["value"] == "#/uptime" for p in got["pages"])
        assert c.put("/api/roles/start-pages", json={"role": "admin", "page": "#/uptime"}).json()["start_pages"] == {"admin": "#/uptime"}
        assert c.get("/api/session").json()["start_page"] == "#/uptime"                 # the access token is an administrator
        assert c.get("/api/me/preferences").json()["role_start_page"] == "#/uptime" and c.get("/api/me/preferences").json()["start_page"] is None
        assert c.put("/api/roles/start-pages", json={"role": "viewer", "page": "#/remote"}).status_code == 422
        assert c.put("/api/roles/start-pages", json={"role": "admin", "page": None}).json()["start_pages"] == {}
