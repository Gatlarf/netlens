import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app
from tests.test_setup import make as make_setup
from tests.test_users import make, sign_in

JS = Path(__file__).resolve().parents[1] / "app" / "static" / "js"


def test_existing_install_starts_as_new_and_progress_is_saved(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        assert c.get("/api/wizard").json() == {"status": "new", "step": 0, "steps": 9}
        assert c.put("/api/wizard", json={"status": "pending", "step": 3}).json()["step"] == 3
        assert c.put("/api/wizard", json={"status": "dismissed"}).json() == {"status": "dismissed", "step": 3, "steps": 9}
        assert c.put("/api/wizard", json={"status": "done"}).json()["status"] == "done"
        assert c.put("/api/wizard", json={"status": "bogus"}).status_code == 422
        assert c.put("/api/wizard", json={"step": 99}).status_code == 422


def test_viewer_cannot_read_or_change_it(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        make(c, "vera", "viewer")
        vera = sign_in(app, "vera")
        assert vera.get("/api/wizard").status_code == 403
        assert vera.put("/api/wizard", json={"status": "done"}).status_code == 403


def test_a_fresh_install_lands_in_the_wizard(tmp_path):
    app = make_setup(tmp_path)
    with TestClient(app) as c:
        assert c.post("/api/setup", json={"username": "Bert", "password": "longenough1"}).status_code == 200
        assert c.get("/api/wizard").json()["status"] == "pending"


def test_demo_never_shows_the_wizard(tmp_path):
    with TestClient(create_app(load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_DEMO": "on"}))) as c:
        c.post("/api/login", json={"username": "demo", "password": "netlens-demo"})
        assert c.get("/api/wizard").json()["status"] == "done"


def test_front_end_is_wired_up():
    assert '"#/wizard": "wizard"' in (JS / "app.js").read_text()
    assert 'location.hash = "#/wizard"' in (JS / "app.js").read_text()
    assert re.search(r'key: "wizard"', (JS / "pages" / "settings.js").read_text())
    assert "wizard-nudge" in (JS / "pages" / "dashboard.js").read_text()
    assert (JS / "pages" / "wizard.js").exists()
