import logging

import pytest
from fastapi.testclient import TestClient

from app import syslog
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


@pytest.fixture
def logger_setup(tmp_path):
    root = logging.getLogger()
    before = list(root.handlers)
    level = root.level
    syslog.setup(tmp_path)
    yield tmp_path
    for h in list(root.handlers):
        if h not in before:
            root.removeHandler(h)
            h.close()
    root.setLevel(level)


def test_lines_are_kept_in_a_file_and_read_back(logger_setup):
    log = logging.getLogger("netlens.test")
    log.info("hello %s", "world")
    log.warning("careful")
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("it broke")
    out = syslog.entries(logger_setup, level="info")
    assert [e["message"].split("\n")[0] for e in out["entries"]][:3] == ["it broke", "careful", "hello world"]          # newest first
    assert "ValueError: boom" in out["entries"][0]["message"] and out["entries"][0]["level"] == "error" and out["entries"][0]["logger"] == "netlens.test"
    assert [e["message"] for e in syslog.entries(logger_setup, level="warning")["entries"]][1:] == ["careful"]
    assert [e["level"] for e in syslog.entries(logger_setup, level="error")["entries"]] == ["error"]
    assert [e["message"] for e in syslog.entries(logger_setup, level="info", query="WORLD")["entries"]] == ["hello world"]
    assert syslog.entries(logger_setup, level="info", limit=1)["entries"][0]["message"].startswith("it broke")
    assert "hello world" in syslog.download(logger_setup)


def test_setup_twice_adds_no_second_handler(logger_setup):
    syslog.setup(logger_setup)
    logging.getLogger("netlens.twice").info("once")
    assert len([e for e in syslog.entries(logger_setup)["entries"] if e["message"] == "once"]) == 1


def test_nothing_logged_yet_and_an_unwritable_folder(tmp_path):
    assert syslog.entries(tmp_path)["entries"] == [] and syslog.download(tmp_path) == ""
    blocker = tmp_path / "file"
    blocker.write_text("x")
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        assert syslog.setup(blocker) is None                     # cannot make a folder inside a file: Netlens must still start
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)


def test_a_capability_failure_reaches_the_system_log(logger_setup):
    from app.scanner.errors import explain_scan_error

    logging.getLogger("app.scanner.orchestrator").error("scan 3 failed: SETTING MISSING on the netlens container. %s", explain_scan_error("Operation not permitted")[:60])
    assert "SETTING MISSING" in syslog.entries(logger_setup, level="error")["entries"][0]["message"]


def test_the_api_is_for_administrators(tmp_path, logger_setup):
    from app import users

    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    users.create_user(c, "vera", "a-long-enough-password", "viewer")
    c.close()
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(logger_setup)})
    app = create_app(settings, db_path=p)
    logging.getLogger("netlens.api").warning("seen by the admin")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as admin:
        j = admin.get("/api/system-log?level=warning").json()
        assert j["entries"][0]["message"] == "seen by the admin" and j["files"] == 1
        assert admin.get("/api/system-log?level=bogus&limit=0").status_code == 422
        assert "seen by the admin" in admin.get("/api/system-log/download").text
    with TestClient(app) as viewer:
        assert viewer.post("/api/login", json={"username": "vera", "password": "a-long-enough-password"}).status_code == 200
        assert viewer.get("/api/system-log").status_code == 403 and viewer.get("/api/system-log/download").status_code == 403


def test_every_table_is_made_resizable_by_one_observer():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
    js = (root / "colresize.js").read_text()
    assert "export function autoResizable" in js and "table.data, table.table, table.rep-table" in js and "no-resize" in js
    app = (root / "app.js").read_text()
    assert 'import { autoResizable } from "./colresize.js"' in app and "autoResizable();" in app


def test_the_application_links_to_the_public_website_address_only():
    from pathlib import Path

    for path in list((Path(__file__).resolve().parent.parent / "app").rglob("*.js")) + list((Path(__file__).resolve().parent.parent / "app").rglob("*.py")):
        assert "www.home.codeshrimp.com" not in path.read_text(encoding="utf-8", errors="ignore"), f"{path.name} links to the temporary website address"
