"""A backup brings the installed plugins back too: their code and their settings."""
import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.backup import create_backup, validate_backup
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.service import get_state

AUTH = {"Authorization": "Bearer secret"}
PY = "def fetch(config):\n    return {'devices': []}\n\n\ndef test(config):\n    return {'ok': True}\n"


def plugin_zip(plugin_id="omada", version="1.0.0"):
    manifest = {"id": plugin_id, "name": plugin_id.title(), "version": version, "api_version": 1, "kind": "topology",
                "config": [{"key": "host", "type": "text", "label": "Host", "required": True}]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.json", json.dumps(manifest))
        z.writestr("plugin.py", PY)
    return buf.getvalue()


def instance(root):
    root.mkdir()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(root)}), db_path=root / "netlens.db")
    conn = connect(root / "netlens.db")
    init_db(conn)
    conn.close()
    return TestClient(app, headers=AUTH)


def test_a_restore_into_a_fresh_data_folder_brings_back_plugins_and_settings(tmp_path):
    old = instance(tmp_path / "old")
    with old:
        assert old.post("/api/plugins", content=plugin_zip(), headers={"Content-Type": "application/zip"}).status_code == 200
        assert old.put("/api/plugins/omada", json={"enabled": True, "config": {"host": "10.0.0.1"}}).status_code == 200
        backup = old.get("/api/backup").content

    new = instance(tmp_path / "new")                                   # a recreated container: empty data folder
    with new:
        assert new.get("/api/plugins").json()["plugins"] == [] or all(p["builtin"] for p in new.get("/api/plugins").json()["plugins"])
        res = new.post("/api/restore", content=backup, headers={"Content-Type": "application/octet-stream"})
        assert res.status_code == 200 and res.json()["plugins"] == ["omada"] and res.json()["plugins_failed"] == []
        omada = new.get("/api/plugins/omada").json()
        assert omada["enabled"] is True and omada["config"]["host"] == "10.0.0.1"
        assert new.get("/api/plugins").json()["missing"] == []
        assert (tmp_path / "new" / "plugins" / "omada" / "plugin.py").read_text() == PY

    conn = connect(tmp_path / "new" / "netlens.db")                    # the transport table does not stay in the live database
    try:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'backup_plugins'").fetchone() is None
    finally:
        conn.close()


def test_restoring_puts_the_version_of_the_backup_back(tmp_path):
    app = instance(tmp_path / "a")
    with app:
        app.post("/api/plugins", content=plugin_zip(version="1.0.0"), headers={"Content-Type": "application/zip"})
        backup = app.get("/api/backup").content
        app.post("/api/plugins", content=plugin_zip(version="2.0.0"), headers={"Content-Type": "application/zip"}, params={"replace": "true"})
        assert app.get("/api/plugins/omada").json()["manifest"]["version"] == "2.0.0"
        app.post("/api/restore", content=backup, headers={"Content-Type": "application/octet-stream"})
        assert app.get("/api/plugins/omada").json()["manifest"]["version"] == "1.0.0"


def test_a_backup_is_still_a_valid_netlens_database_and_old_backups_restore(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    conn = connect(root / "netlens.db")
    init_db(conn)
    conn.close()
    create_backup(root / "netlens.db", root / "b.db", root)           # no plugins installed: an empty table
    validate_backup(root / "b.db")
    from app.backup import restore_backup
    assert restore_backup(root / "netlens.db", root / "b.db", root) == {"plugins": [], "plugins_failed": []}
    conn = connect(root / "netlens.db")
    conn.execute("DROP TABLE IF EXISTS backup_plugins")
    conn.close()
