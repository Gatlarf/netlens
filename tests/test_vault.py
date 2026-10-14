import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import vault
from app.config import load_settings
from app.db import connect, get_setting, init_db, set_setting
from app.main import create_app


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    return c


def raw(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def test_secret_settings_are_encrypted_at_rest_and_read_back(conn):
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": True, "config": {"password": "hunter2"}}))
    set_setting(conn, "notify.channels", json.dumps([{"settings": {"bot_token": "123:SECRET"}}]))
    for key in ("plugin.proxmox", "notify.channels"):
        stored = raw(conn, key)
        assert stored.startswith("enc:v1:") and "hunter2" not in stored and "SECRET" not in stored
    assert json.loads(get_setting(conn, "plugin.proxmox"))["config"]["password"] == "hunter2"


def test_other_settings_stay_readable(conn):
    set_setting(conn, "plugin.proxmox.status", json.dumps({"ok": True}))
    set_setting(conn, "map_default_layout", "compact")
    assert raw(conn, "plugin.proxmox.status") == json.dumps({"ok": True}) and raw(conn, "map_default_layout") == "compact"


def test_same_value_gets_a_new_nonce_each_time(conn):
    set_setting(conn, "plugin.x", "{}")
    first = raw(conn, "plugin.x")
    set_setting(conn, "plugin.x", "{}")
    assert raw(conn, "plugin.x") != first


def test_plain_text_from_an_older_version_is_encrypted_once_with_a_copy_kept(conn, tmp_path):
    conn.execute("INSERT INTO settings (key, value) VALUES ('plugin.truenas', ?)", (json.dumps({"enabled": True, "api_key": "KEY123"}),))
    conn.execute("INSERT INTO settings (key, value) VALUES ('scan.quick', '15')")
    conn.commit()
    assert vault.status(conn)["plaintext"] == 1
    assert vault.migrate(conn) == 1 and vault.migrate(conn) == 0
    assert "KEY123" not in raw(conn, "plugin.truenas") and raw(conn, "scan.quick") == "15"
    assert json.loads(get_setting(conn, "plugin.truenas"))["api_key"] == "KEY123"
    copy = tmp_path / "t.db.pre-encryption"
    assert copy.exists() and "KEY123" in sqlite3.connect(copy).execute("SELECT value FROM settings WHERE key='plugin.truenas'").fetchone()[0]


def test_key_file_is_private_and_a_wrong_key_degrades_gracefully(conn, tmp_path):
    set_setting(conn, "plugin.npm", json.dumps({"password": "pw"}))
    key_file = tmp_path / "secret.key"
    assert key_file.exists() and oct(key_file.stat().st_mode & 0o777) == "0o600"
    # another installation's key: the value cannot be read, nothing crashes
    key_file.write_text(vault.encode_key(b"\x01" * 32))
    vault.forget_cached_key(conn)
    assert get_setting(conn, "plugin.npm") is None
    state = vault.status(conn)
    assert state["unreadable"] == 1 and state["encrypted"] == 1


def test_environment_key_wins(conn, tmp_path, monkeypatch):
    monkeypatch.setenv(vault.ENV_KEY, vault.encode_key(b"\x07" * 32))
    set_setting(conn, "plugin.a", "{}")
    assert not (tmp_path / "secret.key").exists() and vault.key_source(conn) == "env"
    assert get_setting(conn, "plugin.a") == "{}"
    monkeypatch.setenv(vault.ENV_KEY, "a passphrase works too")
    assert get_setting(conn, "plugin.a") is None                       # a different key


def test_old_mail_copy_is_removed_after_the_migration(conn):
    from app.notify import channels as ch
    from app.notify.config import NotifyConfig, save_config

    save_config(conn, NotifyConfig(enabled=True, smtp_host="smtp.example.com", from_addr="a@example.com", to_addrs=["b@example.com"], password="MAILPW"))
    channels = ch.load_channels(conn)
    assert channels[0]["settings"]["password"] == "MAILPW"
    assert raw(conn, "notifications") is None
    assert "MAILPW" not in raw(conn, "notify.channels")


def test_api_status_and_key_handling(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        c.post("/api/notify-channels", json={"type": "ntfy", "settings": {"topic": "t"}})
        state = c.get("/api/vault").json()
        assert state["encrypted"] >= 1 and state["unreadable"] == 0 and state["source"] == "file"
        key = c.get("/api/vault/key").json()["key"]
        assert len(key) == 43
        # a working key is not replaced by accident
        assert c.put("/api/vault/key", json={"key": vault.encode_key(b"\x02" * 32)}).status_code == 409
        # through a proxy the key is never shown
        assert c.get("/api/vault/key", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 403
        # after "restoring on another machine": a different key file, then the right one is put back
        (tmp_path / "secret.key").write_text(vault.encode_key(b"\x09" * 32))
        from app.db import connect as _c
        vault.forget_cached_key(_c(tmp_path / "t.db"))
        assert c.get("/api/vault").json()["unreadable"] >= 1
        assert c.put("/api/vault/key", json={"key": "nonsense"}).status_code == 422
        fixed = c.put("/api/vault/key", json={"key": key}).json()
        assert fixed["unreadable"] == 0
        assert c.get("/api/dashboard").status_code == 200


def test_recovery_passphrase_wraps_the_key(conn):
    set_setting(conn, "plugin.a", json.dumps({"pw": "x"}))
    assert vault.status(conn)["recovery"] is False
    vault.set_recovery(conn, "a long passphrase")
    assert vault.status(conn)["recovery"] is True
    wrapped = conn.execute("SELECT value FROM settings WHERE key = 'vault.recovery'").fetchone()[0]
    assert "passphrase" not in wrapped and vault.encode_key(vault._key(conn)) not in wrapped
    assert vault.recover(conn, "a long passphrase") == vault._key(conn)
    with pytest.raises(vault.VaultError):
        vault.recover(conn, "another passphrase")
