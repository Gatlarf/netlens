"""The master key held by an external key service (Vault/OpenBao transit): wrapped on first use, unwrapped at start, never on disk in the clear once finished."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app import kms, licence, vault
from app.config import load_settings
from app.db import connect, init_db, set_setting
from app.main import create_app
from tests.fake_vault import ROLE, SECRET, Fake

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def bao():
    fake = Fake().start()
    yield fake
    fake.stop()


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for name in ("NETLENS_SECRET_KEY", "NETLENS_SECRET_KEY_FILE", "NETLENS_KMS", "NETLENS_KMS_URL", "NETLENS_KMS_KEY", "NETLENS_KMS_MOUNT", "NETLENS_KMS_TOKEN", "NETLENS_KMS_ROLE_ID", "NETLENS_KMS_SECRET_ID"):
        monkeypatch.delenv(name, raising=False)
    vault._keys.clear()
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    yield
    vault._keys.clear()


def use_kms(monkeypatch, bao, approle=True):
    monkeypatch.setenv("NETLENS_KMS", "vault_transit")
    monkeypatch.setenv("NETLENS_KMS_URL", bao.url)
    monkeypatch.setenv("NETLENS_KMS_KEY", "netlens")
    if approle:
        monkeypatch.setenv("NETLENS_KMS_ROLE_ID", ROLE)
        monkeypatch.setenv("NETLENS_KMS_SECRET_ID", SECRET)
    else:
        monkeypatch.setenv("NETLENS_KMS_TOKEN", bao.static_token)


def fresh_db(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    return conn


def test_an_installation_with_a_key_file_moves_to_the_key_service_without_losing_a_secret(tmp_path, monkeypatch, bao):
    conn = fresh_db(tmp_path)
    set_setting(conn, "engineer.api_key", "sk-secret-1")
    conn.commit()
    plain = (tmp_path / "secret.key").read_text().strip()
    vault._keys.clear()
    use_kms(monkeypatch, bao)
    assert vault.key_source(conn) == "kms"
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    assert vault.decrypt(conn, row) == "sk-secret-1"                                      # the same key, so nothing is re-encrypted
    wrapped = json.loads((tmp_path / "secret.key.kms").read_text())
    assert wrapped["ciphertext"].startswith("vault:v1:") and plain not in json.dumps(wrapped)
    assert (tmp_path / "secret.key").exists()                                             # kept until the move is confirmed
    st = vault.status(conn)
    assert st["source"] == "kms" and st["kms"]["wrapped"] and st["kms"]["plaintext_key_on_disk"] and st["kms"]["version"] == 1 and plain not in json.dumps(st)
    assert bao.revoked and all(bao.tokens[t] == "approle" for t in bao.revoked)            # every AppRole token was revoked after its call


def test_a_new_installation_never_writes_the_key_in_the_clear(tmp_path, monkeypatch, bao):
    use_kms(monkeypatch, bao, approle=False)
    conn = fresh_db(tmp_path)
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    assert not (tmp_path / "secret.key").exists() and (tmp_path / "secret.key.kms").exists()
    vault._keys.clear()                                                                    # a restart: the key comes back from the service
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    assert vault.decrypt(conn, row) == "sk-1"                                                      # decrypt worked via the service
    assert "decrypt" in bao.transit_calls and bao.revoked == []                            # a fixed token is not revoked


def test_when_the_service_is_down_nothing_is_decrypted_and_it_recovers_by_itself(tmp_path, monkeypatch, bao):
    use_kms(monkeypatch, bao)
    conn = fresh_db(tmp_path)
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    vault._keys.clear()
    bao.down = 3
    with pytest.raises(vault.VaultError, match="key service"):
        vault.decrypt(conn, row)
    bao.down = 0
    assert vault.decrypt(conn, row) == "sk-1"                                              # a failure is not cached


def test_every_problem_with_the_service_is_a_sentence_without_a_key(tmp_path, monkeypatch, bao):
    use_kms(monkeypatch, bao)
    conn = fresh_db(tmp_path)
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    plain = vault.encode_key(vault._key(conn))
    for setup, text in ((lambda: setattr(bao, "transit_allowed", False), "may not use this key"), (lambda: (setattr(bao, "transit_allowed", True), setattr(bao, "transit_key", "other")), "no such transit key")):
        setup()
        vault._keys.clear()
        with pytest.raises(vault.VaultError, match=text) as exc:
            vault._key(conn)
        assert plain not in str(exc.value) and SECRET not in str(exc.value)
    bao.transit_key = "netlens"
    monkeypatch.setenv("NETLENS_KMS_SECRET_ID", "wrong")
    vault._keys.clear()
    with pytest.raises(vault.VaultError, match="refused the AppRole"):
        vault._key(conn)


def test_the_configuration_is_checked(monkeypatch):
    monkeypatch.setenv("NETLENS_KMS", "aws")
    with pytest.raises(kms.KmsError, match="vault_transit"):
        kms.config()
    monkeypatch.setenv("NETLENS_KMS", "vault_transit")
    monkeypatch.setenv("NETLENS_KMS_URL", "https://v.example")
    monkeypatch.setenv("NETLENS_KMS_KEY", "bad key!")
    with pytest.raises(kms.KmsError, match="NETLENS_KMS_KEY"):
        kms.config()
    monkeypatch.setenv("NETLENS_KMS_KEY", "netlens")
    with pytest.raises(kms.KmsError, match="TOKEN"):
        kms.config()
    monkeypatch.setenv("NETLENS_KMS_TOKEN_FILE", "/nonexistent")
    with pytest.raises(kms.KmsError, match="cannot be read"):
        kms.config()


def test_without_the_licence_a_new_wrapping_is_refused_but_an_existing_one_keeps_working(tmp_path, monkeypatch, bao):
    use_kms(monkeypatch, bao)
    conn = fresh_db(tmp_path)
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    monkeypatch.setattr(licence, "allows", lambda conn_, feature, now=None: False)
    vault._keys.clear()
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    assert vault.decrypt(conn, row) == "sk-1"                                              # already wrapped: never locked out
    other = tmp_path / "other"
    other.mkdir()
    c2 = connect(other / "t.db")
    with pytest.raises(vault.VaultError, match="Enterprise"):
        init_db(c2)
        set_setting(c2, "engineer.api_key", "x")


@pytest.fixture
def api(tmp_path, monkeypatch, bao):
    use_kms(monkeypatch, bao)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app, client=("192.168.0.50", 5000)) as c:
        yield c, tmp_path, bao


def test_rewrap_moves_the_wrapped_key_to_the_new_version_and_changes_nothing_else(api):
    c, path, bao = api
    conn = connect(path / "netlens.db")
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    before = vault._key(conn)
    assert c.get("/api/vault", headers=ADMIN).json()["kms"]["version"] == 1
    bao.transit_version = 2                                                               # the transit key was rotated in the service
    r = c.post("/api/vault/kms/rewrap", headers=ADMIN)
    assert r.status_code == 200 and r.json()["kms"]["version"] == 2 and r.json()["unreadable"] == 0
    assert json.loads((path / "secret.key.kms").read_text())["ciphertext"].startswith("vault:v2:")
    vault._keys.clear()
    assert vault._key(conn) == before                                                      # the master key itself is unchanged
    assert "rewrap" in bao.transit_calls
    audit = " ".join(r["action"] for r in c.get("/api/audit", headers=ADMIN).json()["entries"])
    assert "version 2" in audit and vault.encode_key(before) not in audit


def test_finish_deletes_the_plain_text_key_only_when_the_service_returns_it(api):
    c, path, bao = api
    conn = connect(path / "netlens.db")
    set_setting(conn, "engineer.api_key", "sk-1")
    conn.commit()
    assert c.post("/api/vault/kms/finish", json={}, headers=ADMIN).status_code == 422
    key_file = path / "secret.key"
    assert not key_file.exists()                                                          # a new installation never had one
    key_file.write_text(vault.encode_key(b"\x07" * 32) + "\n")                              # a different key in the file: the service does not return it
    assert c.post("/api/vault/kms/finish", json={"confirm": True}, headers=ADMIN).status_code == 409 and key_file.exists()
    key_file.write_text(vault.encode_key(vault._key(conn)) + "\n")
    done = c.post("/api/vault/kms/finish", json={"confirm": True}, headers=ADMIN)
    assert done.status_code == 200 and not key_file.exists() and done.json()["kms"]["plaintext_key_on_disk"] is False
    vault._keys.clear()
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    assert vault.decrypt(conn, row) == "sk-1"                                              # a restart still works
    assert c.get("/api/vault/key", headers=ADMIN).status_code == 409                       # and the key cannot be shown: this server has only the wrapped copy
