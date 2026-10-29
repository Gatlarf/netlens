"""The master key held by a real OpenBao/Vault transit engine. Runs only when one is given:
  NETLENS_TEST_KMS_URL  NETLENS_TEST_KMS_ROLE  NETLENS_TEST_KMS_SECRET   (transit key "netlens-master", policy: update on encrypt/decrypt/rewrap, read on keys)"""

import json
import os

import pytest

from app import kms, licence, vault
from app.db import connect, init_db, set_setting

URL, ROLE, SECRET = (os.environ.get(k, "") for k in ("NETLENS_TEST_KMS_URL", "NETLENS_TEST_KMS_ROLE", "NETLENS_TEST_KMS_SECRET"))
pytestmark = pytest.mark.skipif(not (URL and ROLE and SECRET), reason="no real OpenBao/Vault transit given")


def test_wrap_unwrap_rewrap_and_a_restart(tmp_path, monkeypatch):
    for name, value in (("NETLENS_KMS", "vault_transit"), ("NETLENS_KMS_URL", URL), ("NETLENS_KMS_KEY", "netlens-master"), ("NETLENS_KMS_ROLE_ID", ROLE), ("NETLENS_KMS_SECRET_ID", SECRET)):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    vault._keys.clear()
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    set_setting(conn, "engineer.api_key", "sk-live-1")
    conn.commit()
    key = vault._key(conn)
    wrapped = json.loads((tmp_path / "secret.key.kms").read_text())["ciphertext"]
    assert wrapped.startswith("vault:v") and not (tmp_path / "secret.key").exists()
    vault._keys.clear()                                                                    # a restart
    assert vault._key(conn) == key
    new, version = kms.rewrap(wrapped)
    assert new.startswith("vault:v") and version and kms.unwrap(new) == key
    row = conn.execute("SELECT value FROM settings WHERE key = 'engineer.api_key'").fetchone()[0]
    assert vault.decrypt(conn, row) == "sk-live-1"
