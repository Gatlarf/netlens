"""The Vault/OpenBao provider against a real server. Runs only when one is given (the lab OpenBao); everything else is covered by tests/test_pam.py with a stand-in.

  NETLENS_TEST_BAO_URL=http://host:8200  NETLENS_TEST_BAO_ROLE=...  NETLENS_TEST_BAO_SECRET=...  NETLENS_TEST_BAO_TOKEN=...
with a KV v2 engine "secret" holding netlens/linux-admin (username, password), a KV v1 engine "kv1" holding old/db, and a policy that reads only those.
"""

import os

import pytest

from app import pam

URL, ROLE, SECRET, TOKEN = (os.environ.get(k, "") for k in ("NETLENS_TEST_BAO_URL", "NETLENS_TEST_BAO_ROLE", "NETLENS_TEST_BAO_SECRET", "NETLENS_TEST_BAO_TOKEN"))
pytestmark = pytest.mark.skipif(not (URL and ROLE and SECRET and TOKEN), reason="no real OpenBao/Vault given")

BASE = {"id": "live", "name": "lab", "provider": "vault_kv", "url": URL, "mount": "secret", "kv_version": "2", "path": "netlens/linux-admin", "role_id": ROLE, "secret_id": SECRET}


def go(**over):
    return pam.checkout({**BASE, **over}, pam.Context("live test", "tester"), True)


def test_approle_token_and_both_kv_versions():
    f = go()
    assert sorted(f.values) == ["password", "username"]
    f.done()
    f = go(role_id="", secret_id="", token=TOKEN)
    assert f.values["username"] and f.lease
    f = go(mount="kv1", kv_version="1", path="old/db", role_id="", secret_id="", token=TOKEN)
    assert f.values["username"] == "legacy"


def test_the_policy_is_respected_and_errors_are_clear():
    with pytest.raises(pam.PamError, match="may not read"):
        go(path="other/forbidden")
    with pytest.raises(pam.PamError, match="no secret at that path"):
        go(path="netlens/nothing-here")
    with pytest.raises(pam.PamError, match="AppRole sign-in was refused"):
        go(secret_id="00000000-0000-0000-0000-000000000000")
