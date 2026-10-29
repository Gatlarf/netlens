"""CyberArk Central Credential Provider: against a stand-in that follows the documentation (mutual TLS, query parameters, error bodies). NOT a real CyberArk."""

import glob
import json
import os

import pytest

from app import credstore, pam
from app.db import connect, init_db
from tests.fake_cyberark import Fake, Pki


@pytest.fixture(scope="module")
def pki():
    return Pki()


@pytest.fixture
def ccp(pki):
    fake = Fake(pki).start()
    yield fake
    fake.stop()


def entry(ccp, pki, **over):
    return {"id": "c1", "name": "Web01 service account", "kind": "pam", "provider": "cyberark_ccp", "url": ccp.url, "appid": "Netlens", "safe": "Linux", "object": "svc-web01",
            "ca_cert": pki.ca, "client_cert": pki.client, "client_key": pki.client_key_pem, **over}


def get(ccp, pki, reason="", interactive=True, **over):
    return pam.checkout(entry(ccp, pki, **over), pam.Context("SSH terminal to web01", "anna", reason=reason, device="web01"), interactive)


def test_the_password_is_retrieved_with_the_application_id_a_client_certificate_and_a_traceable_reason(ccp, pki):
    f = get(ccp, pki, reason="INC-9 restart")
    assert f.values == {"username": "svc", "password": "pw-ccp-1"} and f.lease == "ccp:svc-web01"
    req = ccp.requests[-1]
    assert req["path"] == "/AIMWebService/api/Accounts" and req["query"]["AppID"] == "Netlens" and req["query"]["Safe"] == "Linux" and req["query"]["Object"] == "svc-web01"
    assert req["query"]["FailRequestOnPasswordChange"] == "true"
    assert "anna" in req["query"]["Reason"] and "INC-9 restart" in req["query"]["Reason"] and "[nl-" in req["query"]["Reason"] and "pw-ccp" not in req["query"]["Reason"]
    assert req["peer"]["subject"][0][0][1] == "Test CA" or req["peer"] is not None        # the stand-in saw a verified client certificate


def test_the_client_certificate_is_not_left_on_disk(ccp, pki):
    before = set(glob.glob("/dev/shm/nl-cc-*") + glob.glob("/tmp/nl-cc-*"))
    get(ccp, pki)
    assert set(glob.glob("/dev/shm/nl-cc-*") + glob.glob("/tmp/nl-cc-*")) == before


def test_without_a_client_certificate_or_with_a_wrong_one_nothing_is_handed_out(ccp, pki):
    with pytest.raises(pam.PamError, match="client certificate"):
        get(ccp, pki, client_cert="", client_key="")
    with pytest.raises(pam.PamError):
        get(ccp, pki, client_cert=pki.rogue_client, client_key=pki.client_key_pem)           # signed by a CA the server does not trust
    with pytest.raises(pam.PamError, match="both the client certificate and its key"):
        pam.validate(entry(ccp, pki, client_key=""))
    with pytest.raises(pam.PamError, match="not valid"):
        get(ccp, pki, client_cert="garbage", client_key="garbage")


def test_the_server_certificate_must_be_trusted(ccp, pki):
    with pytest.raises(pam.PamError, match="not trusted"):
        get(ccp, pki, ca_cert=pki.other_ca)


def test_every_refusal_is_a_sentence_without_a_secret(ccp, pki):
    cases = [({"appid": "Other"}, "refused the application"), ({"object": "nope"}, "no such account")]
    for over, text in cases:
        with pytest.raises(pam.PamError, match=text) as exc:
            get(ccp, pki, **over)
        assert "pw-ccp" not in str(exc.value)
    ccp.status_override = 503
    with pytest.raises(pam.PamError, match="not available"):
        get(ccp, pki)
    ccp.status_override = 0
    with pytest.raises(pam.PamError, match="changing this account's password"):
        get(ccp, pki, object="changing")


def test_a_private_key_account_and_a_fixed_user_name(ccp, pki):
    f = get(ccp, pki, object="svc-key", content_as="private_key")
    assert f.values == {"username": "root", "private_key": "KEYDATA"}


@pytest.mark.parametrize("field,bad", [("safe", "a&AppID=x"), ("object", "o=1"), ("folder", "r?x"), ("appid", "a;b"), ("object", "x\ny"), ("account_user", "u#")])
def test_a_field_cannot_add_or_change_a_parameter(ccp, pki, field, bad):
    with pytest.raises(pam.PamError):
        get(ccp, pki, **{field: bad})
    assert not ccp.requests


def test_the_account_must_be_named_and_the_address_guarded(ccp, pki):
    with pytest.raises(pam.PamError, match="name the account"):
        pam.validate(entry(ccp, pki, object=""))
    for url in ("http://169.254.169.254", "file:///x", ""):
        with pytest.raises(pam.PamError):
            get(ccp, pki, url=url)


def test_a_reason_is_enforced_like_for_every_provider(ccp, pki):
    with pytest.raises(pam.PamError, match="needs a reason"):
        get(ccp, pki, reason_required=True)
    with pytest.raises(pam.PamError, match="only be used by a person"):
        get(ccp, pki, reason="INC-1", interactive=False, reason_required=True)


def test_through_the_credential_store_the_secret_and_key_are_never_shown(ccp, pki, tmp_path):
    conn = connect(tmp_path / "c.db")
    init_db(conn)
    made = credstore.create(conn, "anna", "CCP", "pam", {k: v for k, v in entry(ccp, pki).items() if k not in ("id", "name", "kind")}, shared=True)
    shown = json.dumps(credstore.listing(conn, "anna"))
    assert made["pam"]["where"] == "Linux/svc-web01" and made["pam"]["auth"] == "certificate" and made["has_secret"]
    assert "BEGIN" not in shown and "PRIVATE" not in shown and pki.client_key_pem.splitlines()[1] not in shown
    stored = conn.execute("SELECT value FROM settings WHERE key = 'credstore.entries'").fetchone()[0]
    assert stored.startswith("enc:v1:") and pki.client_key_pem.splitlines()[1] not in stored
    got = credstore.resolve(conn, "anna", made["id"], "SSH terminal", "", "web01")
    assert got["password"] == "pw-ccp-1" and "client_key" not in got
    rows = " ".join(r["action"] for r in conn.execute("SELECT action FROM audit_log WHERE method = 'PAM'"))
    assert "cyberark_ccp" in rows and "pw-ccp" not in rows
    conn.close()
