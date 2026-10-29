"""Delinea Secret Server and BeyondTrust Password Safe, which check passwords out. Against stand-ins that follow the vendors' documentation. NOT real products."""

import json

import pytest

from app import credstore, pam
from app.db import connect, init_db
from tests import fake_beyondtrust, fake_delinea


@pytest.fixture(autouse=True)
def clean():
    yield
    pam.release_all()


@pytest.fixture
def dsm():
    f = fake_delinea.Fake().start()
    yield f
    f.stop()


@pytest.fixture
def bt():
    f = fake_beyondtrust.Fake().start()
    yield f
    f.stop()


def d_entry(f, **over):
    return {"id": "d1", "name": "Web admin", "kind": "pam", "provider": "delinea_ss", "url": f.url, "secret_id_ref": "1234", "app_user": "netlens-app", "app_password": "app-pw", **over}


def b_entry(f, **over):
    return {"id": "b1", "name": "Web admin", "kind": "pam", "provider": "beyondtrust_ps", "url": f.url, "api_key": "KEY-1", "run_as": "svc-netlens", "ps_system": "web01", "ps_account": "svc", **over}


def run(entry, reason="", interactive=True):
    return pam.checkout(entry, pam.Context("SSH terminal to web01", "anna", reason=reason, device="web01"), interactive)


# ------------------------------------------------------------------ Delinea
def test_delinea_reads_the_fields_and_sends_a_traceable_comment(dsm):
    f = run(d_entry(dsm), reason="INC-3")
    assert f.values == {"username": "svc-web", "password": "pw-dsm-1"} and f.lease == "secret 1234"
    read = [r for r in dsm.requests if r["path"] == "/api/v1/secrets/1234"][0]
    comment = read["query"]["autoComment"][0]
    assert "anna" in comment and "INC-3" in comment and "[nl-" in comment and read["headers"]["Authorization"] == "Bearer tok-1"
    f.done()
    assert dsm.check_ins == []                                  # it was not checked out, so there is nothing to check in


def test_delinea_checks_a_checked_out_secret_in_again(dsm):
    f = run(d_entry(dsm, secret_id_ref="2000"))
    assert f.values["password"] == "pw-dsm-2" and dsm.check_ins == []
    f.done()
    f.done()
    assert dsm.check_ins == ["2000"]


def test_delinea_refusals_are_sentences_without_secrets(dsm):
    cases = [({"app_password": "wrong"}, "refused the application user"), ({"secret_id_ref": "9999"}, "no such secret"), ({"secret_id_ref": "3000"}, "no user name and password")]
    for over, text in cases:
        with pytest.raises(pam.PamError, match=text) as exc:
            run(d_entry(dsm, **over))
        assert "app-pw" not in str(exc.value) and "pw-dsm" not in str(exc.value)
    dsm.deny.add("1234")
    with pytest.raises(pam.PamError, match="may not read"):
        run(d_entry(dsm))


@pytest.mark.parametrize("bad", ["12a", "", "1 or 1", "../x", "1234/check-in"])
def test_delinea_secret_ids_are_numbers_only(dsm, bad):
    with pytest.raises(pam.PamError):
        run(d_entry(dsm, secret_id_ref=bad))
    assert not dsm.requests


# ------------------------------------------------------------------ BeyondTrust
def test_beyondtrust_signs_in_requests_reads_and_checks_in_and_out(bt):
    f = run(b_entry(bt), reason="INC-5")
    assert f.values == {"username": "svc", "password": "pw-bt-1"} and f.lease == "request 4711"
    paths = [(r["method"], r["path"].split("v3")[1]) for r in bt.requests]
    assert paths[:4] == [("POST", "/Auth/SignAppIn"), ("GET", "/ManagedAccounts"), ("POST", "/Requests"), ("GET", "/Credentials/4711")]
    request = [r for r in bt.requests if r["path"].endswith("/Requests")][0]["body"]
    assert request["AccessType"] == "View" and request["ConflictOption"] == "reuse" and request["DurationMinutes"] == 5 and "INC-5" in request["Reason"] and "[nl-" in request["Reason"]
    assert bt.check_ins == [] and bt.signouts == 0               # held for the login attempt
    f.done()
    assert bt.check_ins == ["4711"] and bt.signouts == 1
    f.done()
    assert bt.signouts == 1


def test_beyondtrust_session_cookie_is_used_for_every_later_call(bt):
    run(b_entry(bt)).done()
    later = [r for r in bt.requests if not r["path"].endswith("SignAppIn")]
    assert later and all("ASP.NET_SessionId=sess-" in r["headers"].get("Cookie", "") for r in later)


def test_beyondtrust_signs_out_when_something_fails_and_says_why(bt):
    bt.needs_approval = True
    with pytest.raises(pam.PamError, match="pending approval|need approval|refused the request") as exc:
        run(b_entry(bt))
    assert "pw-bt" not in str(exc.value) and bt.signouts == 1 and bt.check_ins == ["4711"]
    bt.needs_approval = False
    with pytest.raises(pam.PamError, match="refused the API registration"):
        run(b_entry(bt, api_key="WRONG"))
    with pytest.raises(pam.PamError, match="no such managed account"):
        run(b_entry(bt, ps_account="nobody"))


@pytest.mark.parametrize("field", ["api_key", "run_as", "ps_system", "ps_account"])
def test_beyondtrust_values_cannot_break_the_auth_header_or_query(bt, field):
    with pytest.raises(pam.PamError, match="may not contain"):
        run(b_entry(bt, **{field: "x; runas=admin"}))
    assert not bt.requests


# ------------------------------------------------------------------ the hold, through the store
def test_the_store_holds_a_checked_out_password_until_the_login_attempt_is_over(dsm, tmp_path):
    conn = connect(tmp_path / "c.db")
    init_db(conn)
    made = credstore.create(conn, "anna", "Checked out", "pam", {k: v for k, v in d_entry(dsm, secret_id_ref="2000").items() if k not in ("id", "name", "kind")}, shared=True)
    shown = json.dumps(credstore.listing(conn, "anna"))
    assert "app-pw" not in shown and made["pam"]["where"] == "secret 2000" and made["has_secret"]
    got = credstore.resolve(conn, "anna", made["id"], "SSH terminal", "", "web01")
    assert got["password"] == "pw-dsm-2" and "app_password" not in got
    assert dsm.check_ins == []                                  # still held: the login attempt is under way
    pam.release_all()
    assert dsm.check_ins == ["2000"]                            # and checked in afterwards (here: forced, normally after 90 seconds)
    conn.close()
