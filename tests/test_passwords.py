"""Password hygiene: the commonest passwords and trivial patterns are refused, and the policy can ask for a longer minimum."""

import pytest
from fastapi.testclient import TestClient

from app import licence, passwords, secpolicy, users
from app.config import load_settings
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.mark.parametrize("pw", ["password", "Password1", "PASSWORD123", "12345678", "qwertyuiop", "iloveyou1", "P@ssw0rd", "pass-word 123", "11111111", "abababab", "01234567890", "98765432109", "Netlens123"])
def test_the_commonest_and_trivial_passwords_are_refused(pw):
    with pytest.raises(users.UserError):
        users.check_password(pw)


def test_a_password_that_is_the_user_name_is_refused():
    with pytest.raises(users.UserError, match="user name"):
        users.check_password("Alice-Admin", "alice-admin")


@pytest.mark.parametrize("pw", ["longenough1", "correct horse battery 99", "another-longer-1", "Tr0ub4dor&3x", "blue-Giraffe-sings-42"])
def test_ordinary_good_passwords_are_accepted(pw):
    assert users.check_password(pw) == pw


def test_the_length_rules_are_unchanged_and_the_policy_can_raise_the_minimum():
    with pytest.raises(users.UserError, match="at least 8"):
        users.check_password("short-1")
    with pytest.raises(users.UserError, match="at least 15"):
        users.check_password("only-twelve-ch", minimum=15)
    assert users.check_password("fourteen-chars-ok", minimum=14)
    with pytest.raises(users.UserError, match="too long"):
        users.check_password("x-" * 200)


def test_the_policy_minimum_is_enforced_for_new_users_and_password_changes_and_is_an_enterprise_setting(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        assert c.put("/api/security-policy", json={"min_password": 3}, headers=ADMIN).status_code == 422
        assert c.put("/api/security-policy", json={"min_password": 14}, headers=ADMIN).json()["policy"]["min_password"] == 14
        assert c.get("/api/users", headers=ADMIN).json()["min_password"] == 14
        r = c.post("/api/users", json={"username": "ann", "password": "twelve-chars", "role": "viewer"}, headers=ADMIN)
        assert r.status_code == 422 and "at least 14" in r.json()["detail"]
        assert c.post("/api/users", json={"username": "ann", "password": "fourteen-chars-ok", "role": "viewer"}, headers=ADMIN).status_code == 201
        uid = c.get("/api/users", headers=ADMIN).json()["users"][0]["id"]
        assert c.patch(f"/api/users/{uid}", json={"password": "short-pass-1"}, headers=ADMIN).status_code == 422
        state["privileged"] = False
        assert c.put("/api/security-policy", json={"min_password": 8}, headers=ADMIN).status_code == 402          # lowering it needs the edition too
        assert c.get("/api/users", headers=ADMIN).json()["min_password"] == 14                                    # and the policy in force stays in force
    secpolicy.forget()
