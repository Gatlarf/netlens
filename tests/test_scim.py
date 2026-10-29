"""SCIM 2.0 provisioning: the provider can make and remove its own accounts, nobody else's, and never an administrator."""

import pytest
from fastapi.testclient import TestClient

from app import licence, oidc, secpolicy
from app.config import load_settings
from app.db import connect
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "sso": True, "teams": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        assert c.post("/api/users", json={"username": "alice", "password": "longenough1", "role": "admin"}, headers=ADMIN).status_code == 201
        token = c.post("/api/scim/token", json={"name": "entra"}, headers=ADMIN).json()["token"]
        assert c.put("/api/scim", json={"enabled": True}, headers=ADMIN).status_code == 200
        yield app, tmp_path / "t.db", state, c, {"Authorization": f"Bearer {token}"}
    secpolicy.forget()


def user_body(name="anna@example.com", **over):
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": name, "externalId": "ext-" + name, "emails": [{"value": name, "primary": True}], "displayName": "Anna", "active": True, **over}


def test_joiners_are_created_with_the_default_role_and_never_as_administrator(env):
    app, path, state, c, scim_h = env
    r = c.post("/scim/v2/Users", json=user_body(), headers=scim_h)
    assert r.status_code == 201 and r.headers["content-type"].startswith("application/scim+json")
    made = r.json()
    assert made["userName"] == "anna@example.com" and made["active"] is True and made["emails"][0]["value"] == "anna@example.com" and made["id"].isdigit()
    row = connect(path).execute("SELECT * FROM users WHERE id = ?", (int(made["id"]),)).fetchone()
    assert row["role"] == "viewer" and row["scim_managed"] == 1 and row["username"] == "anna" and row["password_hash"]
    assert c.post("/scim/v2/Users", json=user_body(roles=[{"value": "admin"}], role="admin"), headers=scim_h).status_code == 409        # duplicate: and a role in the body is never read
    assert c.put("/api/scim", json={"role": "admin"}, headers=ADMIN).status_code == 422
    assert c.put("/api/scim", json={"role": "operator"}, headers=ADMIN).status_code == 200
    second = c.post("/scim/v2/Users", json=user_body("bo@example.com"), headers=scim_h).json()
    assert connect(path).execute("SELECT role FROM users WHERE id = ?", (int(second["id"]),)).fetchone()[0] == "operator"
    assert c.post("/scim/v2/Users", json={"userName": ""}, headers=scim_h).status_code == 400
    assert c.post("/scim/v2/Users", json={"userName": "x\ny"}, headers=scim_h).status_code == 400


def test_the_token_and_the_networks_guard_the_door(env):
    app, path, state, c, scim_h = env
    assert c.get("/scim/v2/Users").status_code == 401
    assert c.get("/scim/v2/Users", headers={"Authorization": "Bearer nlscim_wrong"}).status_code == 401
    assert c.get("/scim/v2/Users", headers=ADMIN).status_code == 401                                      # the access token is not a SCIM token
    assert c.get("/scim/v2/Users", headers=scim_h).status_code == 200
    assert c.put("/api/scim", json={"networks": ["10.9.0.0/16"]}, headers=ADMIN).status_code == 200
    assert c.get("/scim/v2/Users", headers=scim_h).status_code == 401                                     # the test client is not in that network
    c.put("/api/scim", json={"networks": []}, headers=ADMIN)
    for _ in range(5):                                                                                       # five wrong tokens from one address and the sixth try is refused outright
        c.get("/scim/v2/Users", headers={"Authorization": "Bearer nlscim_wrong"})
    assert c.get("/scim/v2/Users", headers=scim_h).status_code == 429
    app.state.login_limiter.reset("testclient")
    assert c.put("/api/scim", json={"networks": ["nope"]}, headers=ADMIN).status_code == 422
    fresh = c.post("/api/scim/token", json={}, headers=ADMIN).json()["token"]
    assert c.get("/scim/v2/Users", headers=scim_h).status_code == 401 and c.get("/scim/v2/Users", headers={"Authorization": f"Bearer {fresh}"}).status_code == 200
    c.delete("/api/scim/token", headers=ADMIN)
    assert c.get("/scim/v2/Users", headers={"Authorization": f"Bearer {fresh}"}).status_code == 401


def test_the_provider_cannot_touch_local_accounts_or_the_last_administrator(env):
    app, path, state, c, scim_h = env
    conn = connect(path)
    alice = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    assert c.get(f"/scim/v2/Users/{alice}", headers=scim_h).status_code == 404
    assert c.patch(f"/scim/v2/Users/{alice}", json={"Operations": [{"op": "replace", "path": "active", "value": False}]}, headers=scim_h).status_code == 404
    assert c.delete(f"/scim/v2/Users/{alice}", headers=scim_h).status_code == 404
    assert c.get("/scim/v2/Users", headers=scim_h).json()["totalResults"] == 0                           # it sees only what it made
    made = c.post("/scim/v2/Users", json=user_body(), headers=scim_h).json()
    conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (int(made["id"]),))                    # an administrator promoted it (and alice goes)
    conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (alice,))
    conn.commit()
    r = c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "replace", "path": "active", "value": "False"}]}, headers=scim_h)
    assert r.status_code == 409 and "last administrator" in r.json()["detail"]
    assert c.delete(f"/scim/v2/Users/{made['id']}", headers=scim_h).status_code == 409


def test_leavers_are_deactivated_with_their_sessions_ended_in_the_shapes_the_big_providers_send(env):
    app, path, state, c, scim_h = env
    made = c.post("/scim/v2/Users", json=user_body(), headers=scim_h).json()
    conn = connect(path)
    conn.execute("INSERT INTO sessions (token_hash, user_id, created, expires, seq) VALUES ('x', ?, '2026-10-29T10:00:00Z', '2099-01-01T00:00:00Z', 1)", (int(made["id"]),))
    conn.commit()
    entra = c.patch(f"/scim/v2/Users/{made['id']}", json={"schemas": [scim_patch := "urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}, headers=scim_h)
    assert entra.status_code == 200 and entra.json()["active"] is False
    assert conn.execute("SELECT disabled FROM users WHERE id = ?", (int(made["id"]),)).fetchone()[0] == 1 and conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (int(made["id"]),)).fetchone()[0] == 0
    okta = c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "replace", "value": {"active": True}}]}, headers=scim_h)
    assert okta.json()["active"] is True
    renamed = c.put(f"/scim/v2/Users/{made['id']}", json=user_body("anna@example.com", displayName="Anna B", active=True), headers=scim_h)
    assert renamed.status_code == 200 and renamed.json()["displayName"] == "Anna B"
    assert c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": []}, headers=scim_h).status_code == 400
    assert c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "move"}]}, headers=scim_h).status_code == 400
    assert c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "replace", "path": "active", "value": "maybe"}]}, headers=scim_h).status_code == 400
    assert c.delete(f"/scim/v2/Users/{made['id']}", headers=scim_h).status_code == 204
    assert c.get(f"/scim/v2/Users/{made['id']}", headers=scim_h).status_code == 404


def test_filters_paging_and_discovery(env):
    app, path, state, c, scim_h = env
    for n in ("a", "b", "c"):
        c.post("/scim/v2/Users", json=user_body(f"{n}@example.com"), headers=scim_h)
    listing = c.get("/scim/v2/Users", params={"startIndex": 2, "count": 1}, headers=scim_h).json()
    assert listing["totalResults"] == 3 and listing["itemsPerPage"] == 1 and listing["startIndex"] == 2
    one = c.get("/scim/v2/Users", params={"filter": 'userName eq "B@example.com"'}, headers=scim_h).json()
    assert one["totalResults"] == 1 and one["Resources"][0]["userName"] == "b@example.com"
    assert c.get("/scim/v2/Users", params={"filter": 'externalId eq "ext-c@example.com"'}, headers=scim_h).json()["totalResults"] == 1
    for bad in ('userName co "a"', 'userName eq "a" or x', 'userName eq "a" --'):
        r = c.get("/scim/v2/Users", params={"filter": bad}, headers=scim_h)
        assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter", bad
    assert c.get("/scim/v2/ServiceProviderConfig", headers=scim_h).json()["patch"]["supported"] is True
    assert c.get("/scim/v2/ResourceTypes", headers=scim_h).status_code == 200 and c.get("/scim/v2/Schemas", headers=scim_h).status_code == 200


def test_without_the_licence_people_can_still_leave_but_not_join(env):
    app, path, state, c, scim_h = env
    made = c.post("/scim/v2/Users", json=user_body(), headers=scim_h).json()
    state["privileged"] = False
    r = c.post("/scim/v2/Users", json=user_body("new@example.com"), headers=scim_h)
    assert r.status_code == 403 and "Enterprise" in r.json()["detail"]
    assert c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "replace", "path": "active", "value": False}]}, headers=scim_h).status_code == 200
    assert c.delete(f"/scim/v2/Users/{made['id']}", headers=scim_h).status_code == 204
    assert c.post("/api/scim/token", json={}, headers=ADMIN).status_code == 402


def test_everything_is_in_the_audit_log_without_the_token(env):
    app, path, state, c, scim_h = env
    c.post("/scim/v2/Users", json=user_body(), headers=scim_h)
    c.get("/scim/v2/Users/999", headers=scim_h)
    entries = c.get("/api/audit", headers=ADMIN).json()["entries"]
    text = " ".join(e["action"] for e in entries)
    assert "SCIM: created the account 'anna@example.com'" in text and "SCIM refused" in text and scim_h["Authorization"][7:] not in text
    assert "token" in text and "shown once" in text


def test_a_provisioned_person_is_matched_at_their_first_single_sign_on(env):
    app, path, state, c, scim_h = env
    made = c.post("/scim/v2/Users", json=user_body("anna@example.com", externalId="sub-anna"), headers=scim_h).json()
    conn = connect(path)
    cfg = {"groups_claim": "groups", "admin_groups": "", "default_role": "viewer", "group_map": []}
    from app import users

    cookie = oidc.sign_in(conn, {"sub": "sub-anna", "preferred_username": "anna.b", "email": "anna@example.com", "groups": []}, cfg)
    row = users.user_for_session(conn, cookie)
    assert row["id"] == int(made["id"]) and conn.execute("SELECT oidc_sub FROM users WHERE id = ?", (row["id"],)).fetchone()[0] == "sub-anna"
    # matched by e-mail only when the provider vouches for it
    made2 = c.post("/scim/v2/Users", json=user_body("bo@example.com", externalId="elsewhere"), headers=scim_h).json()
    c2 = oidc.sign_in(conn, {"sub": "sub-bo", "email": "bo@example.com", "email_verified": False, "groups": []}, cfg)
    assert users.user_for_session(conn, c2)["id"] != int(made2["id"])
    made3 = c.post("/scim/v2/Users", json=user_body("cy@example.com", externalId="x3"), headers=scim_h).json()
    c3 = oidc.sign_in(conn, {"sub": "sub-cy", "email": "cy@example.com", "email_verified": True, "groups": []}, cfg)
    assert users.user_for_session(conn, c3)["id"] == int(made3["id"])
    # a deactivated account cannot sign in
    c.patch(f"/scim/v2/Users/{made['id']}", json={"Operations": [{"op": "replace", "path": "active", "value": False}]}, headers=scim_h)
    with pytest.raises(oidc.OidcError, match="disabled"):
        oidc.sign_in(conn, {"sub": "sub-anna", "groups": []}, cfg)
