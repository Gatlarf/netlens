"""Custom roles: a base role plus read-only capabilities, from a catalogue in the code. Nothing here may become a way to administrator."""

import re

import pytest
from fastapi.testclient import TestClient

from app import assistant, licence, roles, secpolicy, stepup
from app.config import load_settings
from app.db import connect
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


# ------------------------------------------------------------------ the catalogue
def test_every_capability_matches_only_the_routes_it_is_meant_to():
    """The catalogue is checked against the real routes of the application: each capability reaches only GET routes, and exactly these."""
    import tempfile

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tempfile.mkdtemp() + "/i.db")
    routes = [(method.upper(), re.sub(r"\{[^}]+\}", "1", path)) for path, ops in app.openapi()["paths"].items() for method in ops]
    expected = {"audit": {"/api/audit", "/api/audit.csv", "/api/audit/integrity"}, "reports": {"/api/reports/availability", "/api/reports/availability.csv", "/api/reports/weekly", "/api/reports/monthly"},
                "backups": {"/api/backups"}, "access_review": {"/api/access-review", "/api/access-review.csv"}, "vulnerabilities": {"/api/vulns"}, "storage": {"/api/storage"}, "dns": {"/api/dns"}, "inventory": {"/api/inventory"}}
    assert set(roles.CATALOG) == set(expected)
    for cap, rx in roles._COMPILED.items():
        hit = {(m, p) for m, p in routes if rx.match(p)}
        assert {p for _, p in hit} == expected[cap], cap                                  # exactly the intended paths exist and are matched
        assert {m for m, _ in hit} <= {"GET", "HEAD"}, (cap, hit)                         # and none of them changes anything


def test_no_capability_reaches_what_needs_step_up_or_what_an_assistant_may_never_reach():
    sensitive = ["/api/credentials", "/api/users", "/api/roles", "/api/vault/status", "/api/ingest", "/api/sso", "/api/security-policy", "/api/restore", "/api/central", "/api/hosts",
                 "/api/terminal/1/ws", "/api/remote", "/api/siem", "/api/sbom", "/api/backup", "/api/settings", "/api/licence", "/api/mcp", "/api/assistant/token", "/api/me/totp"]
    for cap, rx in roles._COMPILED.items():
        for path in sensitive:
            assert not rx.match(path), (cap, path)
    for method, path in (("PUT", "/api/roles/x"), ("POST", "/api/roles"), ("DELETE", "/api/roles/x"), ("POST", "/api/credentials")):
        assert stepup.protected(method, path), path
    assert assistant.NEVER.match("/api/roles")


def test_the_role_rules():
    from app.db import connect as db_connect, init_db
    import tempfile, os

    path = os.path.join(tempfile.mkdtemp(), "r.db")
    conn = db_connect(path)
    init_db(conn)
    for bad in (("", "viewer", []), ("x" * 41, "viewer", []), ("Ok", "admin", []), ("Ok", "viewer", ["terminal"]), ("Ok", "viewer", "audit"), ("admin", "viewer", []), ("Ok", "viewer", [1])):
        with pytest.raises(roles.RoleError):
            roles.save(conn, *bad)
    made = roles.save(conn, "Auditor", "viewer", ["audit", "reports", "audit"])
    assert made == {"id": "auditor", "name": "Auditor", "base": "viewer", "grants": ["audit", "reports"]}
    with pytest.raises(roles.RoleError, match="exists"):
        roles.save(conn, "auditor", "viewer", [])
    for n in range(roles.MAX_ROLES - 1):
        roles.save(conn, f"R{n}", "viewer", [])
    with pytest.raises(roles.RoleError, match="at most"):
        roles.save(conn, "One too many", "viewer", [])


# ------------------------------------------------------------------ through the API
@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "mfa_policy": True, "teams": True, "customer_views": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as admin:
        for name, role in (("vera", "viewer"), ("olga", "operator"), ("cara", "viewer"), ("adam", "admin")):
            assert admin.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code == 201, name
        yield app, path, state, admin
    secpolicy.forget()


def signin(app, name):
    c = TestClient(app)
    assert c.post("/api/login", json={"username": name, "password": "longenough1"}).status_code == 200
    return c


def uid(path, name):
    c = connect(path)
    try:
        return c.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()[0]
    finally:
        c.close()


def test_an_auditor_reads_the_audit_log_and_nothing_else(env):
    app, path, state, admin = env
    vera = signin(app, "vera")
    assert vera.get("/api/audit").status_code == 403 and vera.get("/api/audit/integrity").status_code == 403           # a plain viewer cannot
    made = admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit", "reports"]}, headers=ADMIN)
    assert made.status_code == 201 and made.json()["roles"][0]["id"] == "auditor"
    assert admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": "auditor"}, headers=ADMIN).status_code == 200
    vera = signin(app, "vera")
    assert vera.get("/api/audit").status_code == 200 and vera.get("/api/audit.csv").status_code == 200
    assert vera.get("/api/audit/integrity?run=true").json()["result"]["ok"] is True
    assert vera.get("/api/reports/monthly").status_code != 403
    session = vera.get("/api/session").json()["user"]
    assert session["role"] == "viewer" and sorted(session["grants"]) == ["audit", "reports"]
    for method, path_ in (("get", "/api/credentials"), ("get", "/api/users"), ("get", "/api/roles"), ("get", "/api/ingest"), ("get", "/api/dns"), ("get", "/api/backups"), ("post", "/api/audit"),
                          ("put", "/api/security-policy"), ("post", "/api/credentials"), ("delete", "/api/users/1"), ("get", "/api/vault/status"), ("get", "/api/sbom")):
        r = getattr(vera, method)(path_, **({"json": {}} if method in ("post", "put") else {}))
        assert r.status_code in (403, 404, 405), (method, path_, r.status_code)


def test_the_base_role_still_applies_and_an_operator_keeps_acting(env):
    app, path, state, admin = env
    admin.post("/api/roles", json={"name": "Ops reader", "base": "operator", "grants": ["dns", "storage"]}, headers=ADMIN)
    assert admin.patch(f"/api/users/{uid(path, 'olga')}", json={"custom_role": "ops-reader"}, headers=ADMIN).status_code == 200
    olga = signin(app, "olga")
    assert olga.get("/api/dns").status_code == 200 and olga.get("/api/storage").status_code == 200
    assert olga.get("/api/maintenance").status_code == 200                                    # the operator's own reading
    assert olga.get("/api/audit").status_code == 200                                          # operators read the audit log anyway
    assert olga.get("/api/credentials").status_code == 403
    users = admin.get("/api/users", headers=ADMIN).json()
    row = next(u for u in users["users"] if u["username"] == "olga")
    assert row["role"] == "operator" and row["custom_role"] == "ops-reader"


def test_a_lapsed_licence_returns_the_user_to_the_base_role_without_deleting_anything(env):
    app, path, state, admin = env
    admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit"]}, headers=ADMIN)
    admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": "auditor"}, headers=ADMIN)
    vera = signin(app, "vera")
    assert vera.get("/api/audit").status_code == 200
    state["privileged"] = False
    assert vera.get("/api/audit").status_code == 403 and "grants" not in vera.get("/api/session").json()["user"]
    assert admin.post("/api/roles", json={"name": "Another", "base": "viewer", "grants": []}, headers=ADMIN).status_code == 402
    assert admin.patch(f"/api/users/{uid(path, 'cara')}", json={"custom_role": "auditor"}, headers=ADMIN).status_code == 402
    assert admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": ""}, headers=ADMIN).status_code == 200       # taking a role away is always allowed
    assert admin.get("/api/roles", headers=ADMIN).json()["roles"][0]["id"] == "auditor"
    state["privileged"] = True
    assert signin(app, "vera").get("/api/audit").status_code == 403                                   # it was taken away


def test_who_may_manage_and_hold_roles(env):
    app, path, state, admin = env
    vera = signin(app, "vera")
    assert vera.get("/api/roles").status_code == 403 and vera.post("/api/roles", json={"name": "x"}).status_code == 403
    for body in ({"name": "", "base": "viewer", "grants": []}, {"name": "X", "base": "admin", "grants": []}, {"name": "X", "base": "viewer", "grants": ["credentials"]}):
        assert admin.post("/api/roles", json=body, headers=ADMIN).status_code == 422, body
    admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit"]}, headers=ADMIN)
    assert admin.patch(f"/api/users/{uid(path, 'adam')}", json={"custom_role": "auditor"}, headers=ADMIN).status_code == 422             # an administrator already may everything
    assert admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": "nope"}, headers=ADMIN).status_code == 422
    group = admin.post("/api/groups", json={"name": "Customer A"}, headers=ADMIN)
    assert group.status_code in (200, 201), group.text
    gid = group.json().get("id") or group.json()["groups"][-1]["id"]
    assert admin.patch(f"/api/users/{uid(path, 'cara')}", json={"scope": [gid]}, headers=ADMIN).status_code == 200
    assert admin.patch(f"/api/users/{uid(path, 'cara')}", json={"custom_role": "auditor"}, headers=ADMIN).status_code == 422       # a customer view cannot hold one


def test_changing_a_role_moves_its_users_and_removing_it_keeps_their_base(env):
    app, path, state, admin = env
    admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit"]}, headers=ADMIN)
    admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": "auditor"}, headers=ADMIN)
    assert admin.put("/api/roles/auditor", json={"name": "Auditor", "base": "operator", "grants": ["audit", "dns"]}, headers=ADMIN).status_code == 200
    conn = connect(path)
    assert conn.execute("SELECT role FROM users WHERE username = 'vera'").fetchone()[0] == "operator"
    assert signin(app, "vera").get("/api/dns").status_code == 200
    assert admin.delete("/api/roles/auditor", headers=ADMIN).status_code == 200
    row = conn.execute("SELECT role, custom_role FROM users WHERE username = 'vera'").fetchone()
    assert row["role"] == "operator" and row["custom_role"] is None
    assert signin(app, "vera").get("/api/dns").status_code == 403
    assert admin.delete("/api/roles/auditor", headers=ADMIN).status_code == 404
    admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit"]}, headers=ADMIN)
    admin.patch(f"/api/users/{uid(path, 'cara')}", json={"custom_role": "auditor"}, headers=ADMIN)
    assert admin.patch(f"/api/users/{uid(path, 'cara')}", json={"role": "viewer"}, headers=ADMIN).status_code == 200                 # an explicit plain role ends it
    assert conn.execute("SELECT custom_role FROM users WHERE username = 'cara'").fetchone()[0] is None


def test_a_token_of_a_user_with_a_role_carries_the_extra_reading_but_a_read_only_token_still_only_reads(env):
    app, path, state, admin = env
    admin.post("/api/roles", json={"name": "Auditor", "base": "viewer", "grants": ["audit"]}, headers=ADMIN)
    admin.patch(f"/api/users/{uid(path, 'vera')}", json={"custom_role": "auditor"}, headers=ADMIN)
    token = admin.post(f"/api/users/{uid(path, 'vera')}/tokens", json={"name": "siem"}, headers=ADMIN).json()["token"]
    c = TestClient(app)
    assert c.get("/api/audit", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert c.get("/api/credentials", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    assert c.post("/api/roles", json={"name": "x"}, headers={"Authorization": f"Bearer {token}"}).status_code == 403
