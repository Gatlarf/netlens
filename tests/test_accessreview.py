"""The access review and the signed evidence pack: findings in plain words, no secrets, a pack that proves itself."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import accessreview, licence, secpolicy
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    real = licence.allows
    state = {"privileged": True, "mfa_policy": True, "teams": True, "customer_views": True}
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: state[feature] if feature in state else real(conn, feature, now))
    secpolicy.forget()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        for name, role in (("alice", "admin"), ("bella", "admin"), ("olga", "operator"), ("vera", "viewer")):
            assert c.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code == 201
        yield app, tmp_path / "t.db", state, c
    secpolicy.forget()


def test_the_report_says_who_has_access_and_what_is_wrong(env):
    app, path, state, c = env
    conn = connect(path)
    old = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE users SET last_login = ?, created = ? WHERE username = 'olga'", (old, old))
    conn.execute("UPDATE users SET totp_enabled = 1 WHERE username = 'bella'")
    conn.commit()
    tok = c.post(f"/api/users/{conn.execute('SELECT id FROM users WHERE username = ?', ('alice',)).fetchone()[0]}/tokens", json={"name": "ci"}, headers=ADMIN).json()["token"]
    rep = c.get("/api/access-review", headers=ADMIN).json()
    by = {p["username"]: p for p in rep["people"]}
    assert by["bella"]["has_second_factor"] and by["bella"]["second_factor"] == "authenticator app" and not by["alice"]["has_second_factor"] and by["alice"]["second_factor"] == "none"
    texts = [f["text"] for f in rep["findings"]]
    assert any("alice is an administrator without a second factor" in t for t in texts)
    assert any("olga (operator) has not signed in for 20" in t for t in texts)
    assert any("API token 'ci' can change things and never expires" in t for t in texts)
    assert any("a second factor is not required of anybody" in t for t in texts)
    assert rep["findings"][0]["level"] == "bad" and rep["totals"]["administrators"] == 2 and rep["totals"]["without_second_factor"] >= 2
    blob = json.dumps(rep)
    assert tok not in blob and "password_hash" not in blob and "scrypt" not in blob and "totp_secret" not in blob


def test_the_csv_is_safe_to_open_in_a_spreadsheet():
    person = {"username": "=cmd|' /C calc'!A0", "role": "viewer", "custom_role": "@x", "source": "local", "second_factor": "none", "disabled": False, "break_glass": False, "customer_view": False,
              "last_login": None, "days_since_login": None, "sessions_open": 0, "tokens": []}
    text = accessreview.csv_text({"people": [person]})
    assert "'=cmd" in text.splitlines()[1]
    assert ",=cmd" not in text and ",@x" not in text


def test_the_pack_is_signed_recorded_and_checked(env):
    app, path, state, c = env
    doc = c.post("/api/access-review/pack", headers=ADMIN)
    assert doc.status_code == 200
    doc = doc.json()
    assert doc["format"] == "netlens-access-review-v1" and len(doc["sha256"]) == 64 and len(doc["signature"]) == 64
    audit = " ".join(r["action"] for r in c.get("/api/audit", headers=ADMIN).json()["entries"])
    assert doc["sha256"][:24] in audit
    ok = c.post("/api/access-review/verify", json=doc, headers=ADMIN).json()
    assert ok["ok"] and ok["in_audit_log"] is True
    forged = json.loads(json.dumps(doc))
    forged["report"]["people"][0]["role"] = "viewer"
    assert c.post("/api/access-review/verify", json=forged, headers=ADMIN).json() == {"ok": False, "why": "the content does not match its hash: it was changed"}
    resigned = json.loads(json.dumps(forged))
    resigned["sha256"] = accessreview.hashlib.sha256(accessreview._canonical(resigned["report"])).hexdigest()
    assert "not from this installation" in c.post("/api/access-review/verify", json=resigned, headers=ADMIN).json()["why"]          # a new hash without the key is no use
    assert c.post("/api/access-review/verify", json={"x": 1}, headers=ADMIN).json()["ok"] is False


def test_a_review_can_be_recorded_and_the_dashboard_reminds(env):
    app, path, state, c = env
    from app import dashboard

    assert c.put("/api/security-policy", json={"review_days": 90}, headers=ADMIN).status_code == 200
    conn = connect(path)
    assert [p for p in dashboard.current_problems(conn) if "access review" in p["text"]]
    r = c.post("/api/access-review/complete", json={"comment": "checked all admins, removed bob"}, headers=ADMIN)
    assert r.status_code == 200 and r.json()["by"] == "access token"
    secpolicy.forget()
    assert not [p for p in dashboard.current_problems(conn) if "access review" in p["text"]]
    assert c.get("/api/access-review", headers=ADMIN).json()["last_review"]["comment"].startswith("checked all admins")
    assert "Completed the access review" in " ".join(r["action"] for r in c.get("/api/audit", headers=ADMIN).json()["entries"])


def test_who_may_read_it_and_the_licence(env):
    app, path, state, c = env
    vera = TestClient(app)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.get("/api/access-review").status_code == 403
    c.post("/api/roles", json={"name": "Reviewer", "base": "viewer", "grants": ["access_review"]}, headers=ADMIN)
    vid = connect(path).execute("SELECT id FROM users WHERE username = 'vera'").fetchone()[0]
    assert c.patch(f"/api/users/{vid}", json={"custom_role": "reviewer"}, headers=ADMIN).status_code == 200
    vera = TestClient(app)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.get("/api/access-review").status_code == 200 and vera.get("/api/access-review.csv").status_code == 200
    assert vera.post("/api/access-review/pack").status_code == 403 and vera.post("/api/access-review/complete", json={}).status_code == 403       # reading only
    state["privileged"] = False
    assert c.get("/api/access-review", headers=ADMIN).status_code == 402
