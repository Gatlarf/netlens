"""The tamper-evident audit log: every line is linked to the one before it with a keyed hash; changes, insertions and removals show; pruning keeps what is left verifiable."""

import json
import threading

import pytest
from fastapi.testclient import TestClient

from app import audit, auditchain
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "a.db")
    init_db(c)
    yield c
    c.close()


def lines(conn, n=6, start=0):
    for i in range(start, start + n):
        audit.record(conn, "anna", "admin", "10.0.0.1", "POST", f"/api/x/{i}", 200, f"Did thing {i}")


def test_an_untouched_log_verifies_and_every_line_carries_a_chain_value(conn):
    lines(conn)
    assert all(len(r[0]) == 64 for r in conn.execute("SELECT chain FROM audit_log"))
    r = auditchain.verify(conn)
    assert r["ok"] and r["checked"] == 6 and r["problem"] is None and r["head"]["id"] == 6 and r["unchained"] == 0
    assert auditchain.last_result(conn)["ok"]


@pytest.mark.parametrize("sql,kind", [
    ("UPDATE audit_log SET action = 'Did nothing' WHERE id = 3", "broken"),
    ("UPDATE audit_log SET user = 'mallory' WHERE id = 2", "broken"),
    ("UPDATE audit_log SET status = 200, ts = '2020-01-01T00:00:00Z' WHERE id = 4", "broken"),
    ("DELETE FROM audit_log WHERE id = 3", "broken"),
    ("UPDATE audit_log SET chain = NULL WHERE id = 5", "unchained"),
    ("UPDATE audit_log SET chain = '" + "0" * 64 + "' WHERE id = 6", "broken"),
    ("INSERT INTO audit_log (id, ts, user, role, ip, method, path, status, action) VALUES (7, '2026-10-29T10:00:00Z', 'x', '', '', 'POST', '/p', 200, 'forged')", "unchained"),
])
def test_every_kind_of_tampering_is_found(conn, sql, kind):
    lines(conn)
    conn.execute(sql)
    conn.commit()
    r = auditchain.verify(conn)
    assert not r["ok"] and r["problem"]["kind"] == kind and r["problem"]["id"] >= 2


def test_a_forged_insert_with_a_guessed_chain_is_found_without_the_key(conn):
    lines(conn)
    head = conn.execute("SELECT chain FROM audit_log WHERE id = 6").fetchone()[0]
    import hashlib

    conn.execute("INSERT INTO audit_log (id, ts, user, role, ip, method, path, status, action, chain) VALUES (7, 't', 'x', '', '', 'POST', '/p', 200, 'forged', ?)", (hashlib.sha256(head.encode()).hexdigest(),))
    conn.commit()
    assert auditchain.verify(conn)["problem"]["kind"] == "broken"


def test_lines_from_before_the_chain_existed_are_counted_not_failed(conn):
    for i in range(3):
        conn.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES ('2026-01-01T00:00:00Z', 'old', '', '', 'POST', '/p', 200, ?)", (f"old {i}",))
    conn.commit()
    lines(conn, 3)
    r = auditchain.verify(conn)
    assert r["ok"] and r["unchained"] == 3 and r["checked"] == 3


def test_pruning_keeps_the_rest_verifiable_and_an_edit_after_it_is_still_found(conn):
    lines(conn, 10)
    assert auditchain.prune(conn, None, 4) == 6                                     # keep the newest four
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 4
    r = auditchain.verify(conn)
    assert r["ok"] and r["checked"] == 4
    lines(conn, 2, 10)
    assert auditchain.verify(conn)["ok"]
    conn.execute("UPDATE audit_log SET action = 'edited' WHERE id = 9")
    conn.commit()
    assert not auditchain.verify(conn)["ok"]


def test_the_retention_job_prunes_through_the_chain(conn):
    from app import dbmaint

    lines(conn, 5)
    conn.execute("UPDATE audit_log SET ts = '2000-01-01T00:00:00Z' WHERE id <= 3")          # old enough to go (these lines are removed, so their ts is no longer checked)
    conn.commit()
    assert dbmaint.purge(conn)["audit"] == 3
    r = auditchain.verify(conn)
    assert r["ok"] and r["checked"] == 2


def test_the_dry_run_removes_nothing(conn):
    lines(conn, 6)
    assert auditchain.prune(conn, None, 2, dry_run=True) == 4
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 6


def test_writers_in_several_threads_still_make_one_chain(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)

    def work(tag):
        own = connect(path)
        for i in range(25):
            audit.record(own, tag, "admin", "", "POST", "/p", 200, f"{tag} {i}")
        own.close()

    threads = [threading.Thread(target=work, args=(f"t{n}",)) for n in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    r = auditchain.verify(c)
    assert r["ok"] and r["checked"] == 100
    c.close()


def test_a_different_key_cannot_verify_and_says_so(conn, monkeypatch):
    lines(conn)
    from app import vault

    monkeypatch.setattr(vault, "derive_key", lambda conn_, purpose: b"\x01" * 32)
    r = auditchain.verify(conn)
    assert not r["ok"] and "key was replaced" in r["problem"]["text"]


def test_a_failure_to_link_never_loses_the_line(conn, monkeypatch):
    from app import vault

    monkeypatch.setattr(vault, "derive_key", lambda c, p: (_ for _ in ()).throw(vault.VaultError("no key")))
    lines(conn, 2)
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE chain IS NULL").fetchone()[0] == 2


# ------------------------------------------------------------------ anchors, events, the API
def test_the_anchor_holds_the_head_and_a_removed_line_it_names_is_found(conn):
    lines(conn, 4)
    assert auditchain.anchor(conn) is True
    assert auditchain.anchor(conn) is False                                              # nothing new since
    anchor_line = conn.execute("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0]
    head = conn.execute("SELECT chain FROM audit_log WHERE id = 4").fetchone()[0]
    assert anchor_line == f"Audit chain anchor: row 4, chain {head}"
    assert auditchain.verify(conn)["anchors_checked"] == 1
    lines(conn, 1, 9)
    assert auditchain.anchor(conn) is True and auditchain.verify(conn)["anchors_checked"] == 2


def test_a_failed_check_raises_one_critical_event_and_a_problem(conn):
    from app import dashboard

    lines(conn, 4)
    conn.execute("UPDATE audit_log SET action = 'edited' WHERE id = 2")
    conn.commit()
    auditchain.check(conn)
    auditchain.check(conn)                                                               # the same failure is not reported twice
    events = conn.execute("SELECT kind, detail FROM events WHERE kind = 'audit_tampered'").fetchall()
    assert len(events) == 1 and "line 2" in events[0]["detail"]
    assert [p for p in dashboard.current_problems(conn) if "integrity" in p["text"]]


def test_the_api_reports_and_runs_the_check(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        c.post("/api/users", json={"username": "anna", "password": "longenough1", "role": "admin"}, headers=ADMIN)
        r = c.get("/api/audit/integrity?run=true", headers=ADMIN).json()
        assert r["result"]["ok"] and r["result"]["checked"] >= 1
        conn = connect(tmp_path / "t.db")
        conn.execute("UPDATE audit_log SET action = 'edited' WHERE id = 1")
        conn.commit()
        conn.close()
        bad = c.get("/api/audit/integrity?run=true", headers=ADMIN).json()["result"]
        assert not bad["ok"] and bad["problem"]["id"] == 1
        assert c.get("/api/audit/integrity", headers=ADMIN).json()["result"]["ok"] is False          # the stored result is the latest one
        # a plain user cannot read it
        c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=ADMIN)
        v = TestClient(app)
        v.post("/api/login", json={"username": "vera", "password": "longenough1"})
        assert v.get("/api/audit/integrity").status_code in (401, 403)
