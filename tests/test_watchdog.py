import asyncio

from fastapi.testclient import TestClient

from app import watchdog
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


def test_problem_none_for_a_readable_database(tmp_path):
    db = tmp_path / "t.db"
    init_db(connect(db))
    assert watchdog.problem(db) is None


def test_problem_when_database_cannot_be_opened(tmp_path):
    assert "database" in watchdog.problem(tmp_path / "missing" / "t.db")


def test_problem_when_descriptors_run_out(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    init_db(connect(db))
    monkeypatch.setattr(watchdog, "open_files", lambda: (950, 1000))
    assert "file descriptors" in watchdog.problem(db)


def test_loop_ends_the_process_after_the_strikes(tmp_path):
    died = []
    asyncio.run(watchdog.loop(tmp_path / "missing" / "t.db", die=lambda: died.append(1), every=0, strikes=3))
    assert died == [1]


def test_loop_forgives_a_short_problem(tmp_path, monkeypatch):
    answers = iter(["bad", None, "bad", None])
    calls = []

    def fake(_):
        try:
            return next(answers)
        except StopIteration:
            raise asyncio.CancelledError

    monkeypatch.setattr(watchdog, "problem", fake)
    try:
        asyncio.run(watchdog.loop("x", die=lambda: calls.append(1), every=0, strikes=2))
    except asyncio.CancelledError:
        pass
    assert calls == []


def test_health_is_503_when_unwell(tmp_path, monkeypatch):
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=str(tmp_path / "t.db"))
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        monkeypatch.setattr(watchdog, "problem", lambda _: "no descriptors")
        res = client.get("/api/health", headers={"Authorization": "Bearer nope"}, cookies={})
        assert res.status_code == 503 and res.json() == {"status": "unwell"}          # a stranger learns nothing more
        res = client.get("/api/health", headers={"Authorization": "Bearer t"})
        assert res.status_code == 503 and res.json()["problem"] == "no descriptors"
