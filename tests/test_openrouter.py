import json

import pytest
from fastapi.testclient import TestClient

from app import engineer, licence, openrouter
from app.config import load_settings
from app.db import connect, get_setting, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


def entry(id, prompt="0", completion="0", context=128000, out=("text",), tools=True):
    return {"id": id, "name": id, "context_length": context, "pricing": {"prompt": prompt, "completion": completion},
            "architecture": {"input_modalities": ["text"], "output_modalities": list(out)}, "supported_parameters": ["tools"] if tools else []}


CATALOGUE = {"data": [entry("a/big:free"), entry("b/small:free", context=8000), entry("c/paid", "0.000001", "0.000002"), entry("d/music", out=("audio",)),
                      entry("e/notools:free", tools=False), entry("f/weird", prompt="n/a")]}


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    openrouter._cache.update(at=0.0, models=None)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    return c


def fetch_of(doc):
    return lambda: doc


def test_only_free_text_models_with_room_are_listed(conn):
    ids = [m["id"] for m in openrouter.free_models(conn, fetch_of(CATALOGUE))]
    assert ids == ["a/big:free", "e/notools:free"]          # tools first, then the rest


def test_tested_models_come_first_and_poor_ones_last(conn):
    openrouter.catalogue(fetch_of(CATALOGUE))
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (openrouter.TESTS_KEY, json.dumps({"e/notools:free": {"verdict": "good", "passed": 6, "total": 6, "at": "t"}, "a/big:free": {"verdict": "poor", "passed": 1, "total": 6, "at": "t"}})))
    assert [m["id"] for m in openrouter.free_models(conn)] == ["e/notools:free", "a/big:free"]


def test_run_test_stores_the_verdict_and_forgets_vanished_models(conn):
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (openrouter.TESTS_KEY, json.dumps({"x/gone:free": {"verdict": "good", "passed": 6, "total": 6, "at": "t"}})))
    result = openrouter.run_test(conn, "a/big:free", "key", fetch_of(CATALOGUE), ask=lambda messages: "no")
    assert result["model"] == "a/big:free" and result["verdict"] in ("good", "usable", "poor")
    stored = openrouter.tests(conn)
    assert set(stored) == {"a/big:free"} and stored["a/big:free"]["total"] == result["total"]
    with pytest.raises(openrouter.OpenRouterError):
        openrouter.run_test(conn, "c/paid", "key", fetch_of(CATALOGUE), ask=lambda m: "no")


def test_use_saves_the_model_and_starts_the_watch(conn):
    openrouter.use(conn, "a/big:free", "sk-1", fetch_of(CATALOGUE))
    cfg = engineer.settings(conn)
    assert (cfg["url"], cfg["model"], cfg["enabled"], cfg["has_key"]) == (openrouter.URL, "a/big:free", True, True)
    assert openrouter.watch_state(conn)["state"] == "ok"
    with pytest.raises(openrouter.OpenRouterError):
        openrouter.use(conn, "c/paid", None, fetch_of(CATALOGUE))


def test_the_watch_raises_one_event_when_the_model_goes_and_again_when_it_is_back(conn):
    openrouter.use(conn, "a/big:free", "sk-1", fetch_of(CATALOGUE))
    events = lambda: [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'llm_model_unavailable'")]
    assert openrouter.watch(conn, fetch_of(CATALOGUE), force=True)["state"] == "ok" and events() == []
    gone = {"data": [e for e in CATALOGUE["data"] if e["id"] != "a/big:free"]}
    assert openrouter.watch(conn, fetch_of(gone), force=True)["state"] == "gone"
    assert openrouter.watch(conn, fetch_of(gone), force=True)["state"] == "gone"
    assert len(events()) == 1 and "not offered" in events()[0]
    paid = {"data": [entry("a/big:free", "0.1", "0.1")]}
    assert openrouter.watch(conn, fetch_of(paid), force=True)["state"] == "paid" and len(events()) == 2
    assert openrouter.watch(conn, fetch_of(CATALOGUE), force=True)["state"] == "ok"


def test_the_watch_is_once_a_day_and_offline_is_not_gone(conn):
    openrouter.use(conn, "a/big:free", None, fetch_of(CATALOGUE))
    openrouter.watch(conn, fetch_of(CATALOGUE), force=True)
    calls = []

    def broken():
        calls.append(1)
        raise openrouter.OpenRouterError("offline")

    assert openrouter.watch(conn, broken)["state"] == "ok" and calls == []           # looked at a moment ago
    assert openrouter.watch(conn, broken, force=True)["state"] == "ok" and calls == [1]


def test_choosing_a_model_by_hand_ends_the_watch(conn):
    openrouter.use(conn, "a/big:free", None, fetch_of(CATALOGUE))
    engineer.save_settings(conn, {"model": "my-own-model"})
    assert openrouter.watch_state(conn) is None
    assert openrouter.watch(conn, fetch_of({"data": []}), force=True) is None


def test_other_servers_are_never_watched(conn):
    engineer.save_settings(conn, {"url": "http://192.168.0.5:8080/v1", "model": "qwen", "enabled": True})
    assert openrouter.watch_state(conn) is None


def test_api_list_test_and_use(tmp_path, monkeypatch):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    monkeypatch.setattr(openrouter, "_get", lambda url, timeout=15.0: CATALOGUE)
    with TestClient(app) as c:
        listing = c.get("/api/engineer/openrouter?refresh=true", headers=ADMIN).json()
        assert [m["id"] for m in listing["models"]] == ["a/big:free", "e/notools:free"] and listing["watch"] is None
        assert c.post("/api/engineer/openrouter/use", json={"model": "c/paid"}, headers=ADMIN).status_code == 422
        assert c.post("/api/engineer/openrouter/use", json={"model": "a/big:free", "api_key": "sk-1"}, headers=ADMIN).json()["model"] == "a/big:free"
        assert c.get("/api/engineer/openrouter", headers=ADMIN).json()["watch"]["state"] == "ok"
        monkeypatch.setattr(openrouter, "_get", lambda url, timeout=15.0: {"data": []})
        openrouter.watch(connect(tmp_path / "t.db"), force=True)
        after = c.get("/api/engineer/openrouter?refresh=true", headers=ADMIN).json()
        assert after["watch"]["state"] == "gone" and "not offered" in after["watch_message"]
        attention = c.get("/api/dashboard", headers=ADMIN).json()["attention"]
        assert any("not offered on OpenRouter" in a["text"] for a in attention)


def test_api_needs_a_licence_to_use_a_model(tmp_path, monkeypatch):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    monkeypatch.setattr(openrouter, "_get", lambda url, timeout=15.0: CATALOGUE)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "engineer")
    with TestClient(app) as c:
        assert c.post("/api/engineer/openrouter/use", json={"model": "a/big:free"}, headers=ADMIN).status_code == 402
        assert c.post("/api/engineer/openrouter/test", json={"model": "a/big:free"}, headers=ADMIN).status_code == 402


def test_openrouter_404_and_429_have_plain_messages(monkeypatch):
    import io
    import urllib.error

    def boom(code):
        def fake(request, timeout=0):
            raise urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))
        return fake

    for code, word in ((404, "no provider"), (429, "busy")):
        monkeypatch.setattr("urllib.request.urlopen", boom(code))
        with pytest.raises(engineer.EngineerError, match=word):
            engineer.chat_with(openrouter.URL, "m", "k", [{"role": "user", "content": "x"}])


def test_busy_server_makes_the_exam_inconclusive_and_stores_nothing(conn, monkeypatch):
    from app import modelcheck

    monkeypatch.setattr(modelcheck, "_sleep", lambda s: None)

    def busy(messages):
        raise engineer.EngineerError("the language model is busy or its free allowance for today is used up (HTTP 429): try again later")

    with pytest.raises(openrouter.OpenRouterError, match="could not be tested"):
        openrouter.run_test(conn, "a/big:free", "k", fetch_of(CATALOGUE), ask=busy)
    assert openrouter.tests(conn) == {}


def test_a_busy_server_is_waited_for_and_a_plain_text_reply_gets_one_reminder(monkeypatch):
    from app import modelcheck

    waits = []
    monkeypatch.setattr(modelcheck, "_sleep", waits.append)
    calls = []

    def flaky(messages):
        calls.append(messages[-1]["content"])
        if len(calls) == 1:
            raise engineer.EngineerError("busy (HTTP 429)")
        if modelcheck.NUDGE not in messages[-1]["content"]:
            return "The offline devices are all of them."          # plain text first
        return '{"answer": "ok"}'

    reply, reminded = modelcheck._step(None, flaky, [{"role": "user", "content": "q"}])
    assert reply == '{"answer": "ok"}' and reminded is True and waits == [4.0] and len(calls) == 3
