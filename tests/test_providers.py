import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from app import engineer, licence, providers
from app.config import load_settings
from app.db import connect, get_setting, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.mark.parametrize("url,expected", [
    ("https://api.anthropic.com/v1", "anthropic"), ("https://api.openai.com/v1", "openai"), ("https://generativelanguage.googleapis.com/v1beta/openai", "google"),
    ("https://api.mistral.ai/v1", "mistral"), ("https://api.x.ai/v1", "xai"), ("https://openrouter.ai/api/v1", "openrouter"), ("https://api.groq.com/openai/v1", "groq"),
    ("http://192.168.0.115:11434/v1", "local"), ("http://localhost:8080/v1", "local"), ("https://llm.example.com/v1", "custom"), ("", ""),
])
def test_the_address_tells_the_provider(url, expected):
    assert providers.detect(url) == expected


def test_models_are_listed_with_the_right_credentials_and_only_chat_models():
    seen = {}

    def fake(url, headers):
        seen["url"], seen["headers"] = url, headers
        return {"data": [{"id": "gpt-4o"}, {"id": "text-embedding-3-small"}, {"id": "whisper-1"}, {"id": "gpt-5"}, {"id": "dall-e-3"}, {"id": "gpt-4o-mini"}]}

    models = providers.list_models("https://api.openai.com/v1", "sk-test", fake)
    assert [m["id"] for m in models] == ["gpt-5", "gpt-4o-mini", "gpt-4o"] or models[0]["id"] == "gpt-5"
    assert {m["id"] for m in models} == {"gpt-5", "gpt-4o", "gpt-4o-mini"}
    assert seen["url"] == "https://api.openai.com/v1/models" and seen["headers"]["Authorization"] == "Bearer sk-test"

    providers.list_models("https://api.anthropic.com/v1", "sk-ant-x", fake)
    assert seen["headers"]["x-api-key"] == "sk-ant-x" and "Authorization" not in seen["headers"] and seen["url"].endswith("/models?limit=100")

    gem = providers.list_models("https://generativelanguage.googleapis.com/v1beta/openai", "k", lambda u, h: {"data": [{"id": "models/gemini-2.5-flash"}, {"id": "models/text-embedding-004"}]})
    assert [m["id"] for m in gem] == ["gemini-2.5-flash"]


def test_listing_needs_a_key_for_cloud_providers_and_explains_refusals():
    with pytest.raises(providers.ProviderError, match="API key first"):
        providers.list_models("https://api.anthropic.com/v1", None, lambda u, h: {})
    providers.list_models("http://192.168.0.5:11434/v1", None, lambda u, h: {"data": [{"id": "llama3.1:8B"}]})         # a local server needs none

    def refuse(u, h):
        raise urllib.error.HTTPError(u, 401, "x", {}, io.BytesIO(b""))

    with pytest.raises(providers.ProviderError, match="refused the API key"):
        providers.list_models("https://api.openai.com/v1", "bad", refuse)
    with pytest.raises(providers.ProviderError, match="no models"):
        providers.list_models("https://api.x.ai/v1", "k", lambda u, h: {"data": []})


class Capture:
    def __init__(self, *replies):
        self.replies, self.requests = list(replies), []

    def __call__(self, request, timeout=0):
        self.requests.append((request.full_url, dict((k.lower(), v) for k, v in request.header_items()), json.loads(request.data.decode())))
        reply = self.replies.pop(0)
        if isinstance(reply, int):
            raise urllib.error.HTTPError(request.full_url, reply, "x", {}, io.BytesIO(b'{"error": {"message": "max_tokens is not supported, use max_completion_tokens"}}'))
        return io.BytesIO(json.dumps(reply).encode())


def test_anthropic_uses_its_own_api(monkeypatch):
    cap = Capture({"content": [{"type": "text", "text": "ready"}]})
    monkeypatch.setattr("urllib.request.urlopen", cap)
    out = engineer.chat_with("https://api.anthropic.com/v1", "claude-haiku-5-5", "sk-ant-x",
                             [{"role": "system", "content": "be brief"}, {"role": "user", "content": "one"}, {"role": "user", "content": "two"}])
    assert out == "ready"
    url, headers, body = cap.requests[0]
    assert url == "https://api.anthropic.com/v1/messages" and headers["x-api-key"] == "sk-ant-x" and headers["anthropic-version"] == "2023-06-01" and "authorization" not in headers
    assert body["system"] == "be brief" and body["model"] == "claude-haiku-5-5" and body["messages"] == [{"role": "user", "content": "one\n\ntwo"}] and body["max_tokens"] == 4096


def test_anthropic_drops_the_temperature_when_a_model_refuses_it(monkeypatch):
    class Refuse(Capture):
        def __call__(self, request, timeout=0):
            self.requests.append((request.full_url, {}, json.loads(request.data.decode())))
            if "temperature" in self.requests[-1][2]:
                raise urllib.error.HTTPError(request.full_url, 400, "x", {}, io.BytesIO(b'{"error": {"message": "temperature is deprecated for this model"}}'))
            return io.BytesIO(json.dumps({"content": [{"type": "text", "text": "ok"}]}).encode())

    cap = Refuse()
    monkeypatch.setattr("urllib.request.urlopen", cap)
    assert engineer.chat_with("https://api.anthropic.com/v1", "m", "k", [{"role": "user", "content": "x"}]) == "ok"
    assert "temperature" in cap.requests[0][2] and "temperature" not in cap.requests[1][2]


def test_openai_gets_the_newer_parameter_and_other_servers_the_classic_one(monkeypatch):
    cap = Capture({"choices": [{"message": {"content": "a"}}]}, {"choices": [{"message": {"content": "b"}}]})
    monkeypatch.setattr("urllib.request.urlopen", cap)
    engineer.chat_with("https://api.openai.com/v1", "gpt-5", "k", [{"role": "user", "content": "x"}])
    engineer.chat_with("https://api.mistral.ai/v1", "mistral-large-latest", "k", [{"role": "user", "content": "x"}])
    assert "max_completion_tokens" in cap.requests[0][2] and "temperature" not in cap.requests[0][2]
    assert "max_tokens" in cap.requests[1][2] and cap.requests[1][2]["temperature"] == 0.1 and cap.requests[1][1]["authorization"] == "Bearer k"


def test_a_server_that_wants_the_other_token_parameter_is_asked_again(monkeypatch):
    cap = Capture(400, {"choices": [{"message": {"content": "fine"}}]})
    monkeypatch.setattr("urllib.request.urlopen", cap)
    assert engineer.chat_with("https://llm.example.com/v1", "m", None, [{"role": "user", "content": "x"}]) == "fine"
    assert "max_tokens" in cap.requests[0][2] and "max_completion_tokens" in cap.requests[1][2] and "max_tokens" not in cap.requests[1][2]


def test_a_refused_key_and_a_missing_model_are_said_plainly(monkeypatch):
    for code, word in ((401, "refused the API key"), (404, "not available to this key")):
        monkeypatch.setattr("urllib.request.urlopen", Capture(code))
        with pytest.raises(engineer.EngineerError, match=word):
            engineer.chat_with("https://api.anthropic.com/v1", "claude-x", "k", [{"role": "user", "content": "x"}])


def test_a_key_is_never_carried_over_to_another_provider(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    engineer.save_settings(conn, {"url": "https://api.openai.com/v1", "model": "gpt-5", "api_key": "sk-openai"})
    assert engineer.settings(conn)["has_key"] and engineer.settings(conn)["provider"] == "openai"
    engineer.save_settings(conn, {"model": "gpt-4o", "url": "https://api.openai.com/v1"})
    assert engineer.settings(conn)["has_key"]                                              # same provider: kept
    engineer.save_settings(conn, {"url": "https://api.anthropic.com/v1", "model": "claude-sonnet-5-5"})
    assert not engineer.settings(conn)["has_key"] and engineer.settings(conn)["provider"] == "anthropic"      # another provider: forgotten
    engineer.save_settings(conn, {"url": "https://api.x.ai/v1", "api_key": "sk-xai"})
    assert engineer.settings(conn)["has_key"]                                              # a new key typed along with it is kept


def test_api_lists_providers_and_models_and_never_lends_the_saved_key(tmp_path, monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    calls = []
    monkeypatch.setattr(providers, "_get", lambda url, headers: (calls.append((url, headers)), {"data": [{"id": "claude-sonnet-5-5"}]})[1])
    with TestClient(app) as c:
        listing = c.get("/api/engineer/providers", headers=ADMIN).json()
        assert [p["id"] for p in listing["providers"]][:2] == ["anthropic", "openai"] and listing["current"] == ""
        assert all("prefer" not in p for p in listing["providers"])
        c.put("/api/engineer", json={"url": "https://api.anthropic.com/v1", "model": "claude-sonnet-5-5", "api_key": "sk-ant-saved"}, headers=ADMIN)
        assert c.get("/api/engineer", headers=ADMIN).json()["provider"] == "anthropic"
        ok = c.post("/api/engineer/models", json={"url": "https://api.anthropic.com/v1"}, headers=ADMIN).json()
        assert ok["models"][0]["id"] == "claude-sonnet-5-5" and calls[-1][1]["x-api-key"] == "sk-ant-saved"
        other = c.post("/api/engineer/models", json={"url": "https://api.openai.com/v1"}, headers=ADMIN)
        assert other.status_code == 422 and "API key first" in other.json()["detail"]            # the Anthropic key is not tried on OpenAI
        assert len(calls) == 1
