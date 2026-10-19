"""The language model providers a user can pick in Settings → AI, with their addresses and a live list of their models.

Everything speaks the OpenAI chat protocol except Anthropic, whose own API (app/engineer.py) is used. The list of models is always read from the provider
with the user's key, because model names change all the time; nothing here is a fixed list except the addresses.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

PROVIDERS: list[dict[str, Any]] = [
    {"id": "anthropic", "name": "Anthropic (Claude)", "url": "https://api.anthropic.com/v1", "key_url": "https://console.anthropic.com/settings/keys",
     "prefer": [r"sonnet-5", r"haiku-5", r"opus-5", r"fable-5", r"sonnet-4", r"haiku-4"]},
    {"id": "openai", "name": "OpenAI (ChatGPT)", "url": "https://api.openai.com/v1", "key_url": "https://platform.openai.com/api-keys",
     "prefer": [r"^gpt-5", r"^gpt-4\.1", r"^gpt-4o", r"^o\d"]},
    {"id": "google", "name": "Google (Gemini)", "url": "https://generativelanguage.googleapis.com/v1beta/openai", "key_url": "https://aistudio.google.com/apikey",
     "prefer": [r"gemini-\d+(\.\d+)?-pro", r"gemini-\d+(\.\d+)?-flash"]},
    {"id": "mistral", "name": "Mistral (Le Chat)", "url": "https://api.mistral.ai/v1", "key_url": "https://console.mistral.ai/api-keys",
     "prefer": [r"mistral-large", r"mistral-medium", r"mistral-small"]},
    {"id": "xai", "name": "xAI (Grok)", "url": "https://api.x.ai/v1", "key_url": "https://console.x.ai", "prefer": [r"^grok-\d"]},
    {"id": "deepseek", "name": "DeepSeek", "url": "https://api.deepseek.com/v1", "key_url": "https://platform.deepseek.com/api_keys", "prefer": [r"deepseek-chat"]},
    {"id": "groq", "name": "Groq (fast, has a free tier)", "url": "https://api.groq.com/openai/v1", "key_url": "https://console.groq.com/keys", "prefer": [r"70b", r"120b"]},
    {"id": "openrouter", "name": "OpenRouter (many models, some free)", "url": "https://openrouter.ai/api/v1", "key_url": "https://openrouter.ai/settings/keys", "prefer": []},
    {"id": "local", "name": "My own server (Ollama, llama.cpp, LM Studio)", "url": "http://localhost:11434/v1", "key_url": "", "prefer": []},
    {"id": "custom", "name": "Other (any OpenAI-compatible address)", "url": "", "key_url": "", "prefer": []},
]
BY_ID = {p["id"]: p for p in PROVIDERS}
NOT_CHAT = re.compile(r"embed|whisper|tts|dall-e|image|moderation|audio|realtime|transcribe|ocr|guard|rerank|imagen|video|aqa|speech|instruct$|davinci|babbage|search", re.I)


class ProviderError(RuntimeError):
    pass


def public() -> list[dict[str, Any]]:
    return [{k: v for k, v in p.items() if k != "prefer"} for p in PROVIDERS]


def detect(url: str) -> str:
    """Which preset an address belongs to ('' when none is set)."""
    host = (urlparse(url or "").hostname or "").lower()
    if not host:
        return ""
    for p in PROVIDERS:
        if p["url"] and urlparse(p["url"]).hostname == host:
            return p["id"]
    try:
        ip = ipaddress.ip_address(host)
        return "local" if ip.is_private or ip.is_loopback else "custom"
    except ValueError:
        return "local" if host in ("localhost", "host.docker.internal") or host.endswith((".local", ".lan", ".home")) else "custom"


def host_of(url: str) -> str:
    return (urlparse(url or "").hostname or "").lower()


def _order(provider: str, ids: list[str]) -> list[str]:
    prefer = [re.compile(x, re.I) for x in BY_ID.get(provider, {}).get("prefer", [])]

    def rank(model: str) -> tuple:
        for n, rx in enumerate(prefer):
            if rx.search(model):
                return (n, "".join(chr(255 - ord(c)) for c in model))      # newest-looking (highest) name first within a family
        return (len(prefer), "".join(chr(255 - ord(c)) for c in model))

    return sorted(dict.fromkeys(ids), key=rank)


def list_models(url: str, key: str | None, fetch: Callable[[str, dict], dict] | None = None) -> list[dict[str, str]]:
    """The chat models the provider offers this key right now: [{id, name}], the most likely choices first."""
    url = (url or "").strip().rstrip("/")
    if not re.match(r"^https?://[^\s/]+", url):
        raise ProviderError("fill in the address first")
    provider = detect(url)
    headers: dict[str, str] = {"User-Agent": "Netlens", "Accept": "application/json"}
    if key:
        if provider == "anthropic":
            headers.update({"x-api-key": key, "anthropic-version": "2023-06-01"})
        else:
            headers["Authorization"] = f"Bearer {key}"
    elif provider not in ("local", "custom", "openrouter"):
        raise ProviderError("enter your API key first: the provider only lists models to someone with a key")
    target = url + "/models" + ("?limit=100" if provider == "anthropic" else "")
    try:
        doc = (fetch or _get)(target, headers)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ProviderError("the provider refused the API key") from None
        raise ProviderError(f"the provider answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ProviderError(f"cannot reach {host_of(url)}: {getattr(exc, 'reason', exc)}") from None
    rows = doc.get("data") if isinstance(doc, dict) else doc
    names: dict[str, str] = {}
    for m in rows or []:
        if isinstance(m, dict) and m.get("id"):
            mid = str(m["id"]).removeprefix("models/")
            if provider != "local" and NOT_CHAT.search(mid):
                continue
            names[mid] = str(m.get("display_name") or mid)
    if not names:
        raise ProviderError("the provider listed no models for this key")
    return [{"id": i, "name": names[i]} for i in _order(provider, list(names))]


def _get(url: str, headers: dict) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as resp:        # noqa: S310 - the address is the administrator's own setting
        return json.loads(resp.read(4_000_000).decode("utf-8", "replace"))
