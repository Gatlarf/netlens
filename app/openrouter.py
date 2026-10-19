"""Free language models on OpenRouter: a live list, a test with Netlens's own exams, and a watch that tells you when the chosen model goes away.

OpenRouter's free models change all the time: they are added, renamed, limited or withdrawn without notice. So nothing here is a fixed list. The list is read from
OpenRouter's public catalogue when the page asks (and cached for an hour), "best suited" means "passed the exams of app/modelcheck.py on this installation", and
once a day the model you chose is looked up again. When it is gone, or no longer free, an event `llm_model_unavailable` is raised (once) and the dashboard says so.
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

from app import engineer, modelcheck
from app.db import add_event, get_setting, set_setting, utcnow

URL = "https://openrouter.ai/api/v1"
CATALOGUE = URL + "/models"
MIN_CONTEXT = 32_000                        # the instructions Netlens sends are short, but a model with less room than this cannot hold a question and its data
CACHE_SECONDS = 3600
WATCH_EVERY = 20 * 3600
TESTS_KEY, WATCH_KEY, SOURCE_KEY, WATCHED_AT = "openrouter.tests", "openrouter.watch", "engineer.source", "openrouter.watched_at"
RANK = {"good": 0, "usable": 1, "poor": 3, None: 2}      # untested models sit between usable and poor: they may be fine, nobody has checked
_cache: dict[str, Any] = {"at": 0.0, "models": None}


class OpenRouterError(RuntimeError):
    pass


def _get(url: str, timeout: float = 15.0) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "Netlens", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:        # noqa: S310 - fixed https address
            return json.loads(resp.read(8_000_000).decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OpenRouterError(f"cannot read OpenRouter's list of models: {getattr(exc, 'reason', exc)}") from None


def _free(entry: dict) -> bool:
    price = entry.get("pricing") or {}
    try:
        return float(price.get("prompt", 1)) == 0 and float(price.get("completion", 1)) == 0
    except (TypeError, ValueError):
        return False


def _usable(entry: dict) -> bool:
    arch = entry.get("architecture") or {}
    text_in = "text" in (arch.get("input_modalities") or ["text"])
    text_out = (arch.get("output_modalities") or ["text"]) == ["text"] or "text" in (arch.get("output_modalities") or [])
    return bool(entry.get("id")) and text_in and text_out and (entry.get("context_length") or 0) >= MIN_CONTEXT


def catalogue(fetch: Callable[[], dict] | None = None, force: bool = False) -> list[dict]:
    """Every model OpenRouter lists right now: [{id, name, context, free, tools}]. Cached for an hour."""
    if not force and _cache["models"] is not None and time.monotonic() - _cache["at"] < CACHE_SECONDS:
        return _cache["models"]
    data = (fetch or (lambda: _get(CATALOGUE)))()
    models = [
        {"id": m["id"], "name": m.get("name") or m["id"], "context": m.get("context_length") or 0, "free": _free(m),
         "tools": "tools" in (m.get("supported_parameters") or []), "usable": _usable(m)}
        for m in data.get("data", []) if isinstance(m, dict) and m.get("id")
    ]
    _cache.update(at=time.monotonic(), models=models)
    return models


def tests(conn: sqlite3.Connection) -> dict[str, dict]:
    try:
        stored = json.loads(get_setting(conn, TESTS_KEY) or "{}")
    except ValueError:
        return {}
    return stored if isinstance(stored, dict) else {}


def free_models(conn: sqlite3.Connection, fetch: Callable[[], dict] | None = None, force: bool = False) -> list[dict]:
    """The free, text-only models with enough room, best tested first. Each carries its last exam result on this installation (or None)."""
    done = tests(conn)
    out = [{**m, "test": done.get(m["id"])} for m in catalogue(fetch, force) if m["free"] and m["usable"]]
    out.sort(key=lambda m: (RANK[(m["test"] or {}).get("verdict")], not m["tools"], -m["context"], m["id"]))
    return out


def run_test(conn: sqlite3.Connection, model: str, key: str | None, fetch: Callable[[], dict] | None = None, ask: Callable[[list[dict]], str] | None = None) -> dict:
    """Run the six exams against one free model (about 8 calls: free models allow only a few dozen a day, so one model at a time)."""
    known = {m["id"]: m for m in catalogue(fetch)}
    if model not in known or not known[model]["free"]:
        raise OpenRouterError("OpenRouter does not list this model as free right now")
    ask = ask or (lambda messages: engineer.chat_with(URL, model, key, messages, timeout=120.0))
    result = modelcheck.run(conn, ask)
    result["model"] = model
    if result["inconclusive"]:
        raise OpenRouterError("OpenRouter was busy or its free allowance for today is used up, so this model could not be tested. Nothing was saved; try again later.")
    stored = tests(conn)
    stored[model] = {"verdict": result["verdict"], "passed": result["passed"], "total": result["total"], "at": utcnow()}
    for gone in [m for m in stored if m not in known]:      # forget exams of models that no longer exist
        del stored[gone]
    set_setting(conn, TESTS_KEY, json.dumps(stored))
    return result


def use(conn: sqlite3.Connection, model: str, key: str | None, fetch: Callable[[], dict] | None = None) -> dict:
    """Make a free OpenRouter model the language model of Netlens (the digital engineer and Insights)."""
    known = {m["id"]: m for m in catalogue(fetch)}
    if model not in known or not known[model]["free"]:
        raise OpenRouterError("OpenRouter does not list this model as free right now")
    engineer.save_settings(conn, {"url": URL, "model": model, "enabled": True, **({"api_key": key} if key else {})})
    set_setting(conn, SOURCE_KEY, "openrouter-free")
    set_setting(conn, WATCH_KEY, json.dumps({"state": "ok", "model": model, "at": utcnow()}))
    return engineer.settings(conn)


def watch_state(conn: sqlite3.Connection) -> dict | None:
    """{state: 'ok'|'gone'|'paid', model, at} for a chosen OpenRouter free model; None when another kind of model is in use."""
    cfg = engineer.settings(conn)
    if urlparse(cfg["url"]).hostname != "openrouter.ai" or get_setting(conn, SOURCE_KEY) != "openrouter-free":
        return None
    try:
        state = json.loads(get_setting(conn, WATCH_KEY) or "null")
    except ValueError:
        state = None
    return state if isinstance(state, dict) and state.get("model") == cfg["model"] else {"state": "ok", "model": cfg["model"], "at": None}


def watch(conn: sqlite3.Connection, fetch: Callable[[], dict] | None = None, force: bool = False) -> dict | None:
    """Once a day: is the chosen free model still offered, and still free? Raises one event when it stops being so."""
    state = watch_state(conn)
    if state is None:
        return None
    last = get_setting(conn, WATCHED_AT)
    if not force and last and time.time() - float(last) < WATCH_EVERY:
        return state
    try:
        known = {m["id"]: m for m in catalogue(fetch, force=True)}
    except OpenRouterError:
        return state          # offline is not "gone"
    set_setting(conn, WATCHED_AT, str(time.time()))
    model = state["model"]
    now = "gone" if model not in known else ("ok" if known[model]["free"] else "paid")
    if now != state["state"]:
        set_setting(conn, WATCH_KEY, json.dumps({"state": now, "model": model, "at": utcnow()}))
        if now != "ok":
            add_event(conn, "llm_model_unavailable", message(model, now))
        state = {"state": now, "model": model, "at": utcnow()}
    return state


def message(model: str, state: str) -> str:
    if state == "gone":
        return f"The language model {model} is not offered on OpenRouter any more. Choose another in Settings → AI → Language model."
    return f"The language model {model} is no longer free on OpenRouter. Choose another in Settings → AI → Language model, or add credit to your OpenRouter account."
