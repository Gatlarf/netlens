"""The digital engineer (a paid feature): an LLM that reads an incident and says what it thinks is wrong and which of YOUR rules would fix it.

It never runs anything and never invents an action: it is given the rules an administrator wrote (by name and kind of action, not their commands) and
can only recommend one of them, or none. A rule in the mode `engineer` is approved only when the engineer recommends exactly that rule with high
confidence; every other case waits for a person. Any OpenAI-compatible server works (a local one such as llama.cpp, Ollama or LM Studio, or a hosted
one with your own key). What is sent can be made anonymous: addresses, MAC addresses and names are replaced by placeholders before they leave.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

from app.db import get_setting, set_setting, utcnow

KEYS = ("engineer.enabled", "engineer.url", "engineer.model", "engineer.api_key", "engineer.redact")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IPV6 = re.compile(r"(?<![\w:])[0-9a-fA-F:]*:[0-9a-fA-F:]*:[0-9a-fA-F:.]*(?![\w:])")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
SYSTEM = (
    "You are a careful network and systems engineer helping an administrator. You are given one incident from a network monitor: the event, facts about the device, "
    "its recent events, related checks and earlier automatic fixes, and a numbered list of RULES the administrator wrote (each rule is a fixed action). "
    "Decide what is most likely wrong and whether one of the rules is an appropriate fix. Never invent commands and never recommend a rule that is not in the list. "
    "If the evidence is weak, or the problem looks like something a restart will not fix (a cable, power, a network outage upstream), recommend no rule. "
    'Answer with ONLY a JSON object: {"diagnosis": "...", "confidence": "low|medium|high", "recommended_rule_id": <number or null>, "reasoning": "...", "next_steps": ["..."]}'
)


def _is_v6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(text)
        return True
    except ValueError:
        return False


class EngineerError(RuntimeError):
    pass


def settings(conn: sqlite3.Connection) -> dict[str, Any]:
    return {"enabled": get_setting(conn, "engineer.enabled") == "1", "url": get_setting(conn, "engineer.url") or "", "model": get_setting(conn, "engineer.model") or "",
            "has_key": bool(get_setting(conn, "engineer.api_key")), "redact": get_setting(conn, "engineer.redact") != "0"}


def save_settings(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    if "url" in data:
        url = str(data["url"] or "").strip().rstrip("/")
        if url and not re.match(r"^https?://[^\s/]+", url):
            raise EngineerError("the address must start with http:// or https://")
        set_setting(conn, "engineer.url", url)
    if "model" in data:
        set_setting(conn, "engineer.model", str(data["model"] or "").strip()[:100])
    if data.get("api_key"):
        set_setting(conn, "engineer.api_key", str(data["api_key"]).strip())
    if data.get("clear_key"):
        conn.execute("DELETE FROM settings WHERE key = 'engineer.api_key'")
        conn.commit()
    if "enabled" in data:
        set_setting(conn, "engineer.enabled", "1" if data["enabled"] else "0")
    if "redact" in data:
        set_setting(conn, "engineer.redact", "1" if data["redact"] else "0")
    return settings(conn)


class Redactor:
    """Consistent placeholders: the same address or name gets the same token everywhere in one request."""

    def __init__(self, names: list[str]):
        self.map: dict[str, str] = {}
        self.names = sorted({n for n in names if n and len(n) > 2}, key=len, reverse=True)

    def token(self, value: str, prefix: str) -> str:
        return self.map.setdefault(value.lower(), f"<{prefix}{sum(1 for v in self.map.values() if v.startswith('<' + prefix)) + 1}>")

    def __call__(self, text: str) -> str:
        for name in self.names:
            text = re.sub(re.escape(name), lambda m: self.token(m.group(0), "device"), text, flags=re.I)
        text = MAC.sub(lambda m: self.token(m.group(0), "mac"), text)
        text = IPV6.sub(lambda m: self.token(m.group(0), "ip") if _is_v6(m.group(0)) else m.group(0), text)
        return IPV4.sub(lambda m: self.token(m.group(0), "ip"), text)


def build_context(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    from app import remediation

    run = remediation._run(conn, run_id)
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (run["device_id"],)).fetchone() if run["device_id"] else None
    ctx: dict[str, Any] = {"event": {"kind": run["kind"], "detail": run["detail"], "at": run["created"]}, "rule_under_review": run["rule_id"]}
    if device is not None:
        ctx["device"] = {"name": device["custom_name"] or device["hostname"] or device["primary_ip"], "type": device["type_override"] or device["device_type"], "vendor": device["vendor"],
                         "os": device["os_name"], "online": bool(device["online"]), "ip": device["primary_ip"], "first_seen": device["first_seen"], "last_seen": device["last_seen"]}
        ctx["recent_events"] = [{"at": r["ts"], "kind": r["kind"], "detail": (r["detail"] or "")[:200]}
                                for r in conn.execute("SELECT ts, kind, detail FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 15", (device["id"],))]
        ctx["services"] = [{"name": r["name"], "kind": r["kind"], "up": None if r["last_up"] is None else bool(r["last_up"]), "detail": (r["last_detail"] or "")[:120]}
                           for r in conn.execute("SELECT name, kind, last_up, last_detail FROM service_checks WHERE enabled = 1 AND device_id = ? LIMIT 15", (device["id"],))]
        ctx["earlier_fixes"] = [{"rule": r["rule_name"], "at": r["created"], "result": r["state"], "recovered": bool(r["recovered"])}
                                for r in conn.execute("SELECT * FROM remediation_runs WHERE device_id = ? AND id != ? AND state IN ('ok', 'failed') ORDER BY id DESC LIMIT 8", (device["id"], run_id))]
    ctx["rules"] = [{"id": r["id"], "name": r["name"], "does": {"wake": "wake the device (Wake-on-LAN)", "webhook": "call a web address (an automation)", "ssh": "run a fixed command on the device over SSH"}[r["action"]["type"]],
                     "for_events": r["kinds"]} for r in remediation.list_rules(conn) if r["enabled"]]
    return ctx


def chat(conn: sqlite3.Connection, messages: list[dict], timeout: float = 90.0) -> str:
    cfg = settings(conn)
    if not cfg["url"] or not cfg["model"]:
        raise EngineerError("set the address and the model of the language model first (Settings → Digital engineer)")
    body = json.dumps({"model": cfg["model"], "messages": messages, "temperature": 0.1, "max_tokens": 6000}).encode()
    request = urllib.request.Request(cfg["url"] + "/chat/completions", data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": "Netlens-engineer"})
    key = get_setting(conn, "engineer.api_key")
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:        # noqa: S310 - the address is the administrator's own setting
            doc = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
        text = str(doc["choices"][0]["message"].get("content") or "")
        if not text.strip():                  # a model that thinks first can use up its allowance before it answers
            raise EngineerError("the language model gave no answer (it may have run out of room while thinking)")
        return text
    except urllib.error.HTTPError as exc:
        raise EngineerError(f"the language model answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise EngineerError(f"cannot reach the language model: {getattr(exc, 'reason', exc)}") from None
    except (ValueError, KeyError, IndexError, TypeError):
        raise EngineerError("the language model did not answer in the expected way") from None


def parse_answer(text: str) -> dict[str, Any]:
    """The JSON object in the model's answer (models like to add words around it); only known fields, clipped."""
    match = re.search(r"\{.*\}", text, re.S)
    try:
        doc = json.loads(match.group(0)) if match else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        raise EngineerError("the language model did not return a usable answer")
    rule = doc.get("recommended_rule_id")
    rule = rule if isinstance(rule, int) and not isinstance(rule, bool) else (int(rule) if isinstance(rule, str) and rule.isdigit() else None)
    confidence = str(doc.get("confidence") or "low").lower()
    steps = doc.get("next_steps") if isinstance(doc.get("next_steps"), list) else []
    return {"diagnosis": str(doc.get("diagnosis") or "")[:800], "confidence": confidence if confidence in ("low", "medium", "high") else "low", "recommended_rule_id": rule,
            "reasoning": str(doc.get("reasoning") or "")[:1200], "next_steps": [str(s)[:300] for s in steps[:6]]}


def advise(conn: sqlite3.Connection, run_id: int, ask: Callable[[list[dict]], str] | None = None, now: datetime | None = None) -> dict[str, Any] | None:
    """Ask the engineer about a run, store the answer on it. Returns the analysis plus `approve` (True only for this rule, with high confidence), None when it is switched off."""
    from app import licence, remediation

    if not licence.allows(conn, "engineer", now) or not settings(conn)["enabled"]:
        return None
    ctx = build_context(conn, run_id)
    names = [n for n in (ctx.get("device", {}).get("name"),) if n]
    redact = Redactor(names) if settings(conn)["redact"] else (lambda t: t)
    payload = redact(json.dumps(ctx, default=str, indent=1))
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": payload}]
    answer = parse_answer((ask or (lambda m: chat(conn, m)))(messages))
    valid = {r["id"] for r in ctx["rules"]}
    if answer["recommended_rule_id"] not in valid:
        answer["recommended_rule_id"] = None
    run = remediation._run(conn, run_id)
    answer["approve"] = bool(answer["recommended_rule_id"] is not None and answer["recommended_rule_id"] == run["rule_id"] and answer["confidence"] == "high")
    answer["asked"] = utcnow()
    answer["redacted"] = settings(conn)["redact"]
    conn.execute("UPDATE remediation_runs SET analysis = ? WHERE id = ?", (json.dumps(answer), run_id))
    conn.commit()
    return answer
