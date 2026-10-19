"""Is this language model good enough for Insights and the digital engineer? Six small exams with made-up data (a paid feature, see app/insights.py).

A model that cannot follow a one-line protocol, copies numbers wrongly or leaves items out gives answers that look right and are not. The exams run
the same instructions the real questions use, against invented devices, and say plainly which ones failed.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from app import ask, engineer

QUESTION_TOOLS = ("offline_now", "overview")


NUDGE = 'Reply with one JSON object only: {"tool": ..., "args": ...} or {"answer": ...}.'      # the same reminder the real question loop gives (app/ask.py)
BUSY = ("busy", "HTTP 429", "HTTP 5", "cannot reach", "timed out", "refused the API key", "needs credit")       # the server or the account, not the model, failed: the exam says nothing about the model
RETRY_WAITS = (4.0, 12.0)
_sleep = time.sleep


def _step(conn, ask_fn, messages: list[dict]) -> tuple[str, bool]:
    """The model's reply, and whether it needed the reminder to answer in JSON. A busy server is waited for twice before it counts as a failure."""
    call = ask_fn or (lambda m: engineer.chat(conn, m, timeout=120.0))

    def once(msgs: list[dict]) -> str:
        for wait in (*RETRY_WAITS, None):
            try:
                return call(msgs)
            except Exception as exc:  # noqa: BLE001
                if wait is None or not any(w in str(exc) for w in BUSY):
                    raise
                _sleep(wait)
        raise RuntimeError("unreachable")

    reply = once(messages)
    if ask._parse_reply(reply) is None:
        return once(messages + [{"role": "assistant", "content": (reply or "")[:500]}, {"role": "user", "content": NUDGE}]), True
    return reply, False


def _result(question: str, tool: str, args: dict, result: dict) -> list[dict]:
    return [{"role": "system", "content": ask.system_prompt()}, {"role": "user", "content": question},
            {"role": "assistant", "content": json.dumps({"tool": tool, "args": args})}, {"role": "user", "content": f"Result of {tool}:\n{json.dumps(result)}"}]


def _answer_of(reply: str) -> str | None:
    doc = ask._parse_reply(reply)
    return doc["answer"] if doc and isinstance(doc.get("answer"), str) else None


def run(conn, ask_fn=None) -> dict[str, Any]:
    """[{name, ok, detail, seconds}] for each exam, how many passed and a verdict."""
    checks: list[dict[str, Any]] = []

    def exam(name: str, what: str, messages: list[dict], judge: Callable[[str], tuple[bool, str]]) -> None:
        started = time.monotonic()
        failed = False
        try:
            reply, reminded = _step(conn, ask_fn, messages)
            ok, detail = judge(reply)
            if ok and reminded:
                detail += " (after one reminder to answer in JSON)"
        except Exception as exc:  # noqa: BLE001 - an unreachable model fails every exam, and says why
            ok, detail, failed = False, f"no answer ({str(exc)[:120]})", any(w in str(exc) for w in BUSY)
        checks.append({"name": what, "ok": ok, "detail": detail, "seconds": round(time.monotonic() - started, 1), "id": name, "server_failed": failed})

    def picks(*tools):
        def judge(reply):
            doc = ask._parse_reply(reply)
            if doc is None:
                return False, "did not reply with a JSON object"
            return (doc.get("tool") in tools, f"chose {doc.get('tool')!r}" if doc.get("tool") in tools else f"chose {doc.get('tool') or 'no tool'!r} instead of {' or '.join(tools)}")
        return judge

    exam("protocol", "Follows the reply format and picks a fitting tool", [{"role": "system", "content": ask.system_prompt()}, {"role": "user", "content": "Which devices are offline right now?"}], picks("offline_now", "overview"))
    exam("choice", "Chooses the right tool for a less obvious question", [{"role": "system", "content": ask.system_prompt()}, {"role": "user", "content": "Which of my devices answers the slowest?"}], picks("response_times"))

    exam("readings", "Looks at current readings, not at forecasts, for “low on RAM”", [{"role": "system", "content": ask.system_prompt()}, {"role": "user", "content": "Which machines are low on RAM?"}], picks("health"))

    def copies(reply):
        text = _answer_of(reply)
        if text is None:
            return False, "did not answer in the JSON format"
        good = "147.2" in text and "<device1>" in text and "<device3>" not in text and "91.3" in text
        return good, "copied the names and numbers exactly" if good else "changed or left out a name or a number"
    exam("fidelity", "Copies names and numbers exactly", _result("List the average response time of every device.", "response_times", {"days": 7},
         {"order": "slowest", "devices": [{"name": "<device1>", "avg_ms": 147.2}, {"name": "<device2>", "avg_ms": 91.3}], "services": []}), copies)

    def complete(reply):
        text = _answer_of(reply)
        if text is None:
            return False, "did not answer in the JSON format"
        missing = [f"<device{i}>" for i in range(1, 6) if f"<device{i}>" not in text]
        return not missing, "listed all five devices" if not missing else f"left out {', '.join(missing)}"
    exam("completeness", "Does not leave items out of a list", _result("Which devices are offline?", "offline_now", {},
         {"offline": [{"name": f"<device{i}>", "last_seen": "2026-10-17T10:00:00Z", "always_on": False} for i in range(1, 6)]}), complete)

    def honest(reply):
        doc = ask._parse_reply(reply)
        if doc is None:
            return False, "did not reply with a JSON object"
        if "tool" in doc:
            return True, "looked at the data instead of guessing"
        text = _answer_of(reply) or ""
        return not any(ch.isdigit() for ch in text), "admitted the data does not tell" if not any(ch.isdigit() for ch in text) else "invented a number that is not in the data"
    exam("honesty", "Does not invent what the data cannot tell", [{"role": "system", "content": ask.system_prompt()}, {"role": "user", "content": "What was the temperature in my server room yesterday at noon?"}], honest)

    passed = sum(1 for c in checks if c["ok"])
    inconclusive = any(c["server_failed"] for c in checks) or all(c["detail"].startswith("no answer") for c in checks)      # no answer at all: nothing was learned about the model
    verdict = "good" if passed == len(checks) else "usable" if passed >= len(checks) - 1 else "poor"
    advice = {"good": "This model follows the instructions well enough for Insights and the digital engineer.",
              "usable": "This model mostly works. Check important answers yourself and keep remediation rules on “ask first”.",
              "poor": "This model is not reliable enough: answers can look right and be wrong. Use a larger or less compressed model. Insights still work without any model."}[verdict]
    return {"passed": passed, "total": len(checks), "verdict": verdict, "advice": advice, "inconclusive": inconclusive, "checks": checks, "model": engineer.settings(conn)["model"]}
