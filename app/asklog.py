"""The questions "Ask your network" could not answer.

Nobody can predict what will be asked. A question that ends in "the data does not tell" (or that the built-in logic did not understand) is kept
here, so an administrator can see what is missing and add it. Only the question's text (cut to 200 characters), the time, the tools that were
tried and which part answered are kept: no answer text, no names of the person asking. At most 200 questions, none older than 90 days; the same
question is counted, not repeated. Administrators only, and it can be switched off.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY, SWITCH = "ask.misses", "ask.log"
MAX_ITEMS, KEEP_DAYS, MAX_TEXT = 200, 90, 200
STAMP = "%Y-%m-%dT%H:%M:%SZ"
# the words of an answer that gives up (the language model words it in many ways)
GAVE_UP = re.compile(r"does not tell|do not tell|doesn'?t tell|cannot answer|can'?t (answer|show|say|tell|give)|does not (say|contain|show|give|list|record|have|include|hold)|"
                     r"no (data|information|measurement|record|reading)s? (about|on|for|of)|not (stored|recorded|available|tracked|measured)|only (gives|has|shows) (the )?(current|totals?)", re.I)


def enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, SWITCH) != "0"


def set_enabled(conn: sqlite3.Connection, on: bool) -> None:
    set_setting(conn, SWITCH, "1" if on else "0")
    conn.commit()


def is_miss(result: dict[str, Any]) -> bool:
    return bool(result.get("understood") is False or not result.get("tools") or GAVE_UP.search(result.get("answer") or ""))


def _load(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    try:
        doc = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    return [x for x in doc if isinstance(x, dict)] if isinstance(doc, list) else []


def record(conn: sqlite3.Connection, question: str, result: dict[str, Any], now: datetime | None = None) -> bool:
    """Keep the question when it was not answered. Never raises: a question must not fail because the log could not be written."""
    try:
        if not enabled(conn) or not is_miss(result):
            return False
        now = now or datetime.now(timezone.utc)
        text = " ".join((question or "").split())[:MAX_TEXT]
        if not text:
            return False
        items = [x for x in _load(conn) if x.get("last", "") >= (now - timedelta(days=KEEP_DAYS)).strftime(STAMP)]
        mine = next((x for x in items if x.get("q", "").lower() == text.lower()), None)
        tools = [t for t in (result.get("tools") or []) if isinstance(t, str)][:6]
        if mine:
            mine.update({"n": mine.get("n", 1) + 1, "last": now.strftime(STAMP), "tools": tools, "source": result.get("source")})
        else:
            items.append({"q": text, "n": 1, "first": now.strftime(STAMP), "last": now.strftime(STAMP), "tools": tools, "source": result.get("source")})
        items.sort(key=lambda x: x["last"], reverse=True)
        set_setting(conn, KEY, json.dumps(items[:MAX_ITEMS]))
        conn.commit()
        return True
    except Exception:  # noqa: BLE001
        return False


def items(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return sorted(_load(conn), key=lambda x: x.get("last", ""), reverse=True)


def clear(conn: sqlite3.Connection) -> int:
    n = len(_load(conn))
    set_setting(conn, KEY, "[]")
    conn.commit()
    return n
