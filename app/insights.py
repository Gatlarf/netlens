"""Insights: questions, incident summaries, anomalies, identification of unknown devices, report summaries, post-mortems (a paid feature).

Every one of them works without a language model: the numbers and the sentences come from Netlens itself. When the digital engineer
(Settings → AI → Language model) is set up and `insights.llm` is on, a model may write the sentences more nicely or answer free questions;
a model never changes data and never decides anything, and when it cannot be reached the plain version is shown.
"""

from __future__ import annotations

import logging
import sqlite3

from app import engineer, licence
from app.db import get_setting, set_setting

log = logging.getLogger(__name__)
LLM_KEY = "insights.llm"


def allowed(conn: sqlite3.Connection) -> bool:
    return licence.allows(conn, "insights")


def llm_wanted(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, LLM_KEY) != "0"


def set_llm_wanted(conn: sqlite3.Connection, on: bool) -> None:
    set_setting(conn, LLM_KEY, "1" if on else "0")


def llm_ready(conn: sqlite3.Connection) -> bool:
    """A language model is set up, allowed and wanted for the insights."""
    cfg = engineer.settings(conn)
    return bool(cfg["enabled"] and cfg["url"] and cfg["model"] and llm_wanted(conn) and licence.allows(conn, "engineer"))


def complete(conn: sqlite3.Connection, system: str, user: str, names: list[str] | None = None, ask=None) -> str | None:
    """The model's answer (addresses and names anonymised on the way out and put back on the way in), or None when there is no model or it fails.
    `ask(messages)` replaces the call in tests."""
    if ask is None and not llm_ready(conn):
        return None
    redact = engineer.Redactor(names or []) if engineer.settings(conn)["redact"] else None
    text = redact(user) if redact else user
    messages = [{"role": "system", "content": system}, {"role": "user", "content": text}]
    try:
        answer = (ask or (lambda m: engineer.chat(conn, m)))(messages)
    except Exception:  # noqa: BLE001 - an unreachable or confused model only means the plain version is shown
        log.debug("the language model could not be used", exc_info=True)
        return None
    answer = (answer or "").strip()
    return (redact.restore(answer) if redact else answer) or None


def status(conn: sqlite3.Connection) -> dict:
    return {"allowed": allowed(conn), "llm_wanted": llm_wanted(conn), "llm_ready": llm_ready(conn), "llm_configured": bool(engineer.settings(conn)["url"])}
