"""Card layouts of the pages that show cards (the device page): which cards, in which order, how wide.

A layout is kept per user and per device type ("windows", "switch", ... or "*" for every type). An administrator can also save a template
for a type that everybody starts from. What a user sees: their own layout for the type, then their own for all types, then the template
for the type, then the template for all types, then the built-in arrangement (no layout at all)."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

PAGES = ("device", "stats", "insights", "nethealth", "site", "vulns")
SIZES = ("s", "w", "f")      # one column, two columns, the whole row
ID = re.compile(r"^[a-z0-9_.-]{1,48}$")
TYPE = re.compile(r"^(\*|[a-z0-9_-]{1,30})$")


def _key(page: str, type_: str, owner: str) -> str:
    return f"layout.{page}.{owner}.{type_}"


def _owner(principal) -> str:
    uid = getattr(principal, "user_id", None)
    return f"u{uid}" if uid is not None else "builtin"


def check(page: str, type_: str) -> None:
    if page not in PAGES:
        raise ValueError("unknown page")
    if not TYPE.match(type_ or ""):
        raise ValueError("unknown device type")


def clean(payload: Any) -> dict:
    """The layout as it is stored: {"order": {tab: [card ids]}, "hidden": [ids], "sizes": {id: s|w|f}}."""
    if not isinstance(payload, dict):
        raise ValueError("a layout is an object")

    def ids(value, limit=80) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for x in value[:limit]:
            if isinstance(x, str) and ID.match(x) and x not in out:
                out.append(x)
        return out

    order = payload.get("order") if isinstance(payload.get("order"), dict) else {}
    sizes = {k: v for k, v in list(payload["sizes"].items())[:120] if isinstance(k, str) and ID.match(k) and v in SIZES} if isinstance(payload.get("sizes"), dict) else {}
    for k in ids(payload.get("full")):          # layouts saved before widths had three steps
        sizes.setdefault(k, "f")
    return {"order": {t: ids(v) for t, v in list(order.items())[:12] if isinstance(t, str) and ID.match(t)},
            "hidden": ids(payload.get("hidden")), "sizes": sizes}


def _read(conn: sqlite3.Connection, key: str) -> dict | None:
    from app.db import get_setting

    try:
        value = json.loads(get_setting(conn, key) or "null")
        return clean(value) if value is not None else None
    except ValueError:
        return None


def _write(conn: sqlite3.Connection, key: str, payload: Any) -> dict:
    from app.db import set_setting

    layout = clean(payload)
    set_setting(conn, key, json.dumps(layout))
    conn.commit()
    return layout


def _delete(conn: sqlite3.Connection, key: str) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    conn.commit()


def resolve(conn: sqlite3.Connection, principal, page: str, type_: str) -> dict:
    check(page, type_)
    me = _owner(principal)
    chain = [("mine", me, type_), ("mine", me, "*"), ("template", "template", type_), ("template", "template", "*")]
    found = {}
    for source, owner, t in chain:
        layout = _read(conn, _key(page, t, owner))
        if layout is not None and source not in found:
            found[source] = (layout, t)
    effective, source = (found["mine"][0], "mine") if "mine" in found else (found["template"][0], "template") if "template" in found else (None, "builtin")
    return {"effective": effective, "source": source, "mine": found["mine"][0] if "mine" in found else None, "mine_type": found["mine"][1] if "mine" in found else None,
            "template": found["template"][0] if "template" in found else None, "template_type": found["template"][1] if "template" in found else None}


def save_mine(conn, principal, page: str, type_: str, payload) -> dict:
    check(page, type_)
    return _write(conn, _key(page, type_, _owner(principal)), payload)


def reset_mine(conn, principal, page: str, type_: str) -> None:
    check(page, type_)
    _delete(conn, _key(page, type_, _owner(principal)))


def save_template(conn, page: str, type_: str, payload) -> dict:
    check(page, type_)
    return _write(conn, _key(page, type_, "template"), payload)


def reset_template(conn, page: str, type_: str) -> None:
    check(page, type_)
    _delete(conn, _key(page, type_, "template"))


def templates(conn: sqlite3.Connection, page: str) -> list[str]:
    prefix = f"layout.{page}.template."
    return sorted(r[0][len(prefix):] for r in conn.execute("SELECT key FROM settings WHERE key LIKE ?", (prefix + "%",)))
