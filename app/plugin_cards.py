"""Dashboard cards supplied by plugins: a plugin declares them in plugin.json (`dashboard`), and Netlens fills in the numbers from what it
knows about that plugin. A plugin never runs code for a card. Every enabled plugin also gets a plain status card."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app.plugins.contract import ContractError, _dict, _fail, _list, _text

SOURCES = {  # what a row may count, and the columns it may filter on
    "guests": ("hypervisor_guests", ("kind", "status", "host_name")),
    "sites": ("proxy_sites", ("type", "enabled", "scheme", "proxy_name")),
    "targets": ("backup_targets", ("type", "last_state", "stale")),
}
VALUES = {"status.ok", "status.ts", "status.error"}
TONES = ("warn", "bad")
CARD_ID = re.compile(r"^[a-z0-9_-]{1,20}$")
HREF = re.compile(r"^#/[A-Za-z0-9_/\-]{1,60}$")
MAX_CARDS, MAX_ROWS = 4, 8


def validate_cards(raw: Any) -> list[dict]:
    """The `dashboard` list of a manifest, normalised. Raises ContractError."""
    if raw is None:
        return []
    out, seen = [], set()
    for i, card in enumerate(_list(raw, "dashboard")):
        path = f"dashboard[{i}]"
        card = _dict(card, path)
        cid = _text(card.get("id"), f"{path}.id", required=True, max_len=20)
        if not CARD_ID.match(cid) or cid in seen or cid == "status":
            _fail(f"{path}.id", "must be 1-20 lowercase letters, digits, - or _, unique, and not 'status'")
        seen.add(cid)
        href = _text(card.get("href"), f"{path}.href", max_len=64)
        if href and not HREF.match(href):
            _fail(f"{path}.href", "must be a page of Netlens such as #/devices")
        rows = []
        for j, row in enumerate(_list(card.get("rows"), f"{path}.rows")):
            rpath = f"{path}.rows[{j}]"
            row = _dict(row, rpath)
            entry: dict[str, Any] = {"label": _text(row.get("label"), f"{rpath}.label", required=True, max_len=30)}
            if (row.get("count") is None) == (row.get("value") is None):
                _fail(rpath, "needs exactly one of 'count' and 'value'")
            if row.get("count") is not None:
                if row["count"] not in SOURCES:
                    _fail(f"{rpath}.count", f"must be one of {', '.join(SOURCES)}")
                entry["count"] = row["count"]
                where = row.get("where") or {}
                if not isinstance(where, dict):
                    _fail(f"{rpath}.where", "must be an object")
                clean = {}
                for col, want in where.items():
                    if col not in SOURCES[row["count"]][1]:
                        _fail(f"{rpath}.where", f"{col!r} cannot be used with {row['count']} (use {', '.join(SOURCES[row['count']][1])})")
                    values = want if isinstance(want, list) else [want]
                    if not values or len(values) > 10 or not all(isinstance(v, (str, int, bool)) for v in values):
                        _fail(f"{rpath}.where.{col}", "must be a text, number or true/false, or a short list of them")
                    clean[col] = [int(v) if isinstance(v, bool) else v for v in values]
                entry["where"] = clean
            else:
                if row["value"] not in VALUES:
                    _fail(f"{rpath}.value", f"must be one of {', '.join(sorted(VALUES))}")
                entry["value"] = row["value"]
            tone = row.get("tone_if_positive")
            if tone is not None:
                if tone not in TONES:
                    _fail(f"{rpath}.tone_if_positive", "must be 'warn' or 'bad'")
                entry["tone_if_positive"] = tone
            rows.append(entry)
        if not 1 <= len(rows) <= MAX_ROWS:
            _fail(f"{path}.rows", f"needs 1 to {MAX_ROWS} rows")
        out.append({"id": cid, "title": _text(card.get("title"), f"{path}.title", required=True, max_len=40), "about": _text(card.get("about"), f"{path}.about", max_len=120),
                    "href": href or None, "rows": rows})
        if len(out) > MAX_CARDS:
            _fail("dashboard", f"at most {MAX_CARDS} cards")
    return out


def _count(conn: sqlite3.Connection, plugin_id: str, source: str, where: dict[str, list]) -> int:
    table, _ = SOURCES[source]
    sql, args = f"SELECT COUNT(*) FROM {table} WHERE plugin_id = ?", [plugin_id]
    for col, values in where.items():                      # the column names come from the whitelist above
        sql += f" AND {col} IN ({', '.join('?' * len(values))})"
        args += values
    return conn.execute(sql, args).fetchone()[0]


def _row(conn, plugin_id: str, status: dict | None, spec: dict) -> dict:
    if "count" in spec:
        n = _count(conn, plugin_id, spec["count"], spec.get("where", {}))
        return {"label": spec["label"], "value": n, "format": "number", "tone": spec.get("tone_if_positive") if n else None}
    field = spec["value"].split(".", 1)[1]
    if field == "ok":
        ok = (status or {}).get("ok")
        return {"label": spec["label"], "value": "Not synced yet" if ok is None else "Working" if ok else "Failing", "format": "text", "tone": "bad" if ok is False else None}
    return {"label": spec["label"], "value": (status or {}).get(field), "format": "ago" if field == "ts" else "text", "tone": None}


def resolve(conn: sqlite3.Connection, manifest: dict, status: dict | None) -> list[dict]:
    """The cards of one enabled plugin with their numbers: the declared ones and a status card."""
    plugin_id = manifest["id"]
    cards = []
    ok = (status or {}).get("ok")
    base = [{"label": "Status", "value": "Not synced yet" if ok is None else "Working" if ok else "Failing", "format": "text", "tone": "bad" if ok is False else None},
            {"label": "Last sync", "value": (status or {}).get("ts"), "format": "ago", "tone": None}]
    if ok is False and (status or {}).get("error"):
        base.append({"label": "Problem", "value": str(status["error"])[:120], "format": "text", "tone": "bad"})
    if manifest["kind"] == "hypervisor":
        total = _count(conn, plugin_id, "guests", {})
        if total:
            base += [{"label": "Guests", "value": total, "format": "number", "tone": None}, {"label": "Running", "value": _count(conn, plugin_id, "guests", {"status": ["running"]}), "format": "number", "tone": None}]
    if manifest["kind"] == "backup":
        total = _count(conn, plugin_id, "targets", {})
        if total:
            base += [{"label": "Backed up", "value": total, "format": "number", "tone": None},
                     {"label": "Failed or late", "value": _count(conn, plugin_id, "targets", {"last_state": ["failed"]}) + _count(conn, plugin_id, "targets", {"stale": [1]}), "format": "number", "tone": "warn"}]
    if manifest["kind"] == "proxy":
        total = _count(conn, plugin_id, "sites", {})
        if total:
            base.append({"label": "Sites", "value": total, "format": "number", "tone": None})
    cards.append({"id": "status", "plugin": plugin_id, "title": manifest["name"], "about": f"State of the {manifest['name']} plugin.", "href": f"#/settings/plugin-{plugin_id}", "rows": base})
    for card in manifest.get("dashboard") or []:
        cards.append({"id": card["id"], "plugin": plugin_id, "title": card["title"], "about": card["about"] or card["title"], "href": card["href"] or f"#/settings/plugin-{plugin_id}",
                      "rows": [_row(conn, plugin_id, status, r) for r in card["rows"]]})
    return cards
