"""Saved views of the big tables (today the Devices table): which columns, in which order and how wide, the sort order and the filters.

Everybody keeps views of their own (with the one that is open), kept with the rest of their preferences. An administrator can also share views: they appear for
everybody next to their own, and cannot be changed by anyone else. The columns a table offers are listed here (the page has the same list; a test keeps them the same),
so a view can only ask for columns that exist. The first columns of every table are locked: a table without a name column says nothing.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
from typing import Any

from app import preferences
from app.db import get_setting, set_setting

COLUMNS: dict[str, tuple[str, ...]] = {
    "devices": ("status", "name", "primary_ip", "type", "group", "mac", "vendor", "network", "ipv6", "tags", "os_name", "open_ports", "tier", "always_on", "first_seen",
                "last_seen", "trusted", "dns_name", "parent", "port", "medium", "wifi_band", "wifi_signal", "wifi_node", "uptime_7d", "rtt_24h", "maintenance", "notes"),
}
LOCKED: dict[str, tuple[str, ...]] = {"devices": ("status", "name")}
FILTERS: dict[str, tuple[str, ...]] = {
    "devices": ("q", "online", "type", "trusted", "ports", "group", "network"),
}
MAX_VIEWS = 20
MAX_COLUMNS = 30
ID = re.compile(r"^[a-z0-9]{3,16}$")


def check_table(table: str) -> None:
    if table not in COLUMNS:
        raise ValueError("unknown table")


def clean_view(table: str, raw: Any) -> dict:
    """One view as it is stored; raises ValueError for anything that is not a view."""
    check_table(table)
    if not isinstance(raw, dict):
        raise ValueError("a view is an object")
    name = " ".join(str(raw.get("name") or "").split())[:40]
    if not name:
        raise ValueError("a view needs a name")
    known = COLUMNS[table]
    columns = [c for c in (raw.get("columns") or []) if isinstance(c, str) and c in known]
    columns = list(dict.fromkeys(columns))[:MAX_COLUMNS]
    for locked in reversed(LOCKED[table]):              # the locked ones are always there, at the front
        if locked in columns:
            columns.remove(locked)
        columns.insert(0, locked)
    columns = columns[:MAX_COLUMNS]
    widths = {}
    if isinstance(raw.get("widths"), dict):
        for key, value in raw["widths"].items():
            if key in known and isinstance(value, (int, float)) and not isinstance(value, bool) and 48 <= value <= 2000:
                widths[key] = int(value)
    sort = raw.get("sort") if isinstance(raw.get("sort"), dict) else {}
    sort_key = sort.get("key") if sort.get("key") in known else None
    filters = {}
    if isinstance(raw.get("filters"), dict):
        for key, value in raw["filters"].items():
            if key in FILTERS[table] and isinstance(value, str) and value and len(value) <= 80:
                filters[key] = value
    vid = raw.get("id") if isinstance(raw.get("id"), str) and ID.match(raw["id"]) else secrets.token_hex(4)
    return {"id": vid, "name": name, "columns": columns, "widths": widths, "sort": {"key": sort_key, "dir": "desc" if sort.get("dir") == "desc" else "asc"} if sort_key else None, "filters": filters}


def clean_views(table: str, raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        raise ValueError("views are a list")
    if len(raw) > MAX_VIEWS:
        raise ValueError(f"at most {MAX_VIEWS} views")
    out, seen = [], set()
    for item in raw:
        view = clean_view(table, item)
        if view["id"] in seen:
            view["id"] = secrets.token_hex(4)
        seen.add(view["id"])
        out.append(view)
    return out


def _shared_key(table: str) -> str:
    return f"tableviews.shared.{table}"


def shared(conn: sqlite3.Connection, table: str) -> list[dict]:
    import json

    try:
        return clean_views(table, json.loads(get_setting(conn, _shared_key(table)) or "[]"))
    except (ValueError, TypeError):
        return []


def put_shared(conn: sqlite3.Connection, table: str, views: Any) -> list[dict]:
    import json

    cleaned = clean_views(table, views)
    set_setting(conn, _shared_key(table), json.dumps(cleaned))
    return cleaned


def mine(conn: sqlite3.Connection, principal, table: str) -> dict:
    """{"views": [...], "active": id or None}. `active` may name one of the built-in views of the page ("builtin:network"), one of mine, or a shared one ("shared:<id>")."""
    check_table(table)
    data = preferences._load(conn, principal).get("table_views", {}).get(table, {})
    try:
        views = clean_views(table, data.get("views") or [])
    except ValueError:
        views = []
    active = data.get("active") if isinstance(data.get("active"), str) and len(data["active"]) <= 40 else None
    return {"views": views, "active": active}


def put_mine(conn: sqlite3.Connection, principal, table: str, views: Any, active: Any) -> dict:
    check_table(table)
    cleaned = clean_views(table, views)
    if active is not None and not (isinstance(active, str) and len(active) <= 40 and re.match(r"^(builtin:[a-z0-9-]{1,24}|shared:[a-z0-9]{3,16}|[a-z0-9]{3,16})$", active)):
        raise ValueError("that is not a view")
    data = preferences._load(conn, principal)
    data.setdefault("table_views", {})[table] = {"views": cleaned, "active": active}
    import json

    set_setting(conn, preferences._key(principal), json.dumps(data))
    return mine(conn, principal, table)
