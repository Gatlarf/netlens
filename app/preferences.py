"""Personal preferences of a signed-in user (kept on the server, so every browser and device of that user shows the same).

Today: the page Netlens opens on. The administrator's access token (no account) has one set of preferences of its own.
"""

from __future__ import annotations

import json
import sqlite3

from app.db import get_setting, set_setting

# hash -> (label, administrators only)
START_PAGES: dict[str, tuple[str, bool]] = {
    "#/dashboard": ("Dashboard", False),
    "#/map": ("Map", False),
    "#/devices": ("Devices", False),
    "#/hierarchy": ("Hierarchy", False),
    "#/speedtest": ("Speed tests", False),
    "#/uptime": ("Uptime", False),
    "#/health": ("Health", False),
    "#/remote-sites": ("Remote sites", False),
    "#/services": ("Services", False),
    "#/stats": ("Statistics", False),
    "#/reports": ("Reports", False),
    "#/scans": ("Scans & events", False),
    "#/remote": ("Remote access", True),
}


def _key(principal) -> str:
    uid = getattr(principal, "user_id", None)
    return f"user.prefs.user{uid}" if uid is not None else "user.prefs.builtin"


def _load(conn: sqlite3.Connection, principal) -> dict:
    try:
        data = json.loads(get_setting(conn, _key(principal)) or "{}")
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def get(conn: sqlite3.Connection, principal) -> dict:
    """{"start_page": "#/map" or None}. A page the user may no longer open (an administrator-only page after a demotion) is not returned."""
    page = _load(conn, principal).get("start_page")
    admin = bool(getattr(principal, "is_admin", False))
    if page not in START_PAGES or (START_PAGES[page][1] and not admin):
        page = None
    return {"start_page": page}


def options(principal) -> list[dict]:
    admin = bool(getattr(principal, "is_admin", False))
    return [{"value": k, "label": label} for k, (label, only_admin) in START_PAGES.items() if admin or not only_admin]


def set_start_page(conn: sqlite3.Connection, principal, page: str | None) -> dict:
    """Choose the page to open on (None = the dashboard, the default). Raises ValueError for a page that does not exist."""
    data = _load(conn, principal)
    if page in (None, "", "#/"):
        data.pop("start_page", None)
    else:
        if page not in START_PAGES:
            raise ValueError("that is not a page Netlens can start on")
        if START_PAGES[page][1] and not getattr(principal, "is_admin", False):
            raise ValueError("that page is only for administrators")
        data["start_page"] = page
    set_setting(conn, _key(principal), json.dumps(data))
    return get(conn, principal)
