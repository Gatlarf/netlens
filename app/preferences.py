"""Personal preferences of a signed-in user (kept on the server, so every browser and device of that user shows the same).

Today: the page Netlens opens on, and the tables' saved views (app/tableviews.py). An administrator can also set a start page per role (an administrator, an operator, a viewer, or a custom role), used until somebody chooses their own. The administrator's access token (no account) has one set of preferences of its own.
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


# ---- the start page of a role -------------------------------------------------------------------------------------
ROLE_KEY = "preferences.role_start_pages"
BASE_ROLES = ("admin", "operator", "viewer")


def role_pages(conn: sqlite3.Connection) -> dict[str, str]:
    """{role: start page}: the built-in roles by name and custom roles by id. A page that no longer exists is not returned."""
    try:
        data = json.loads(get_setting(conn, ROLE_KEY) or "{}")
    except ValueError:
        return {}
    return {k: v for k, v in (data.items() if isinstance(data, dict) else []) if isinstance(k, str) and v in START_PAGES}


def set_role_page(conn: sqlite3.Connection, role: str, page: str | None) -> dict[str, str]:
    """Choose where everybody with this role lands after signing in (None = the dashboard). Raises ValueError for an unknown role or page, or a page the role may not open."""
    from app import roles

    custom = {r["id"]: r for r in roles.load(conn)}
    if role not in BASE_ROLES and role not in custom:
        raise ValueError("no such role")
    data = role_pages(conn)
    if page in (None, "", "#/", "#/dashboard"):
        data.pop(role, None)
    else:
        if page not in START_PAGES:
            raise ValueError("that is not a page Netlens can start on")
        base = role if role in BASE_ROLES else custom[role]["base"]
        if START_PAGES[page][1] and base != "admin":
            raise ValueError("that page is only for administrators")
        data[role] = page
    set_setting(conn, ROLE_KEY, json.dumps(data))
    return data


def role_default(conn: sqlite3.Connection, principal) -> str | None:
    """The start page the administrator set for this user's role (a custom role first, then the built-in one), or None."""
    pages = role_pages(conn)
    if not pages:
        return None                                                                   # nobody set a start page for a role: no further look-up
    uid = getattr(principal, "user_id", None)
    if uid is not None:
        row = conn.execute("SELECT custom_role FROM users WHERE id = ?", (uid,)).fetchone()
        if row is not None and row["custom_role"] and row["custom_role"] in pages:
            page = pages[row["custom_role"]]
        else:
            page = pages.get(getattr(principal, "role", ""))
    else:
        page = pages.get(getattr(principal, "role", ""))
    if page and START_PAGES[page][1] and not getattr(principal, "is_admin", False):
        return None
    return page


def effective(conn: sqlite3.Connection, principal) -> str | None:
    """Where this user lands: their own choice, else the one for their role, else None (the dashboard)."""
    return get(conn, principal)["start_page"] or role_default(conn, principal)
