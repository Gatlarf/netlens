"""Read-only share links: a secret URL that shows the network (or only a status page) without a login.

The link holds an unguessable token. What a link shows is fixed when it is made: `view` = map and device list,
`status` = counts and service states only; IP and MAC addresses are left out unless the link says otherwise.
A link can expire and be revoked at any time.
"""

import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from app import stats
from app.db import utcnow

MODES = ("view", "status")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,80}$")
MAX_DAYS = 3650


class ShareError(ValueError):
    pass


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def create(conn: sqlite3.Connection, name: str, mode: str, show_ips: bool = False, show_macs: bool = False, expires_days: int | None = None) -> int:
    name = (name or "").strip()[:60]
    if not name:
        raise ShareError("give the link a name, for example Family or Landlord")
    if mode not in MODES:
        raise ShareError("the link shows either the map and devices, or only a status page")
    expires = None
    if expires_days is not None:
        if isinstance(expires_days, bool) or not isinstance(expires_days, int) or not 1 <= expires_days <= MAX_DAYS:
            raise ShareError("a link lasts between 1 and 3650 days")
        expires = _iso(datetime.now(timezone.utc) + timedelta(days=expires_days))
    cur = conn.execute(
        "INSERT INTO share_links (token, name, mode, show_ips, show_macs, created, expires) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (secrets.token_urlsafe(24), name, mode, int(bool(show_ips)), int(bool(show_macs)), utcnow(), expires),
    )
    conn.commit()
    return cur.lastrowid


def _view(row) -> dict:
    expired = bool(row["expires"] and row["expires"] <= utcnow())
    return {
        "id": row["id"], "name": row["name"], "mode": row["mode"], "token": row["token"],
        "show_ips": bool(row["show_ips"]), "show_macs": bool(row["show_macs"]),
        "created": row["created"], "expires": row["expires"], "expired": expired,
        "last_used": row["last_used"], "views": row["views"],
    }


def list_links(conn: sqlite3.Connection) -> list[dict]:
    return [_view(r) for r in conn.execute("SELECT * FROM share_links ORDER BY id DESC")]


def delete(conn: sqlite3.Connection, link_id: int) -> None:
    if conn.execute("DELETE FROM share_links WHERE id = ?", (link_id,)).rowcount == 0:
        raise ShareError("no such link")
    conn.commit()


def find(conn: sqlite3.Connection, token: str, count: bool = True):
    """The live link for a token, or None (unknown, malformed or expired). Counts the visit unless count=False."""
    if not TOKEN_RE.match(token or ""):
        return None
    row = conn.execute("SELECT * FROM share_links WHERE token = ?", (token,)).fetchone()
    if row is None or (row["expires"] and row["expires"] <= utcnow()):
        return None
    if count:
        conn.execute("UPDATE share_links SET last_used = ?, views = views + 1 WHERE id = ?", (utcnow(), row["id"]))
        conn.commit()
    return row


def public_data(conn: sqlite3.Connection, link) -> dict:
    """What a visitor of the link gets, with everything the link hides left out."""
    s = stats.summary(conn)
    base = {
        "name": link["name"], "mode": link["mode"], "generated": s["generated"],
        "problem": s["problem"], "devices_total": s["devices"]["total"], "devices_online": s["devices"]["online"],
        "devices_offline": s["devices"]["offline"],
        "last_scan": (s["scans"]["last"] or {}).get("finished"),
        "services": [{"name": c["name"], "state": c["state"]} for c in _service_list(conn)],
    }
    if link["mode"] == "status":
        return base
    show_ips, show_macs = bool(link["show_ips"]), bool(link["show_macs"])
    devices = []
    for d in s["device_list"]:
        name = d["name"]
        if not show_ips and name == d["ip"]:
            name = f"Device {d['id']}"  # a name that is only an address would leak it
        devices.append({
            "id": d["id"], "name": name, "type": d["type"], "online": d["online"], "last_seen": d["last_seen"],
            "parent_id": d["parent_id"], "vendor": d["vendor"],
            "ip": d["ip"] if show_ips else None, "mac": d["mac"] if show_macs else None,
        })
    return {**base, "show_ips": show_ips, "show_macs": show_macs, "devices": devices}


def _service_list(conn: sqlite3.Connection) -> list[dict]:
    return [c for c in stats._services(conn, utcnow())["checks"] if c["enabled"]]
