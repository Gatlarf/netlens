"""Read-only share links: a secret URL that shows (part of) the network without a login.

The link holds an unguessable token. What a link shows is fixed when it is made and can be changed later: a choice of sections (summary,
services, map, devices, uptime, recent events), a scope (all devices, or only some groups), the services to list, a message, a title and a look.
IP and MAC addresses are left out unless the link says otherwise. A link can start later, expire, have a PIN, and be revoked at any time.
`mode` stays as the old preset name: view = map and devices, status = counts and services only.
"""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from app import checkstats, maintenance, stats, users
from app.db import utcnow

MODES = ("view", "status")
SECTIONS = ("summary", "services", "map", "devices", "uptime", "events")
PRESETS = {"view": ("summary", "services", "map", "devices"), "status": ("summary", "services")}
FIELDS = ("type", "vendor", "last_seen")
THEMES = ("auto", "light", "dark")
PUBLIC_EVENTS = {"device_offline": "went offline", "device_online": "came back online"}   # the only events a link shows: others carry addresses and internals
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,80}$")
ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
MAX_DAYS = 3650
MIN_PIN, MAX_PIN = 4, 64
CACHE_SECONDS = 10  # a public page may be refreshed by many visitors; compute its data once in a while
_cache: dict = {}


class ShareError(ValueError):
    pass


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ids(conn: sqlite3.Connection, value, table: str, what: str) -> list[int]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or any(isinstance(i, bool) or not isinstance(i, int) for i in value):
        raise ShareError(f"{what} must be a list of ids")
    known = {r[0] for r in conn.execute(f"SELECT id FROM {table}")}
    unknown = [i for i in value if i not in known]
    if unknown:
        raise ShareError(f"unknown {what}: {unknown[0]}")
    return sorted(set(value))


def _text(value, limit: int, what: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ShareError(f"{what} must be text")
    return value.strip()[:limit]


def clean_options(conn: sqlite3.Connection, data: dict | None, mode: str = "view") -> dict:
    """Validate what a link shows. Missing keys get the preset for `mode`; unknown keys are dropped."""
    data = data or {}
    sections = data.get("sections")
    if sections is None:
        sections = list(PRESETS[mode])
    if not isinstance(sections, list) or any(s not in SECTIONS for s in sections):
        raise ShareError("sections can be: " + ", ".join(SECTIONS))
    sections = [s for s in SECTIONS if s in sections]
    if not sections:
        raise ShareError("choose at least one thing to show")
    fields = data.get("fields", ["type", "last_seen"])
    if not isinstance(fields, list) or any(f not in FIELDS for f in fields):
        raise ShareError("device fields can be: " + ", ".join(FIELDS))
    limit = data.get("event_limit", 10)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ShareError("show between 1 and 50 recent events")
    days = data.get("uptime_days", 7)
    if days not in (7, 30):
        raise ShareError("the uptime history covers 7 or 30 days")
    accent = _text(data.get("accent"), 7, "the accent colour")
    if accent and not ACCENT_RE.match(accent):
        raise ShareError("the accent colour looks like #1d4ed8")
    theme = data.get("theme", "auto")
    if theme not in THEMES:
        raise ShareError("the theme is auto, light or dark")
    return {
        "sections": sections,
        "service_ids": _ids(conn, data.get("service_ids"), "service_checks", "services"),
        "group_ids": _ids(conn, data.get("group_ids"), "device_groups", "groups"),
        "fields": [f for f in FIELDS if f in fields],
        "generic_names": bool(data.get("generic_names", False)),
        "event_limit": limit,
        "uptime_days": days,
        "title": _text(data.get("title"), 60, "the title"),
        "message": _text(data.get("message"), 500, "the message"),
        "brand": _text(data.get("brand"), 30, "the brand name"),
        "accent": accent,
        "theme": theme,
    }


def uses_branding_or_scope(options: dict) -> bool:
    """The parts that mostly help organisations (customer views, white label); they need a licence to set, and keep working without one."""
    return bool(options.get("group_ids") or options.get("brand") or options.get("accent"))


def _mode_of(options: dict) -> str:
    return "view" if {"map", "devices"} & set(options["sections"]) else "status"


def _stored(options: dict) -> str:
    return json.dumps(options, separators=(",", ":"))


def _pin(pin) -> str | None:
    pin = pin if isinstance(pin, str) else ""
    if not pin:
        return None
    if not MIN_PIN <= len(pin) <= MAX_PIN:
        raise ShareError(f"a PIN has {MIN_PIN} to {MAX_PIN} characters")
    return users.hash_password(pin)


def _valid_from(value) -> str | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ShareError("the start is a date and time")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return _iso(moment.astimezone(timezone.utc))


def _expiry(days) -> str | None:
    if days is None:
        return None
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise ShareError("a link lasts between 1 and 3650 days")
    return _iso(datetime.now(timezone.utc) + timedelta(days=days))


def _check_name(name) -> str:
    name = (name or "").strip()[:60]
    if not name:
        raise ShareError("give the link a name, for example Family or Landlord")
    return name


def create(conn: sqlite3.Connection, name: str, mode: str, show_ips: bool = False, show_macs: bool = False, expires_days: int | None = None,
           options: dict | None = None, pin: str | None = None, valid_from: str | None = None) -> int:
    name = _check_name(name)
    if mode not in MODES:
        raise ShareError("the link shows either the map and devices, or only a status page")
    opts = clean_options(conn, options, mode)
    cur = conn.execute(
        "INSERT INTO share_links (token, name, mode, show_ips, show_macs, created, expires, options, pin_hash, valid_from) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (secrets.token_urlsafe(24), name, _mode_of(opts), int(bool(show_ips)), int(bool(show_macs)), utcnow(), _expiry(expires_days), _stored(opts), _pin(pin), _valid_from(valid_from)),
    )
    conn.commit()
    return cur.lastrowid


def update(conn: sqlite3.Connection, link_id: int, changes: dict) -> None:
    """Change the keys present in `changes`: name, show_ips, show_macs, expires_days (None = no end), valid_from, pin ('' removes it), options, new_token."""
    row = conn.execute("SELECT * FROM share_links WHERE id = ?", (link_id,)).fetchone()
    if row is None:
        raise ShareError("no such link")
    sets: dict = {}
    if "name" in changes:
        sets["name"] = _check_name(changes["name"])
    for key in ("show_ips", "show_macs"):
        if key in changes:
            sets[key] = int(bool(changes[key]))
    if "expires_days" in changes:
        sets["expires"] = _expiry(changes["expires_days"])
    if "valid_from" in changes:
        sets["valid_from"] = _valid_from(changes["valid_from"])
    if "pin" in changes and changes["pin"] is not None:
        sets["pin_hash"] = _pin(changes["pin"])
    if "options" in changes:
        opts = clean_options(conn, changes["options"], row["mode"])
        sets["options"], sets["mode"] = _stored(opts), _mode_of(opts)
    if changes.get("new_token"):
        sets["token"] = secrets.token_urlsafe(24)
    if sets:
        conn.execute("UPDATE share_links SET " + ", ".join(f"{k} = ?" for k in sets) + " WHERE id = ?", [*sets.values(), link_id])
        conn.commit()
    _cache.clear()


def options_of(row) -> dict:
    """The options of a stored link; links made before options existed get the preset of their mode."""
    try:
        stored = json.loads(row["options"] or "{}")
    except (ValueError, TypeError):
        stored = {}
    base = {"sections": list(PRESETS[row["mode"]])}
    base.update(stored if isinstance(stored, dict) else {})
    return {**clean_stored(base)}


def clean_stored(data: dict) -> dict:
    """Fill the defaults without touching the database (ids that no longer exist are dropped later, when the link is read)."""
    return {
        "sections": [s for s in SECTIONS if s in data.get("sections", [])] or ["summary"],
        "service_ids": [i for i in data.get("service_ids", []) if isinstance(i, int)],
        "group_ids": [i for i in data.get("group_ids", []) if isinstance(i, int)],
        "fields": [f for f in FIELDS if f in data.get("fields", ["type", "last_seen"])],
        "generic_names": bool(data.get("generic_names", False)),
        "event_limit": data["event_limit"] if isinstance(data.get("event_limit"), int) else 10,
        "uptime_days": 30 if data.get("uptime_days") == 30 else 7,
        "title": str(data.get("title") or ""),
        "message": str(data.get("message") or ""),
        "brand": str(data.get("brand") or ""),
        "accent": data.get("accent") if ACCENT_RE.match(str(data.get("accent") or "")) else "",
        "theme": data.get("theme") if data.get("theme") in THEMES else "auto",
    }


def _view(row) -> dict:
    expired = bool(row["expires"] and row["expires"] <= utcnow())
    return {
        "id": row["id"], "name": row["name"], "mode": row["mode"], "token": row["token"],
        "show_ips": bool(row["show_ips"]), "show_macs": bool(row["show_macs"]),
        "created": row["created"], "expires": row["expires"], "expired": expired, "valid_from": row["valid_from"],
        "waiting": bool(row["valid_from"] and row["valid_from"] > utcnow()),
        "has_pin": bool(row["pin_hash"]), "options": options_of(row),
        "last_used": row["last_used"], "views": row["views"],
    }


def list_links(conn: sqlite3.Connection) -> list[dict]:
    return [_view(r) for r in conn.execute("SELECT * FROM share_links ORDER BY id DESC")]


def choices(conn: sqlite3.Connection) -> dict:
    """What the form can pick from."""
    return {
        "groups": [{"id": r["id"], "name": r["name"]} for r in conn.execute("SELECT id, name FROM device_groups ORDER BY name COLLATE NOCASE")],
        "services": [{"id": r["id"], "name": r["name"]} for r in conn.execute("SELECT id, name FROM service_checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE")],
    }


def delete(conn: sqlite3.Connection, link_id: int) -> None:
    if conn.execute("DELETE FROM share_links WHERE id = ?", (link_id,)).rowcount == 0:
        raise ShareError("no such link")
    conn.commit()
    _cache.clear()


def find(conn: sqlite3.Connection, token: str, count: bool = True):
    """The live link for a token, or None (unknown, malformed, not started yet or expired). Counts the visit unless count=False."""
    if not TOKEN_RE.match(token or ""):
        return None
    row = conn.execute("SELECT * FROM share_links WHERE token = ?", (token,)).fetchone()
    now = utcnow()
    if row is None or (row["expires"] and row["expires"] <= now) or (row["valid_from"] and row["valid_from"] > now):
        return None
    if count:
        conn.execute("UPDATE share_links SET last_used = ?, views = views + 1 WHERE id = ?", (now, row["id"]))
        conn.commit()
    return row


# ---------------------------------------------------------------------------------------------- PIN
def access_key(link) -> str | None:
    """What a browser sends after the PIN was right (None = the link has no PIN). It changes when the PIN or the token does."""
    if not link["pin_hash"]:
        return None
    return hmac.new(link["pin_hash"].encode(), link["token"].encode(), hashlib.sha256).hexdigest()


def unlock(link, pin: str) -> str | None:
    if link["pin_hash"] and isinstance(pin, str) and users.verify_password(pin, link["pin_hash"]):
        return access_key(link)
    return None


def allowed(link, key: str | None) -> bool:
    expected = access_key(link)
    return expected is None or (isinstance(key, str) and hmac.compare_digest(key, expected))


def locked_page(link) -> dict:
    """All a visitor sees before the PIN is right."""
    options = options_of(link)
    return {"locked": True, "name": options["title"] or link["name"], "brand": options["brand"], "accent": options["accent"], "theme": options["theme"]}


# ---------------------------------------------------------------------------------------------- data
def public_data(conn: sqlite3.Connection, link) -> dict:
    """What a visitor of the link gets, with everything the link hides left out (cached for a few seconds)."""
    key = (link["id"], link["token"], link["name"], link["show_ips"], link["show_macs"], link["options"])
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    data = _build(conn, link)
    _cache.clear() if len(_cache) > 50 else None
    _cache[key] = (time.monotonic(), data)
    return data


def _build(conn: sqlite3.Connection, link) -> dict:
    opts = options_of(link)
    sections = opts["sections"]
    show_ips, show_macs = bool(link["show_ips"]), bool(link["show_macs"])
    s = stats.summary(conn)
    group_of = {r["id"]: r["group_id"] for r in conn.execute("SELECT id, group_id FROM devices")}
    scoped = bool(opts["group_ids"])
    in_scope = [d for d in s["device_list"] if not scoped or group_of.get(d["id"]) in opts["group_ids"]]
    ids = {d["id"] for d in in_scope}
    services = _services(conn, opts, ids if scoped else None)
    online = sum(1 for d in in_scope if d["online"])

    def shown(d) -> str:
        if opts["generic_names"] or (not show_ips and d["name"] == d["ip"]):
            return f"Device {d['id']}"  # a name that is only an address would leak it
        return d["name"]

    names = {d["id"]: shown(d) for d in in_scope}
    covered = maintenance.covered(conn)
    in_maintenance = [i for i in ids if i in covered]
    data = {
        "name": opts["title"] or link["name"], "mode": link["mode"], "sections": sections, "generated": s["generated"],
        "problem": s["problem"] if not scoped else any(c["state"] == "down" for c in services),
        "message": opts["message"], "brand": opts["brand"], "accent": opts["accent"], "theme": opts["theme"],
        "last_scan": (s["scans"]["last"] or {}).get("finished"),
        "maintenance": len(in_maintenance),
    }
    if "summary" in sections:
        data.update(devices_total=len(in_scope), devices_online=online, devices_offline=len(in_scope) - online)
    if "services" in sections:
        data["services"] = [{"name": c["name"], "state": c["state"]} for c in services]
    if "devices" in sections or "map" in sections:
        data.update(show_ips=show_ips, show_macs=show_macs, fields=opts["fields"], devices=[
            {"id": d["id"], "name": names[d["id"]], "online": d["online"], "maintenance": d["id"] in covered,
             "parent_id": d["parent_id"] if d["parent_id"] in ids else None,
             **({"type": d["type"]} if "type" in opts["fields"] else {}), **({"vendor": d["vendor"]} if "vendor" in opts["fields"] else {}),
             **({"last_seen": d["last_seen"]} if "last_seen" in opts["fields"] else {}),
             "ip": d["ip"] if show_ips else None, "mac": d["mac"] if show_macs else None}
            for d in in_scope])
    if "uptime" in sections:
        data["uptime"] = _uptime(conn, opts, ids if scoped else None, services)
    if "events" in sections:
        data["events"] = _events(conn, opts, ids if scoped else None, names, s["generated"])
    return data


def _services(conn: sqlite3.Connection, opts: dict, scope_ids: set[int] | None) -> list[dict]:
    checks = [c for c in stats._services(conn, utcnow())["checks"] if c["enabled"]]
    if opts["service_ids"]:
        checks = [c for c in checks if c["id"] in opts["service_ids"]]
    elif scope_ids is not None:
        device_of = {r["id"]: r["device_id"] for r in conn.execute("SELECT id, device_id FROM service_checks")}
        checks = [c for c in checks if device_of.get(c["id"]) in scope_ids]
    return checks


def _uptime(conn: sqlite3.Connection, opts: dict, scope_ids: set[int] | None, services: list[dict]) -> dict:
    """Availability of the always-on devices in scope (all devices when none is marked), per day, plus the services' last 24 hours."""
    days = opts["uptime_days"]
    rows = conn.execute("SELECT id, always_on FROM devices").fetchall()
    ids = [r["id"] for r in rows if scope_ids is None or r["id"] in scope_ids]
    core = [r["id"] for r in rows if r["always_on"] and r["id"] in ids]
    use = set(core or ids)
    now = utcnow()
    since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%dT00")
    daily: dict[str, list[int]] = {}
    if use and checkstats.current(conn):
        for r in conn.execute("SELECT device_id, substr(hour, 1, 10) AS day, SUM(up) AS u, SUM(n) AS n FROM checks_hourly WHERE hour >= ? GROUP BY device_id, day", (since,)):
            if r["device_id"] in use:
                acc = daily.setdefault(r["day"], [0, 0])
                acc[0] += r["u"] or 0
                acc[1] += r["n"] or 0
    today = datetime.now(timezone.utc).date()
    series = []
    for k in range(days - 1, -1, -1):
        day = (today - timedelta(days=k)).isoformat()
        up, n = daily.get(day, (0, 0))
        series.append({"day": day, "percent": round(100 * up / n, 2) if n else None})
    known = [d for d in series if d["percent"] is not None]
    return {
        "days": days, "daily": series, "percent": round(sum(d["percent"] for d in known) / len(known), 2) if known else None,
        "services": [{"name": c["name"], "percent": c["uptime_24h"]} for c in services if c.get("uptime_24h") is not None],
        "generated": now,
    }


def _events(conn: sqlite3.Connection, opts: dict, scope_ids: set[int] | None, names: dict[int, str], now: str) -> list[dict]:
    out = []
    marks = ",".join("?" for _ in PUBLIC_EVENTS)
    for r in conn.execute(f"SELECT ts, kind, device_id FROM events WHERE kind IN ({marks}) AND device_id IS NOT NULL ORDER BY id DESC LIMIT 400", list(PUBLIC_EVENTS)):
        if scope_ids is not None and r["device_id"] not in scope_ids:
            continue
        name = names.get(r["device_id"]) or f"Device {r['device_id']}"
        out.append({"ts": r["ts"], "text": f"{name} {PUBLIC_EVENTS[r['kind']]}"})
        if len(out) >= opts["event_limit"]:
            break
    return out
