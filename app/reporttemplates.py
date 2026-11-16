"""Report templates: a named report with its own look (title, colour, logo, footer), content (which sections), subject (everything, or some groups, for a customer),
period and schedule, and who gets it by e-mail. A template makes the same report again and again; the document itself is made in app/reportdoc.py.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY = "report.templates"
LOGO_KEY = "report.logo."
SENT_KEY = "report.sent."
RESULT_KEY = "report.result."
SECTIONS = {
    "summary": "At a glance (health score, key figures, trend)",
    "availability": "Availability (devices and services, most downtime)",
    "incidents": "Incidents",
    "changes": "What changed",
    "capacity": "Capacity (disks that are filling up)",
    "health": "Problems now (health readings past their limits)",
    "vulnerabilities": "Vulnerabilities",
    "network": "Wi-Fi and internet connections",
    "devices": "Devices (types, new devices, offline now)",
}
PERIODS = {"7d": "The last 7 days", "30d": "The last 30 days", "month": "The last full month"}
FREQUENCIES = ("off", "weekly", "monthly")
MAX_TEMPLATES = 30
MAX_LOGO = 400_000
ID = re.compile(r"^[a-z0-9]{3,16}$")
COLOUR = re.compile(r"^#[0-9a-fA-F]{6}$")
EMAIL = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


class TemplateError(ValueError):
    pass


def _text(value: Any, name: str, limit: int, required: bool = False) -> str:
    text = " ".join(str(value or "").split())[:limit]
    if required and not text:
        raise TemplateError(f"{name}: fill this in")
    return text


def clean(raw: Any) -> dict:
    """One template as it is stored; raises TemplateError with a sentence for the person."""
    if not isinstance(raw, dict):
        raise TemplateError("a template is an object")
    name = _text(raw.get("name"), "the name", 60, required=True)
    sections = [s for s in (raw.get("sections") or []) if isinstance(s, str) and s in SECTIONS]
    sections = list(dict.fromkeys(sections))
    if not sections:
        raise TemplateError("choose at least one section")
    period = raw.get("period", "7d")
    if period not in PERIODS:
        raise TemplateError("choose the period the report covers")
    accent = raw.get("accent") or "#2563eb"
    if not isinstance(accent, str) or not COLOUR.match(accent):
        raise TemplateError("the colour must look like #2563eb")
    scope_raw = raw.get("scope") if isinstance(raw.get("scope"), dict) else {"type": "all"}
    scope: dict[str, Any] = {"type": "all"}
    if scope_raw.get("type") == "group":
        ids = scope_raw.get("ids")
        if not isinstance(ids, list) or not ids or len(ids) > 100 or not all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids):
            raise TemplateError("choose at least one group")
        scope = {"type": "group", "ids": list(dict.fromkeys(ids))}
    elif scope_raw.get("type") not in (None, "all"):
        raise TemplateError("the report is about everything or about some groups")
    sched = raw.get("schedule") if isinstance(raw.get("schedule"), dict) else {}
    frequency = sched.get("frequency", "off")
    if frequency not in FREQUENCIES:
        raise TemplateError("the schedule is off, weekly or monthly")

    def number(key: str, low: int, high: int, default: int) -> int:
        v = sched.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
            raise TemplateError(f"{key} must be from {low} to {high}")
        return v

    schedule = {"frequency": frequency, "weekday": number("weekday", 0, 6, 0), "hour": number("hour", 0, 23, 7), "monthday": number("monthday", 1, 28, 1)}
    recipients = raw.get("recipients") or []
    if isinstance(recipients, str):
        recipients = [r for r in re.split(r"[,;\s]+", recipients) if r]
    if not isinstance(recipients, list) or len(recipients) > 30 or not all(isinstance(r, str) and EMAIL.match(r.strip()) for r in recipients):
        raise TemplateError("the e-mail addresses are not valid")
    channel = raw.get("channel_id")
    if channel is not None and not (isinstance(channel, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", channel)):
        raise TemplateError("choose the e-mail channel to send through")
    tid = raw.get("id") if isinstance(raw.get("id"), str) and ID.match(raw["id"]) else secrets.token_hex(4)
    return {
        "id": tid, "name": name, "enabled": raw.get("enabled", True) is not False,
        "title": _text(raw.get("title"), "the title", 80) or name, "subtitle": _text(raw.get("subtitle"), "the subtitle", 120), "prepared_for": _text(raw.get("prepared_for"), "prepared for", 80),
        "accent": accent.lower(), "footer": _text(raw.get("footer"), "the footer", 160), "show_netlens": raw.get("show_netlens", True) is not False,
        "sections": sections, "period": period, "scope": scope, "schedule": schedule,
        "recipients": [r.strip() for r in recipients], "channel_id": channel or None, "attach_pdf": raw.get("attach_pdf", True) is not False,
    }


def load(conn: sqlite3.Connection) -> list[dict]:
    try:
        data = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    out = []
    for raw in data if isinstance(data, list) else []:
        try:
            out.append(clean(raw))
        except TemplateError:
            continue
    return out


def get(conn: sqlite3.Connection, template_id: str) -> dict | None:
    return next((t for t in load(conn) if t["id"] == template_id), None)


def _save(conn: sqlite3.Connection, templates: list[dict]) -> None:
    set_setting(conn, KEY, json.dumps(templates))
    conn.commit()


def upsert(conn: sqlite3.Connection, raw: Any) -> dict:
    templates = load(conn)
    tpl = clean(raw)
    wanted = raw.get("id") if isinstance(raw, dict) else None
    if wanted and any(t["id"] == wanted for t in templates):
        templates = [tpl if t["id"] == wanted else t for t in templates]
    else:
        if len(templates) >= MAX_TEMPLATES:
            raise TemplateError(f"at most {MAX_TEMPLATES} templates")
        if any(t["id"] == tpl["id"] for t in templates):
            tpl["id"] = secrets.token_hex(4)
        templates.append(tpl)
    _save(conn, templates)
    return tpl


def remove(conn: sqlite3.Connection, template_id: str) -> bool:
    templates = load(conn)
    kept = [t for t in templates if t["id"] != template_id]
    if len(kept) == len(templates):
        return False
    _save(conn, kept)
    conn.execute("DELETE FROM settings WHERE key IN (?, ?, ?)", (LOGO_KEY + template_id, SENT_KEY + template_id, RESULT_KEY + template_id))
    conn.commit()
    return True


# ---- the logo ------------------------------------------------------------------------------------------------------
def set_logo(conn: sqlite3.Connection, template_id: str, data: bytes) -> dict:
    """Keep a logo (PNG or JPEG) for a template. The picture is checked by the same reader the PDF uses, so what is accepted here can be drawn."""
    from app import pdfimage

    if get(conn, template_id) is None:
        raise TemplateError("no such template")
    if len(data) > MAX_LOGO:
        raise TemplateError(f"the picture is larger than {MAX_LOGO // 1000} KB")
    try:
        image = pdfimage.load(data)
    except pdfimage.ImageError as exc:
        raise TemplateError(str(exc)) from None
    kind = pdfimage.sniff(data)
    set_setting(conn, LOGO_KEY + template_id, json.dumps({"type": "image/png" if kind == "png" else "image/jpeg", "data": base64.b64encode(data).decode(), "width": image["width"], "height": image["height"]}))
    conn.commit()
    return {"type": kind, "width": image["width"], "height": image["height"], "bytes": len(data)}


def get_logo(conn: sqlite3.Connection, template_id: str) -> tuple[bytes, str] | None:
    try:
        raw = json.loads(get_setting(conn, LOGO_KEY + template_id) or "null")
        return base64.b64decode(raw["data"]), raw["type"]
    except (ValueError, TypeError, KeyError):
        return None


def clear_logo(conn: sqlite3.Connection, template_id: str) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (LOGO_KEY + template_id,))
    conn.commit()


# ---- the schedule ----------------------------------------------------------------------------------------------------
def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def last_sent(conn: sqlite3.Connection, template_id: str) -> str | None:
    return get_setting(conn, SENT_KEY + template_id) or None


def mark_sent(conn: sqlite3.Connection, template_id: str, now: datetime) -> None:
    set_setting(conn, SENT_KEY + template_id, now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    conn.commit()


def due(conn: sqlite3.Connection, tpl: dict, now: datetime | None = None) -> bool:
    """Time for this template: switched on, scheduled, the chosen weekday (or day of the month) and hour reached (the clock of the server), and not yet sent for it."""
    sched = tpl["schedule"]
    if not tpl["enabled"] or sched["frequency"] == "off":
        return False
    now = (now or datetime.now(timezone.utc)).astimezone()
    if sched["frequency"] == "weekly":
        scheduled = (now - timedelta(days=(now.weekday() - sched["weekday"]) % 7)).replace(hour=sched["hour"], minute=0, second=0, microsecond=0)
        if scheduled > now:
            scheduled -= timedelta(days=7)
    else:
        scheduled = now.replace(day=sched["monthday"], hour=sched["hour"], minute=0, second=0, microsecond=0)
        if scheduled > now:
            last_month = (now.replace(day=1) - timedelta(days=1)).replace(day=sched["monthday"], hour=sched["hour"], minute=0, second=0, microsecond=0)
            scheduled = last_month
    last = last_sent(conn, tpl["id"])
    return not last or _parse(last) < scheduled.astimezone(timezone.utc)
