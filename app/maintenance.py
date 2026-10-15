"""Maintenance windows: times when a device is expected to be unreachable (a mesh node that reboots every night, a planned update).

A window has a scope (everything, groups, chosen devices, optionally the devices behind them) and a schedule (weekly on chosen
days, or once). While a device is covered by an active window, the events that would raise an alarm about it (went offline,
came online, service down/up) are still recorded but tagged with the window's name, and the notification channels and the e-mail
digest leave them out (the events API shows the window name in `maintenance`). When a window ends and a device is still offline, one normal "offline" event follows.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from app.db import add_event, get_setting, set_setting

KEY = "maintenance_windows"
SILENCED = {"device_offline", "device_online", "service_down", "service_up", "metric_warning", "metric_critical", "metric_ok", "capacity_warning", "capacity_critical"}     # events a window holds back
DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
HHMM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
STAMP = "%Y-%m-%dT%H:%M:%SZ"


# ----------------------------------------------------------------------------- storage
def load_windows(conn: sqlite3.Connection) -> list[dict]:
    try:
        data = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    return [w for w in data if isinstance(w, dict) and w.get("id")] if isinstance(data, list) else []


def save_windows(conn: sqlite3.Connection, windows: list[dict]) -> None:
    set_setting(conn, KEY, json.dumps(windows))


def _ids(value, what: str) -> list[int]:
    if not isinstance(value, list) or any(isinstance(v, bool) or not isinstance(v, int) for v in value):
        raise ValueError(f"{what} must be a list of ids")
    return sorted(set(value))


def _stamp(value, what: str) -> str:
    try:
        return datetime.strptime(str(value), STAMP).strftime(STAMP)
    except ValueError:
        raise ValueError(f"{what} must look like 2026-10-12T01:00:00Z") from None


def clean_window(data: dict, current: dict | None = None) -> dict:
    """Validate what the browser sent and return the window as it is stored. Raises ValueError with a readable message."""
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 80:
        raise ValueError("give the window a name (at most 80 characters)")
    scope_in = data.get("scope") if isinstance(data.get("scope"), dict) else {}
    scope = {"all": bool(scope_in.get("all")), "groups": _ids(scope_in.get("groups", []), "groups"),
             "devices": _ids(scope_in.get("devices", []), "devices"), "behind": bool(scope_in.get("behind"))}
    if not (scope["all"] or scope["groups"] or scope["devices"]):
        raise ValueError("choose what the window covers: everything, a group or some devices")
    sched_in = data.get("schedule") if isinstance(data.get("schedule"), dict) else {}
    kind = sched_in.get("type")
    if kind == "weekly":
        days = _ids(sched_in.get("days", []), "days")
        if not days or any(not 0 <= d <= 6 for d in days):
            raise ValueError("choose at least one day of the week")
        start, end = str(sched_in.get("start") or ""), str(sched_in.get("end") or "")
        if not (HHMM.fullmatch(start) and HHMM.fullmatch(end)):
            raise ValueError("start and end must look like 03:00")
        if start == end:
            raise ValueError("start and end must differ (an end before the start means it runs past midnight)")
        schedule = {"type": "weekly", "days": days, "start": start, "end": end}
    elif kind == "once":
        start, end = _stamp(sched_in.get("start"), "start"), _stamp(sched_in.get("end"), "end")
        if end <= start:
            raise ValueError("the end must be after the start")
        schedule = {"type": "once", "start": start, "end": end}
    else:
        raise ValueError("the schedule must be weekly or once")
    tz = str(data.get("tz") or "UTC")
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{1,60}", tz):
        raise ValueError("invalid time zone")
    offset = data.get("offset_min", 0)
    if isinstance(offset, bool) or not isinstance(offset, int) or not -840 <= offset <= 840:
        raise ValueError("invalid UTC offset")
    return {"id": (current or {}).get("id") or secrets.token_hex(4), "name": name, "enabled": bool(data.get("enabled", True)),
            "scope": scope, "schedule": schedule, "tz": tz, "offset_min": offset, "manual": bool(data.get("manual", (current or {}).get("manual")))}


# ----------------------------------------------------------------------------- time
def _zone(window: dict):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(window["tz"])
    except Exception:  # noqa: BLE001 - no tz database or an unknown name: use the offset the browser gave
        return timezone(timedelta(minutes=window.get("offset_min", 0)))


def _occurrences(window: dict, now: datetime, days_back: int, days_ahead: int):
    """Start and end (aware) of every run of a weekly window that could touch [now - days_back, now + days_ahead]."""
    zone = _zone(window)
    local = now.astimezone(zone)
    sched = window["schedule"]
    sh, sm = map(int, sched["start"].split(":"))
    eh, em = map(int, sched["end"].split(":"))
    for offset in range(-days_back, days_ahead + 1):
        day = (local + timedelta(days=offset)).date()
        if day.weekday() not in sched["days"]:
            continue
        start = datetime(day.year, day.month, day.day, sh, sm, tzinfo=zone)
        end = datetime(day.year, day.month, day.day, eh, em, tzinfo=zone)
        if end <= start:
            end += timedelta(days=1)
        yield start, end


def _once(window: dict) -> tuple[datetime, datetime]:
    s = window["schedule"]
    return (datetime.strptime(s["start"], STAMP).replace(tzinfo=timezone.utc), datetime.strptime(s["end"], STAMP).replace(tzinfo=timezone.utc))


def is_active(window: dict, now: datetime) -> bool:
    if not window.get("enabled", True):
        return False
    if window["schedule"]["type"] == "once":
        start, end = _once(window)
        return start <= now < end
    return any(start <= now < end for start, end in _occurrences(window, now, 1, 0))


def current_end(window: dict, now: datetime) -> datetime | None:
    if not is_active(window, now):
        return None
    if window["schedule"]["type"] == "once":
        return _once(window)[1]
    return next(end for start, end in _occurrences(window, now, 1, 0) if start <= now < end)


def next_start(window: dict, now: datetime) -> datetime | None:
    if not window.get("enabled", True):
        return None
    if window["schedule"]["type"] == "once":
        start, _ = _once(window)
        return start if start > now else None
    starts = [start for start, _ in _occurrences(window, now, 0, 8) if start > now]
    return min(starts) if starts else None


def describe_schedule(window: dict) -> str:
    s = window["schedule"]
    if s["type"] == "once":
        return f"once, {s['start'].replace('T', ' ')[:-1]} to {s['end'].replace('T', ' ')[:-1]} UTC"
    days = s["days"]
    shown = "every day" if len(days) == 7 else ", ".join(DAY_NAMES[d] for d in days)
    return f"{shown} {s['start']}–{s['end']}"


# ----------------------------------------------------------------------------- scope
def device_ids(conn: sqlite3.Connection, window: dict) -> set[int]:
    scope = window["scope"]
    if scope["all"]:
        return {r["id"] for r in conn.execute("SELECT id FROM devices")}
    found = set(scope["devices"])
    if scope["groups"]:
        marks = ",".join("?" for _ in scope["groups"])
        found |= {r["id"] for r in conn.execute(f"SELECT id FROM devices WHERE group_id IN ({marks})", scope["groups"])}
    if scope["behind"] and found:
        from app.hierarchy import descendants, load_hierarchy

        _, hierarchy = load_hierarchy(conn)
        for d in list(found):
            found |= descendants(hierarchy, d)
    return found


def covered(conn: sqlite3.Connection, now: datetime | None = None) -> dict[int, str]:
    """Device id -> name of the active window that covers it, for every device in maintenance right now."""
    now = now or datetime.now(timezone.utc)
    out: dict[int, str] = {}
    for window in load_windows(conn):
        if is_active(window, now):
            for d in device_ids(conn, window):
                out.setdefault(d, window["name"])
    return out


def tag_for(conn: sqlite3.Connection, kind: str, device_id: int | None, now: str | None = None) -> str | None:
    """The window an event belongs to, when it is one a window holds back (used by add_event)."""
    if device_id is None or kind not in SILENCED:
        return None
    when = datetime.strptime(now, STAMP).replace(tzinfo=timezone.utc) if now else datetime.now(timezone.utc)
    return covered(conn, when).get(device_id)


# ----------------------------------------------------------------------------- after a window
def announce_still_down(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """A device that went offline during a window and is still offline now that no window covers it gets one ordinary offline
    event, so the alarm the window held back is not lost. Returns how many were announced."""
    now = now or datetime.now(timezone.utc)
    held = covered(conn, now)
    announced = 0
    for row in conn.execute("SELECT id, primary_ip FROM devices WHERE online = 0").fetchall():
        if row["id"] in held:
            continue
        last = conn.execute("SELECT kind, maintenance FROM events WHERE device_id = ? AND kind IN ('device_offline', 'device_online') ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        if last and last["kind"] == "device_offline" and last["maintenance"]:
            add_event(conn, "device_offline", f"{row['primary_ip'] or ''} still offline after maintenance '{last['maintenance']}'".strip(), device_id=row["id"], now=now.strftime(STAMP))
            announced += 1
    return announced
