"""On-call schedules (part of the same paid feature as escalation): who is notified, by day and hour.

A schedule has *people* (each with the alert channels that reach them), *shifts* (days of the week and hours, with the people who share it, rotating weekly or daily
or not at all), *overrides* (a swap or a holiday: this person, from now until then, wins over the shifts) and a *fallback* for the hours no shift covers. All times are
local time in the schedule's time zone.

Escalation uses it: put **whoever is on call** (`@oncall`) in a level and the alert goes to the channels of the people on call at that moment, instead of a fixed channel.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY = "oncall.schedule"
TOKEN = "@oncall"                       # what a level's channel list contains to mean "the channels of whoever is on call"
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
LOCAL = "%Y-%m-%dT%H:%M"
ROTATE = ("none", "weekly", "daily")
EPOCH_MONDAY = date(1970, 1, 5)
LIMITS = {"people": 20, "shifts": 20, "overrides": 50}


class OnCallError(ValueError):
    pass


def _zone(name: str):
    from zoneinfo import ZoneInfo

    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - no tz database or an unknown name
        return timezone.utc


def default_policy() -> dict[str, Any]:
    return {"enabled": False, "tz": "UTC", "people": [], "shifts": [], "overrides": [], "fallback": []}


def get_policy(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        doc = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        doc = {}
    policy = default_policy()
    for key in policy:
        if key in doc and isinstance(doc[key], type(policy[key])):
            policy[key] = doc[key]
    return policy


def _time(value: Any, what: str) -> str:
    if not isinstance(value, str) or not HHMM.match(value):
        raise OnCallError(f"{what}: a time looks like 08:00")
    return value


def _local(value: Any, what: str) -> str:
    try:
        return datetime.strptime(str(value), LOCAL).strftime(LOCAL)
    except ValueError:
        raise OnCallError(f"{what}: a date and time look like 2026-10-20T08:00")


def clean_policy(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    from app.notify.channels import load_channels

    known = {str(c.get("id")) for c in load_channels(conn)}
    tz = str(data.get("tz") or "UTC")
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{1,60}", tz):
        raise OnCallError("the time zone is not valid (for example Europe/Brussels)")
    people_in, shifts_in, overrides_in = data.get("people") or [], data.get("shifts") or [], data.get("overrides") or []
    if len(people_in) > LIMITS["people"] or len(shifts_in) > LIMITS["shifts"] or len(overrides_in) > LIMITS["overrides"]:
        raise OnCallError("too many people, shifts or overrides")
    people, ids = [], set()
    for i, p in enumerate(people_in, 1):
        name = str(p.get("name") or "").strip()[:40]
        if not name:
            raise OnCallError(f"person {i}: give a name")
        pid = str(p.get("id") or re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or f"p{i}")[:40]
        if pid in ids:
            raise OnCallError(f"two people are called {name}")
        channels = [str(c) for c in p.get("channels") or []]
        if any(c not in known for c in channels):
            raise OnCallError(f"{name}: choose channels that exist (Settings → Alert channels)")
        ids.add(pid)
        people.append({"id": pid, "name": name, "channels": channels})

    def members(value: Any, what: str) -> list[str]:
        listed = [str(x) for x in value or []]
        if any(x not in ids for x in listed):
            raise OnCallError(f"{what}: choose people from the list")
        return listed

    shifts = []
    for i, s in enumerate(shifts_in, 1):
        days = sorted({d for d in s.get("days") or [] if isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6})
        if not days:
            raise OnCallError(f"shift {i}: choose at least one day")
        start, end = _time(s.get("start"), f"shift {i}"), _time(s.get("end"), f"shift {i}")
        if start == end:
            raise OnCallError(f"shift {i}: the start and the end are the same time")
        rotate = str(s.get("rotate") or "none")
        if rotate not in ROTATE:
            raise OnCallError(f"shift {i}: rotate is none, weekly or daily")
        shift_people = members(s.get("people"), f"shift {i}")
        if not shift_people:
            raise OnCallError(f"shift {i}: choose who is on call")
        shifts.append({"name": str(s.get("name") or f"Shift {i}").strip()[:40], "days": days, "start": start, "end": end, "people": shift_people, "rotate": rotate})
    overrides = []
    for i, o in enumerate(overrides_in, 1):
        who = members([o.get("person")], f"override {i}")
        start, end = _local(o.get("from"), f"override {i}"), _local(o.get("to"), f"override {i}")
        if end <= start:
            raise OnCallError(f"override {i}: it must end after it starts")
        overrides.append({"person": who[0], "from": start, "to": end, "note": str(o.get("note") or "").strip()[:80]})
    policy = {"enabled": bool(data.get("enabled")), "tz": tz, "people": people, "shifts": shifts, "overrides": overrides, "fallback": members(data.get("fallback"), "the fallback")}
    return policy


def save_policy(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    set_setting(conn, KEY, json.dumps(clean_policy(conn, data)))
    conn.commit()
    return get_policy(conn)


# ----------------------------------------------------------------------------------------------- who is on call
def _pick(shift: dict, day: date) -> list[str]:
    """The person (or people) of a shift on a day: one of the group when it rotates, else all of them."""
    group = shift["people"]
    if shift["rotate"] == "none" or len(group) == 1:
        return list(group)
    step = (day - EPOCH_MONDAY).days // 7 if shift["rotate"] == "weekly" else (day - EPOCH_MONDAY).days
    return [group[step % len(group)]]


def _occurrences(policy: dict, first: date, last: date):
    """(start, end, shift name, people ids) of every shift that starts between two dates (local naive datetimes)."""
    out = []
    day = first
    while day <= last:
        for shift in policy["shifts"]:
            if day.weekday() not in shift["days"]:
                continue
            h1, m1 = map(int, shift["start"].split(":"))
            h2, m2 = map(int, shift["end"].split(":"))
            start = datetime(day.year, day.month, day.day, h1, m1)
            end = datetime(day.year, day.month, day.day, h2, m2)
            if end <= start:
                end += timedelta(days=1)                   # a night shift belongs to the day it starts
            out.append((start, end, shift["name"], _pick(shift, day)))
        day += timedelta(days=1)
    return out


def _to_utc(local: datetime, zone) -> datetime:
    return local.replace(tzinfo=zone).astimezone(timezone.utc)


def on_call(conn: sqlite3.Connection, now: datetime | None = None, policy: dict | None = None) -> dict[str, Any]:
    """Who is on call at `now`: {"people": [person dicts], "source": "override" | shift name | "fallback" | None, "until": ISO UTC or None}."""
    policy = policy or get_policy(conn)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    zone = _zone(policy["tz"])
    local = now.astimezone(zone).replace(tzinfo=None)
    by_id = {p["id"]: p for p in policy["people"]}
    found = [o for o in policy["overrides"] if o["from"] <= local.strftime(LOCAL) < o["to"]]
    if found:
        until = min(datetime.strptime(o["to"], LOCAL) for o in found)
        return {"people": [by_id[o["person"]] for o in found if o["person"] in by_id], "source": "override", "until": _to_utc(until, zone).strftime("%Y-%m-%dT%H:%M:%SZ")}
    for start, end, name, ids in sorted(_occurrences(policy, local.date() - timedelta(days=1), local.date()), key=lambda o: o[0]):
        if start <= local < end:
            return {"people": [by_id[i] for i in ids if i in by_id], "source": name, "until": _to_utc(end, zone).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return {"people": [by_id[i] for i in policy["fallback"] if i in by_id], "source": "fallback" if policy["fallback"] else None, "until": None}


def channels_now(conn: sqlite3.Connection, now: datetime | None = None) -> list[str]:
    """The channel ids of whoever is on call now (empty when the schedule is off or nobody is on call)."""
    policy = get_policy(conn)
    if not policy["enabled"]:
        return []
    out: list[str] = []
    for person in on_call(conn, now, policy)["people"]:
        out += [c for c in person["channels"] if c not in out]
    return out


def timeline(conn: sqlite3.Connection, now: datetime | None = None, days: int = 7) -> list[dict[str, Any]]:
    """The coming shifts and overrides, for the preview: [{from, to, name, people}] in local time, soonest first."""
    policy = get_policy(conn)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    zone = _zone(policy["tz"])
    local = now.astimezone(zone).replace(tzinfo=None)
    names = {p["id"]: p["name"] for p in policy["people"]}
    end_of = local + timedelta(days=days)
    rows = [{"from": s.strftime(LOCAL), "to": e.strftime(LOCAL), "name": n, "people": [names.get(i, i) for i in ids], "kind": "shift"}
            for s, e, n, ids in _occurrences(policy, local.date() - timedelta(days=1), end_of.date()) if e > local and s < end_of]
    rows += [{"from": o["from"], "to": o["to"], "name": o["note"] or "Override", "people": [names.get(o["person"], o["person"])], "kind": "override"}
             for o in policy["overrides"] if datetime.strptime(o["to"], LOCAL) > local and datetime.strptime(o["from"], LOCAL) < end_of]
    return sorted(rows, key=lambda r: (r["from"], r["kind"]))
