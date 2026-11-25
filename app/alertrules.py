"""Alert rules: decide which events are not sent, without losing them.

A muted event is still recorded (the event list, Home Assistant, the metrics and the log forwarding see it); it is only left out of the notifications, exactly like an event
inside a maintenance window or about a snoozed subject: it carries a tag ("Rule: <name>") and the channels skip tagged events.

Three kinds of rule:
  mute        "ignore these events for these devices" (optionally only at certain times)
  while_down  "ignore these events for these devices while that device is offline" (a dependency the network hierarchy does not know about)
  repeat      "after this many of the same event for a device within so many minutes, ignore the rest and tell me once"

A rule names the events (or all of them), the devices (all, a group, some devices, everything behind a device, an importance level, a type), optionally when it applies,
and by default never mutes the critical events that break through quiet hours. A few security events are never muted.

`decide` is one function used twice: live (while an event is being recorded) and as a replay of the last days, so what the preview says is what the rule would have done.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY = "alert.rules"
SUMMARY = "alerts_muted"
TAG_PREFIX = "Rule: "
TYPES = ("mute", "while_down", "repeat")
SCOPES = ("all", "group", "devices", "below", "tier", "type")
STAMP = "%Y-%m-%dT%H:%M:%SZ"
MAX_RULES = 50
MAX_IDS = 200
NEVER_MUTED = {"audit_tampered", "break_glass_login", "totp_recovery_used", "totp_reset", "approval_requested", SUMMARY}
ID = re.compile(r"^[a-z0-9]{3,16}$")
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class RuleError(ValueError):
    pass


def _critical() -> set[str]:
    from app.notify.channels import CRITICAL

    return CRITICAL


def _recovers() -> dict[str, str]:
    from app import incidents

    return incidents.RECOVERS


# ----------------------------------------------------------------------------- the rules as they are stored
def _ids(value: Any, name: str) -> list[int]:
    if not isinstance(value, list) or len(value) > MAX_IDS or not all(isinstance(x, int) and not isinstance(x, bool) and x > 0 for x in value):
        raise RuleError(f"{name} must be a list of numbers")
    return list(dict.fromkeys(value))


def clean_rule(raw: Any, known_kinds: set[str]) -> dict:
    """One rule as it is stored; raises RuleError with a sentence for the person."""
    if not isinstance(raw, dict):
        raise RuleError("a rule is an object")
    name = " ".join(str(raw.get("name") or "").split())[:60]
    if not name:
        raise RuleError("give the rule a name")
    kind = raw.get("type")
    if kind not in TYPES:
        raise RuleError("choose what kind of rule it is")
    kinds = raw.get("kinds")
    if not isinstance(kinds, list) or not kinds or len(kinds) > 100 or not all(isinstance(k, str) for k in kinds):
        raise RuleError("choose which events the rule is about")
    if "*" in kinds:
        kinds = ["*"]
    else:
        unknown = [k for k in kinds if k not in known_kinds]
        if unknown:
            raise RuleError(f"unknown event: {unknown[0]}")
        kinds = list(dict.fromkeys(kinds))
        if any(k in NEVER_MUTED for k in kinds):
            raise RuleError("security events (a tampered audit log, an emergency sign-in, a two-factor reset) cannot be muted")
    scope_raw = raw.get("scope") if isinstance(raw.get("scope"), dict) else {"type": "all"}
    stype = scope_raw.get("type", "all")
    if stype not in SCOPES:
        raise RuleError("choose which devices the rule is about")
    scope: dict[str, Any] = {"type": stype}
    if stype in ("group", "devices"):
        scope["ids"] = _ids(scope_raw.get("ids"), "the devices" if stype == "devices" else "the groups")
        if not scope["ids"]:
            raise RuleError("choose at least one " + ("device" if stype == "devices" else "group"))
    elif stype == "below":
        root = scope_raw.get("device_id")
        if isinstance(root, bool) or not isinstance(root, int) or root < 1:
            raise RuleError("choose the device whose devices the rule is about")
        scope["device_id"] = root
    elif stype == "tier":
        if scope_raw.get("value") not in ("critical", "normal", "low"):
            raise RuleError("choose an importance level")
        scope["value"] = scope_raw["value"]
    elif stype == "type":
        value = str(scope_raw.get("value") or "")
        if not re.fullmatch(r"[a-z0-9_-]{1,30}", value):
            raise RuleError("choose a device type")
        scope["value"] = value
    when = raw.get("when")
    if when:
        if not isinstance(when, dict):
            raise RuleError("the times must be an object")
        days = when.get("days")
        if not isinstance(days, list) or not days or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days):
            raise RuleError("choose the days the rule applies")
        start, end = str(when.get("from") or ""), str(when.get("to") or "")
        if not HHMM.match(start) or not HHMM.match(end):
            raise RuleError("the times must look like 22:00")
        when = {"days": sorted(set(days)), "from": start, "to": end}
    else:
        when = None
    rule: dict[str, Any] = {"id": raw.get("id") if isinstance(raw.get("id"), str) and ID.match(raw["id"]) else secrets.token_hex(4), "name": name, "enabled": raw.get("enabled", True) is not False,
                            "type": kind, "kinds": kinds, "recoveries": raw.get("recoveries", True) is not False, "scope": scope, "when": when,
                            "keep_critical": raw.get("keep_critical", True) is not False, "note": " ".join(str(raw.get("note") or "").split())[:200]}
    if kind == "while_down":
        dep = raw.get("device_id")
        if isinstance(dep, bool) or not isinstance(dep, int) or dep < 1:
            raise RuleError("choose the device that has to be offline")
        rule["device_id"] = dep
    if kind == "repeat":
        count, minutes = raw.get("count"), raw.get("minutes")
        if isinstance(count, bool) or not isinstance(count, int) or not 2 <= count <= 100:
            raise RuleError("the number of events must be between 2 and 100")
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 1440:
            raise RuleError("the time must be between 1 minute and 24 hours")
        per = raw.get("per", "device")
        if per not in ("device", "scope"):
            raise RuleError("count per device or for all the devices together")
        rule.update(count=count, minutes=minutes, per=per)
    return rule


def kinds_known() -> set[str]:
    from app.notify.channels import EVENT_LABELS

    return {k for k in EVENT_LABELS if k not in NEVER_MUTED}


def load(conn: sqlite3.Connection) -> list[dict]:
    try:
        data = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    known = kinds_known()
    out = []
    for raw in data if isinstance(data, list) else []:
        try:
            out.append(clean_rule(raw, known))
        except RuleError:
            continue                    # a rule that no longer makes sense (an event kind that was removed) is skipped, not fatal
    return out


def save_all(conn: sqlite3.Connection, rules: list[dict]) -> list[dict]:
    set_setting(conn, KEY, json.dumps(rules))
    conn.commit()
    invalidate()
    return rules


def upsert(conn: sqlite3.Connection, raw: Any) -> dict:
    rules = load(conn)
    rule = clean_rule(raw, kinds_known())
    existing = next((r for r in rules if r["id"] == rule["id"]), None) if isinstance(raw, dict) and raw.get("id") else None
    if existing is None:
        if len(rules) >= MAX_RULES:
            raise RuleError(f"at most {MAX_RULES} rules")
        rule["id"] = secrets.token_hex(4) if any(r["id"] == rule["id"] for r in rules) else rule["id"]
        rules.append(rule)
    else:
        rules = [rule if r["id"] == existing["id"] else r for r in rules]
    save_all(conn, rules)
    return rule


def remove(conn: sqlite3.Connection, rule_id: str) -> bool:
    rules = load(conn)
    kept = [r for r in rules if r["id"] != rule_id]
    if len(kept) == len(rules):
        return False
    save_all(conn, kept)
    return True


def set_enabled(conn: sqlite3.Connection, rule_id: str, enabled: bool) -> dict | None:
    rules = load(conn)
    hit = next((r for r in rules if r["id"] == rule_id), None)
    if hit is None:
        return None
    hit["enabled"] = bool(enabled)
    save_all(conn, rules)
    return hit


# ----------------------------------------------------------------------------- the decision
def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, STAMP).replace(tzinfo=timezone.utc)


def kind_matches(rule: dict, kind: str) -> bool:
    if "*" in rule["kinds"]:
        return True
    if kind in rule["kinds"]:
        return True
    return rule["recoveries"] and _recovers().get(kind) in rule["kinds"]            # the "back online" of a problem the rule is about


def in_window(when: dict | None, at: datetime, quiet: dict) -> bool:
    """Is this moment inside the rule's days and hours (in the time zone of the quiet-hours settings)? A window that runs past midnight belongs to the day it started."""
    if not when:
        return True
    from app.notify.channels import local_time

    local = local_time(at, quiet)
    t = local.strftime("%H:%M")
    start, end = when["from"], when["to"]
    day = local.weekday()
    if start == end:
        return day in when["days"]                                                    # the same time twice: the whole day
    if start < end:
        return day in when["days"] and start <= t < end
    if t >= start:
        return day in when["days"]
    if t < end:
        return (day - 1) % 7 in when["days"]
    return False


def in_scope(scope: dict, device_id: int | None, ctx: Any) -> bool:
    if scope["type"] == "all":
        return True
    if device_id is None:
        return False
    if scope["type"] == "devices":
        return device_id in scope["ids"]
    if scope["type"] == "below":
        return device_id in ctx.below(scope["device_id"])
    d = ctx.device(device_id)
    if d is None:
        return False
    if scope["type"] == "group":
        return d["group_id"] in scope["ids"]
    if scope["type"] == "tier":
        return d["tier"] == scope["value"]
    return d["type"] == scope["value"]


def decide(rule: dict, ev: dict, ctx: Any, quiet: dict) -> dict | None:
    """None, or {"mute": True, "summarise": bool} for an event {kind, device_id, ts}. ctx: device(id), below(root), is_down(id), recent(kind, since_ts) -> device ids."""
    if not rule["enabled"]:
        return None
    kind = ev["kind"]
    if kind in NEVER_MUTED or (rule["keep_critical"] and kind in _critical()) or not kind_matches(rule, kind):
        return None
    if rule["type"] == "while_down" and ev.get("device_id") == rule["device_id"]:
        return None                                                                   # what is said about the device itself is never held back by its own rule
    if not in_scope(rule["scope"], ev.get("device_id"), ctx):
        return None
    at = _parse(ev["ts"])
    if not in_window(rule["when"], at, quiet):
        return None
    if rule["type"] == "mute":
        return {"mute": True, "summarise": False}
    if rule["type"] == "while_down":
        return {"mute": True, "summarise": False} if ctx.is_down(rule["device_id"]) else None
    since = (at - timedelta(minutes=rule["minutes"])).strftime(STAMP)
    earlier = ctx.recent(kind, since)
    if rule["per"] == "device":
        seen = sum(1 for d in earlier if d == ev.get("device_id"))
    else:
        seen = sum(1 for d in earlier if in_scope(rule["scope"], d, ctx))
    if seen < rule["count"]:
        return None
    return {"mute": True, "summarise": seen == rule["count"]}


# ----------------------------------------------------------------------------- what it knows about the network, live
_below_cache: dict[tuple, tuple[float, set[int]]] = {}
_lock = threading.Lock()
BELOW_TTL = 20.0


def invalidate() -> None:
    with _lock:
        _below_cache.clear()


class LiveContext:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._devices: dict[int, dict | None] = {}

    def device(self, device_id: int) -> dict | None:
        if device_id not in self._devices:
            row = self.conn.execute("SELECT group_id, COALESCE(type_override, device_type, 'unknown') AS type, COALESCE(tier, 'normal') AS tier, online FROM devices WHERE id = ?", (device_id,)).fetchone()
            self._devices[device_id] = None if row is None else {"group_id": row["group_id"], "type": row["type"], "tier": row["tier"], "online": row["online"]}
        return self._devices[device_id]

    def is_down(self, device_id: int) -> bool:
        d = self.device(device_id)
        return d is not None and not d["online"]

    def below(self, root: int) -> set[int]:
        from app.db import main_file

        key = (main_file(self.conn), root)
        with _lock:
            hit = _below_cache.get(key)
            if hit and time.monotonic() - hit[0] < BELOW_TTL:
                return hit[1]
        from app.hierarchy import descendants, load_hierarchy

        _devices, hierarchy = load_hierarchy(self.conn)
        found = descendants(hierarchy, root) if root in hierarchy else set()
        with _lock:
            _below_cache[key] = (time.monotonic(), found)
        return found

    def recent(self, kind: str, since: str) -> list[int | None]:
        return [r[0] for r in self.conn.execute("SELECT device_id FROM events WHERE kind = ? AND ts >= ?", (kind, since))]


def tag(conn: sqlite3.Connection, kind: str, device_id: int | None, detail: str | None, now: str) -> str | None:
    """Used by add_event: the tag ("Rule: name") of an event a rule mutes, else None. A repeat rule that has just been exceeded also records one summary event."""
    if kind in NEVER_MUTED:
        return None
    rules = [r for r in load(conn) if r["enabled"]]
    if not rules:
        return None
    from app.notify.channels import load_quiet

    quiet = load_quiet(conn)
    ctx = LiveContext(conn)
    ev = {"kind": kind, "device_id": device_id, "ts": now}
    for rule in rules:
        result = decide(rule, ev, ctx, quiet)
        if result is None:
            continue
        if result["summarise"]:
            from app.db import add_event
            from app.notify.channels import EVENT_LABELS

            name = ""
            if device_id is not None:
                row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (device_id,)).fetchone()
                name = f"{row['n']}: " if row else ""
            what = EVENT_LABELS.get(kind, kind)
            add_event(conn, SUMMARY, f"{name}{rule['count']} “{what}” events within {rule['minutes']} minutes. The next ones are muted by the rule “{rule['name']}” until it is quiet for {rule['minutes']} minutes.",
                      device_id=device_id, now=now, subject=None)
        return TAG_PREFIX + rule["name"]
    return None


# ----------------------------------------------------------------------------- the preview: the same decision over the last days
class ReplayContext:
    def __init__(self, devices: dict[int, dict], below: dict[int, set[int]], down: set[int]):
        self._devices, self._below, self.down = devices, below, set(down)
        self._seen: dict[str, list[tuple[str, int | None]]] = {}

    def device(self, device_id: int) -> dict | None:
        return self._devices.get(device_id)

    def is_down(self, device_id: int) -> bool:
        return device_id in self.down

    def below(self, root: int) -> set[int]:
        return self._below.get(root, set())

    def recent(self, kind: str, since: str) -> list[int | None]:
        return [d for ts, d in self._seen.get(kind, []) if ts >= since]

    def add(self, ev: dict) -> None:
        self._seen.setdefault(ev["kind"], []).append((ev["ts"], ev.get("device_id")))
        if ev["kind"] == "device_offline" and ev.get("device_id") is not None:
            self.down.add(ev["device_id"])
        elif ev["kind"] == "device_online":
            self.down.discard(ev.get("device_id"))


def preview(conn: sqlite3.Connection, raw: Any, days: int = 7, limit: int = 20000) -> dict:
    """What a rule would have done to the events of the last `days` days: {"events", "muted", "by_kind", "examples"}. Only events that were not already held back count."""
    from app.hierarchy import descendants, load_hierarchy
    from app.notify.channels import load_quiet

    rule = clean_rule({**(raw if isinstance(raw, dict) else {}), "enabled": True}, kinds_known())
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, min(int(days), 30)))).strftime(STAMP)
    rows = [dict(r) for r in conn.execute("SELECT id, ts, kind, device_id, detail, maintenance FROM events WHERE ts >= ? ORDER BY id LIMIT ?", (since, limit))]
    devices = {r["id"]: {"group_id": r["group_id"], "type": r["type"], "tier": r["tier"]} for r in conn.execute(
        "SELECT id, group_id, COALESCE(type_override, device_type, 'unknown') AS type, COALESCE(tier, 'normal') AS tier FROM devices")}
    names = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
    roots = {rule["scope"]["device_id"]} if rule["scope"]["type"] == "below" else set()
    below: dict[int, set[int]] = {}
    if roots:
        _devs, hierarchy = load_hierarchy(conn)
        below = {root: descendants(hierarchy, root) if root in hierarchy else set() for root in roots}
    first: dict[int, str] = {}
    for e in rows:
        if e["kind"] in ("device_offline", "device_online") and e["device_id"] is not None:
            first.setdefault(e["device_id"], e["kind"])
    ctx = ReplayContext(devices, below, {d for d, k in first.items() if k == "device_online"})       # offline when the period began
    quiet = load_quiet(conn)
    out = {"days": days, "events": 0, "muted": 0, "by_kind": {}, "examples": [], "truncated": len(rows) >= limit}
    for e in rows:
        if e["kind"] in NEVER_MUTED:
            continue
        held = e["maintenance"] is not None and not str(e["maintenance"]).startswith(TAG_PREFIX)
        if not held:
            out["events"] += 1
            result = decide(rule, e, ctx, quiet)
            if result:
                out["muted"] += 1
                out["by_kind"][e["kind"]] = out["by_kind"].get(e["kind"], 0) + 1
                if len(out["examples"]) < 8:
                    out["examples"].append({"ts": e["ts"], "kind": e["kind"], "device": names.get(e["device_id"]) if e["device_id"] is not None else None, "detail": e["detail"]})
        ctx.add(e)
    return out


def muted_counts(conn: sqlite3.Connection, days: int = 7, now: datetime | None = None) -> dict[str, int]:
    """{rule name: how many events it muted in the last `days` days}."""
    since = ((now or datetime.now(timezone.utc)) - timedelta(days=days)).strftime(STAMP)
    return {r["maintenance"][len(TAG_PREFIX):]: r["n"] for r in conn.execute(
        "SELECT maintenance, COUNT(*) AS n FROM events WHERE maintenance LIKE ? AND ts >= ? GROUP BY maintenance", (TAG_PREFIX + "%", since))}
