"""The DNS feature's database side: settings, the devices as the plan engine sees them, bookkeeping, and applying approved changes."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app.db import add_event, get_setting, set_setting, utcnow
from app.dns import names
from app.dns.plan import ACTIONABLE, MARKER, DnsDevice, DnsSettings, build_plan, parse_networks

SETTINGS_KEY = "dns.settings"
DEFAULTS: dict[str, Any] = {
    "plugin": "",              # the DNS plugin to use (empty: the first enabled one)
    "networks": "",            # "192.168.0.0/24 = home.example.com" per line
    "grace_hours": 2,
    "only_known": True,
    "skip_windows": True,
    "template": names.DEFAULT_TEMPLATE,
    "max_offline_days": 7,
    "remove": False,
    "auto_apply": False,
    "max_changes": 25,         # at most this many changes in one go (a runaway guard)
}


def get_settings(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        saved = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        saved = {}
    return {**DEFAULTS, **{k: v for k, v in (saved or {}).items() if k in DEFAULTS}}


def clean_settings(raw: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "plugin" in raw:
        out["plugin"] = str(raw["plugin"] or "")[:31]
    if "networks" in raw:
        text = str(raw["networks"] or "")[:2000]
        parse_networks(text)           # raises ValueError with a useful message
        out["networks"] = text.strip()
    if "template" in raw:
        template = str(raw["template"] or names.DEFAULT_TEMPLATE)[:80]
        if not re.fullmatch(r"(\{(type|vendor|mac4|mac6|ip)\}|[a-z0-9-])+", template.lower()):
            raise ValueError("the name pattern may only contain {type}, {vendor}, {mac4}, {mac6}, {ip}, letters, digits and hyphens")
        out["template"] = template
    for key, low, high in (("grace_hours", 0, 168), ("max_offline_days", 1, 3650), ("max_changes", 1, 500)):
        if key in raw:
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise ValueError(f"{key.replace('_', ' ')} must be a number between {low} and {high}")
            out[key] = value
    for key in ("only_known", "skip_windows", "remove", "auto_apply"):
        if key in raw:
            if not isinstance(raw[key], bool):
                raise ValueError(f"{key} must be true or false")
            out[key] = raw[key]
    return out


def save_settings(conn: sqlite3.Connection, raw: dict) -> dict[str, Any]:
    merged = {**get_settings(conn), **clean_settings(raw)}
    set_setting(conn, SETTINGS_KEY, json.dumps(merged))
    conn.commit()
    return merged


def engine_settings(values: dict[str, Any]) -> DnsSettings:
    return DnsSettings(
        networks=parse_networks(values["networks"]), grace_hours=float(values["grace_hours"]), only_known=bool(values["only_known"]),
        skip_windows=bool(values["skip_windows"]), template=values["template"], max_offline_days=int(values["max_offline_days"]), remove=bool(values["remove"]),
    )


def forward_zones(values: dict[str, Any]) -> list[str]:
    """The zones the plugin has to read (the reverse zones it finds by itself)."""
    return sorted({zone for _, zone in parse_networks(values["networks"])})


def plugin_config_extra(conn: sqlite3.Connection) -> dict[str, Any]:
    """What Netlens adds to a DNS plugin's own settings."""
    return {"zones": forward_zones(get_settings(conn)), "marker": MARKER}


def looks_like_windows(os_name: str | None, hints: list[str]) -> bool:
    text = " ".join([os_name or "", *hints]).lower()
    return "windows" in text or "msft 5.0" in text


# ----------------------------------------------------------------------------- the devices as the engine sees them
def load_devices(conn: sqlite3.Connection) -> list[DnsDevice]:
    states = {r["device_id"]: r for r in conn.execute("SELECT device_id, auto_name, first_missing FROM dns_state")}
    out = []
    for r in conn.execute(
        "SELECT id, primary_ip, mac, vendor, device_type, type_override, hostname, custom_name, dns_name, dns_mode, trusted, last_seen, os_name, hints FROM devices"
    ):
        try:
            hints = json.loads(r["hints"] or "[]")
        except ValueError:
            hints = []
        st = states.get(r["id"])
        out.append(DnsDevice(
            id=r["id"], ip=r["primary_ip"], mac=r["mac"], vendor=r["vendor"], type=r["type_override"] or r["device_type"], hostname=r["hostname"],
            custom_name=r["custom_name"], dns_name=r["dns_name"], dns_mode=r["dns_mode"] or "auto", trusted=bool(r["trusted"]), last_seen=r["last_seen"],
            windows=looks_like_windows(r["os_name"], hints), auto_name=st["auto_name"] if st else None, first_missing=st["first_missing"] if st else None,
        ))
    return out


def tracked_records(conn: sqlite3.Connection, plugin_id: str) -> frozenset:
    return frozenset((r["zone"], r["name"], r["type"], r["value"]) for r in conn.execute("SELECT zone, name, type, value FROM dns_records WHERE plugin_id = ?", (plugin_id,)))


def make_plan(conn: sqlite3.Connection, plugin_id: str, snapshot: dict, now: str | None = None, persist: bool = False) -> dict:
    """Compare the devices with a snapshot. `persist` also stores the bookkeeping (generated names, the grace clock): only the
    scan / refresh path does that, so that merely opening the page does not start any clock."""
    now = now or utcnow()
    plan = build_plan(load_devices(conn), snapshot, engine_settings(get_settings(conn)), now, tracked_records(conn, plugin_id))
    if persist:
        store_bookkeeping(conn, plan, now)
    return plan


def store_bookkeeping(conn: sqlite3.Connection, plan: dict, now: str) -> None:
    """Remember generated names (so they stay stable), since when a device has had no record, and the last state shown."""
    for item in plan["items"]:
        device_id = item["device_id"]
        if device_id is None:
            continue
        conn.execute(
            """
            INSERT INTO dns_state (device_id, auto_name, first_missing, state, reason, fqdn, updated) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                auto_name = COALESCE(excluded.auto_name, dns_state.auto_name), first_missing = excluded.first_missing,
                state = excluded.state, reason = excluded.reason, fqdn = excluded.fqdn, updated = excluded.updated
            """,
            (device_id, plan["auto_names"].get(device_id), plan["first_missing"].get(device_id), item["state"], item["reason"][:300], item["name"], now),
        )
    conn.commit()


# ----------------------------------------------------------------------------- applying
def select_changes(plan: dict, ids: list[str] | None, limit: int) -> list[dict]:
    """The changes of the actionable items the user approved (all of them when ids is None), at most `limit`."""
    wanted = set(ids) if ids is not None else None
    chosen: list[dict] = []
    for item in plan["items"]:
        if item["state"] not in ACTIONABLE:
            continue
        for change in item["changes"]:
            if wanted is None or change["id"] in wanted:
                chosen.append(change)
    if len(chosen) > limit:
        raise ValueError(f"{len(chosen)} changes are more than the limit of {limit} per run; approve fewer, or raise the limit in the DNS settings")
    return chosen


def record_results(conn: sqlite3.Connection, plugin_id: str, changes: list[dict], results: list[dict], now: str | None = None) -> dict[str, int]:
    """Remember what was written (so Netlens recognises its own records even on servers without comments) and log events."""
    now = now or utcnow()
    by_id = {c["id"]: c for c in changes}
    counts = {"added": 0, "updated": 0, "removed": 0, "failed": 0}
    for res in results:
        c = by_id[res["id"]]
        device_id = int(c["id"].split(":")[0]) if c["id"].split(":")[0].isdigit() else None
        label = f"{c['name']} {c['type']} {c['value']}"
        if not res["ok"]:
            counts["failed"] += 1
            add_event(conn, "dns_failed", f"{label}: {res['error'] or 'failed'}", device_id=device_id, now=now)
            continue
        if c["action"] in ("update", "delete"):
            old = c.get("old_value") if c["action"] == "update" else c["value"]
            conn.execute("DELETE FROM dns_records WHERE plugin_id = ? AND zone = ? AND name = ? AND type = ? AND value = ?", (plugin_id, c["zone"], c["name"], c["type"], old))
        if c["action"] in ("add", "update"):
            conn.execute(
                "INSERT OR REPLACE INTO dns_records (plugin_id, zone, name, type, value, device_id, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (plugin_id, c["zone"], c["name"], c["type"], c["value"], device_id, now),
            )
        if c["type"] != "PTR":      # one event per device change, not one for its reverse record too
            kind = {"add": "dns_registered", "update": "dns_updated", "delete": "dns_removed"}[c["action"]]
            counts[{"add": "added", "update": "updated", "delete": "removed"}[c["action"]]] += 1
            add_event(conn, kind, label, device_id=device_id, now=now)
    conn.commit()
    return counts
