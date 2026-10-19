"""Two or three sentences at the top of the weekly report (a paid feature, see app/insights.py).

The sentences are written from the numbers of the report itself; a language model, when set up, may only rewrite them. It can be switched off
(Reports → Weekly report, which also has its own switch for the model) and the report is then the same as before.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from app import incidents, insights, relevance
from app.db import get_setting, set_setting

KEY = "reports.summary"                   # the old switch on the Insights page, used until the weekly report's own setting is saved
SYSTEM = ("You write the opening of a weekly network report for a home or small-business administrator: at most four plain sentences, no greeting, no advice. "
          "Use only the facts in the JSON and invent nothing. Mention what needs attention first, then how the week went.")


def _weekly(conn: sqlite3.Connection) -> dict:
    try:
        data = json.loads(get_setting(conn, "reports.weekly") or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def enabled(conn: sqlite3.Connection) -> bool:
    """The weekly report starts with a summary: the setting of the weekly report (Reports -> Weekly report), independent of the Insights page."""
    mine = _weekly(conn).get("summary")
    on = mine if isinstance(mine, bool) else get_setting(conn, KEY) != "0"
    return on and insights.allowed(conn)


def model_wanted(conn: sqlite3.Connection) -> bool:
    """The language model may word the summary: again a setting of the weekly report itself."""
    mine = _weekly(conn).get("summary_model")
    return mine if isinstance(mine, bool) else True


def set_enabled(conn: sqlite3.Connection, on: bool) -> None:
    set_setting(conn, KEY, "1" if on else "0")


def facts(conn: sqlite3.Connection, report: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    found = incidents.incidents(conn, 7, now, only=relevance.important_ids(conn))
    ev = report["events"]
    av = report["availability"]
    big = max(found, key=lambda i: (i["device_count"], i["events"]), default=None)
    return {"availability_pct": av["core_availability"] if av["core_devices"] else av["devices_availability"], "devices_online": f"{report['devices']['online']} of {report['devices']['total']}",
            "new_devices": report["devices"]["new_count"], "incidents": len(found), "biggest_incident": big["title"] if big else None, "unusual_readings": ev.get("anomaly", 0),
            "automatic_fixes": ev.get("remediation_ran", 0), "fixes_that_worked": ev.get("remediation_recovered", 0), "fixes_failed": ev.get("remediation_failed", 0),
            "disks_filling": len(report["filling"]), "health_problems_now": len(report["problems"]), "silent_sites": sum(1 for s in report["sites"] if s["state"] == "silent")}


def plain(f: dict[str, Any]) -> str:
    attention = f["disks_filling"] + f["health_problems_now"] + f["silent_sites"]
    first = (f"{attention} thing{'s' if attention != 1 else ''} need a look." if attention else "Nothing needs attention right now.")
    second = (f"The network was reachable {f['availability_pct']:g}% of the time" if f["availability_pct"] is not None else "There is no availability data yet")
    second += f", with {f['incidents']} incident{'s' if f['incidents'] != 1 else ''}" + (f" (the biggest: {f['biggest_incident']})" if f["biggest_incident"] else "") + "."
    extra = []
    if f["unusual_readings"]:
        extra.append(f"{f['unusual_readings']} reading{'s were' if f['unusual_readings'] != 1 else ' was'} unusual for the time of day")
    if f["automatic_fixes"]:
        extra.append(f"{f['automatic_fixes']} automatic fix{'es' if f['automatic_fixes'] != 1 else ''} ran, {f['fixes_that_worked']} clearly worked")
    if f["new_devices"]:
        extra.append(f"{f['new_devices']} new device{'s' if f['new_devices'] != 1 else ''} appeared")
    return " ".join([first, second] + ([("; ".join(extra)).capitalize() + "."] if extra else []))


def summary(conn: sqlite3.Connection, report: dict[str, Any], now: datetime | None = None, ask=None) -> str:
    f = facts(conn, report, now)
    text = insights.complete(conn, SYSTEM, json.dumps(f, indent=1), ask=ask, own_switch=True) if model_wanted(conn) else None
    return text or plain(f)
