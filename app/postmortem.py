"""Was the automatic fix worth it? A look back at one run of auto-remediation (a paid feature, see app/insights.py).

The verdict comes from the facts: did the problem go away after the run, how often has the same rule run on the same device lately, and at what
times. A fix that "works" every second night is not a fix. A language model, when set up, may only put the same facts into nicer words.
"""

from __future__ import annotations

import json
import sqlite3
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from app import insights

STAMP = "%Y-%m-%dT%H:%M:%SZ"
WINDOW = timedelta(minutes=60)
SYSTEM = ("You write at most four plain sentences for the administrator of a small network about one automatic fix and how well it worked. "
          "Use only the facts in the JSON, invent nothing, and if the fix keeps being needed say that the real cause should be found.")


def _ts(text: str) -> datetime:
    return datetime.strptime(text, STAMP).replace(tzinfo=timezone.utc)


def postmortem(conn: sqlite3.Connection, run_id: int, now: datetime | None = None) -> dict[str, Any] | None:
    now = now or datetime.now(timezone.utc)
    run = conn.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return None
    device = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (run["device_id"],)).fetchone() if run["device_id"] else None
    name = device["n"] if device else "the network"
    history = conn.execute("SELECT * FROM remediation_runs WHERE rule_id IS ? AND device_id IS ? AND state = 'ok' AND created >= ? AND created <= ? ORDER BY created",
                           (run["rule_id"], run["device_id"], (now - timedelta(days=30)).strftime(STAMP), run["created"])).fetchall()
    times = [_ts(r["created"]) for r in history]
    worked = sum(1 for r in history if r["recovered"])
    gaps = [(b - a).total_seconds() / 86400 for a, b in zip(times, times[1:])]
    hours = Counter(t.hour for t in times)
    usual_hour = hours.most_common(1)[0] if hours else None
    recent_14 = sum(1 for t in times if t >= _ts(run["created"]) - timedelta(days=14))
    if run["state"] != "ok":
        verdict, why = "failed", f"The fix itself failed: {run['result'] or 'no reason given'}."
    elif run["recovered"]:
        minutes = max(0, round((_ts(run["recovered"]) - _ts(run["finished"] or run["created"])).total_seconds() / 60))
        verdict, why = "worked", f"The problem went away within {minutes} minute{'s' if minutes != 1 else ''} after the fix."
    elif run["finished"] and now - _ts(run["finished"]) < WINDOW:
        verdict, why = "too_early", "It is too early to say: the problem has not gone away yet, but the fix only just ran."
    else:
        verdict, why = "no_effect", "The problem did not go away within an hour of the fix."
    recurring = recent_14 >= 3
    parts = [why]
    if len(history) > 1:
        parts.append(f"This rule has run {len(history)} times on {name} in the last 30 days and the problem went away after {worked} of them.")
    if gaps:
        parts.append(f"It comes back about every {statistics.median(gaps):.1f} days" + (f", most often around {usual_hour[0]:02d}:00 UTC" if usual_hour and usual_hour[1] >= 3 and usual_hour[1] >= len(times) / 2 else "") + ".")
    if recurring:
        parts.append("Because it keeps coming back, the fix is hiding a cause that is still there.")
    facts = {"rule": run["rule_name"], "device": name, "event": run["kind"], "verdict": verdict, "runs_30_days": len(history), "worked_30_days": worked, "median_days_between": round(statistics.median(gaps), 1) if gaps else None,
             "usual_hour_utc": usual_hour[0] if usual_hour and usual_hour[1] >= 3 else None, "recurring": recurring}
    return {"run_id": run_id, "verdict": verdict, "recurring": recurring, "summary": " ".join(parts), "facts": facts}


def narrate(conn: sqlite3.Connection, report: dict, ask=None) -> str | None:
    return insights.complete(conn, SYSTEM, json.dumps(report["facts"], indent=1), names=[report["facts"]["device"]], ask=ask)
