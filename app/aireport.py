"""The AI report: what happened in a period and how the events hang together (a paid feature, see app/insights.py).

Netlens finds the connections itself, with plain logic: alerts that belong to one incident, devices that sit behind the same switch or host, things that were
changed shortly before a problem began, and problems that keep coming back or come at the same time of day. Each is a numbered finding with a strength
(strong, likely, possible). A language model, when one is set up, only WRITES the report from those findings, and every sentence it writes must name the
findings it rests on. Netlens checks that: a sentence without a valid finding number, or with a number that is not in the findings it cites, is thrown away.
So even a small model cannot invent a cause; at worst it words things clumsily or writes less. Without a model the report is the findings themselves.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app import changes, engineer, incidents, insights
from app.db import get_setting, set_setting, utcnow
from app.hierarchy import ancestors, device_name, load_hierarchy

PERIODS = {"6h": "the last 6 hours", "24h": "the last 24 hours", "3d": "the last 3 days", "7d": "the last 7 days"}
STRENGTH = {"strong": 0, "likely": 1, "possible": 2, "info": 3}
MAX_FINDINGS = 14
CHANGE_WINDOW = timedelta(minutes=30)       # a change this long before a problem is worth mentioning, never more than that
REPEATS = 3                                 # the same problem this often in the period is "recurring"
CHANGE_KINDS = {"device_new", "device_deleted", "ip_changed", "os_changed", "gateway_changed", "plugin_updated", "plugin_update_failed"}
SYSTEM = (
    "You write a short report for the administrator of a home or small-business network. You get numbered FINDINGS found by a monitoring program, each with a strength "
    "(strong, likely, possible, info). Write 3 to 6 lines. Each line is ONE plain sentence that ends with the numbers of the findings it is based on, in square brackets, "
    "for example [F2] or [F1,F4]. Use only facts from the findings: no other devices, causes, times or numbers. Say 'possibly' for findings marked possible. "
    "Put the most important first. Finish with at most two lines that start with CHECK: and say what to look at next, also ending with finding numbers. No greeting, no headings.\n"
    "Example:\nThe switch Core-1 went wrong at 03:10 and 4 devices behind it were unreachable [F1].\n"
    "A settings change by admin shortly before may be related [F2].\nCHECK: look at the power and cable of Core-1 [F1]."
)


def hours_of(period: str) -> int:
    return changes.PERIODS.get(period if period in PERIODS else "24h", 24)


def _ts(text: str) -> datetime:
    return datetime.strptime(text, changes.STAMP).replace(tzinfo=timezone.utc)


def _age(minutes: float) -> str:
    minutes = max(1, round(minutes))
    return f"{minutes} minute{'s' if minutes != 1 else ''}" if minutes < 90 else f"{minutes / 60:.1f} hours"


def collect(conn: sqlite3.Connection, period: str = "24h", now: datetime | None = None) -> dict[str, Any]:
    """The findings of a period, strongest first, each with an id F1, F2 ... (the model and the reader refer to them by that id)."""
    period = period if period in PERIODS else "24h"
    now = now or datetime.now(timezone.utc)
    hours = hours_of(period)
    since = (now - timedelta(hours=hours)).strftime(changes.STAMP)
    raw: list[dict[str, Any]] = []
    try:
        devices, hierarchy = load_hierarchy(conn)
    except sqlite3.Error:
        devices, hierarchy = {}, {}
    incs = [i for i in incidents.incidents(conn, days=max(1, -(-hours // 24)), now=now) if i["start"] >= since]
    made = changes.timeline(conn, period, include_audit=True, limit=400, now=now)["items"]
    made = [c for c in made if c["category"] == "settings" or c["kind"] in CHANGE_KINDS]

    for inc in incs[:8]:
        strength = "strong" if inc["cause"] else "likely"
        raw.append({"type": "incident", "strength": strength, "ts": inc["start"], "devices": inc["devices"][:6], "text": f"{inc['title']}. {inc['summary']}"})
        start = _ts(inc["start"])
        for c in sorted(made, key=lambda c: c["ts"], reverse=True):       # the nearest changes before it began
            gap = start - _ts(c["ts"])
            if timedelta(0) <= gap <= CHANGE_WINDOW:
                who = f" by {c['who']}" if c.get("who") else ""
                raw.append({"type": "change", "strength": "possible", "ts": c["ts"], "devices": [],
                            "text": f"{_age(gap.total_seconds() / 60)} before “{inc['title']}” began, this changed{who}: {c['text']}"})
                if sum(1 for r in raw if r["type"] == "change" and inc["title"] in r["text"]) >= 2:
                    break
        ids = inc.get("device_ids") or []
        if len(ids) >= 2 and not inc["cause"]:
            chains = [ancestors(hierarchy, i) for i in ids]
            shared = next((a for a in chains[0] if all(a in chain for chain in chains[1:]) and a not in ids), None)
            if shared is not None and shared in devices:
                raw.append({"type": "shared_parent", "strength": "likely", "ts": inc["start"], "devices": [device_name(devices[shared])],
                            "text": f"The {len(ids)} devices in “{inc['title']}” all sit behind {device_name(devices[shared])}, which did not report a problem itself: it, or the link to it, is a possible cause."})

    kinds = incidents.PROBLEMS - {"cert_expiring"}
    by_key: dict[tuple, list[str]] = defaultdict(list)
    for r in conn.execute("SELECT ts, device_id, kind FROM events WHERE ts >= ? AND maintenance IS NULL ORDER BY id", (since,)):
        if r["kind"] in kinds and r["device_id"] is not None:
            by_key[(r["device_id"], r["kind"])].append(r["ts"])
    for (dev, kind), stamps in by_key.items():
        if len(stamps) < REPEATS or dev not in devices:
            continue
        name, word = device_name(devices[dev]), incidents.WORDS.get(kind, kind.replace("_", " "))
        text = f"{name}: {word}, {len(stamps)} times in {PERIODS[period]}."
        hours_seen = Counter(_ts(s).hour for s in stamps)
        best = max(range(24), key=lambda h: (hours_seen[h] + hours_seen[(h + 1) % 24], hours_seen[h]))
        near = hours_seen[best] + hours_seen[(best + 1) % 24]
        if near >= REPEATS and near / len(stamps) >= 0.7:
            when = f"around {best:02d}:00 UTC" if hours_seen[best] == near else f"between {best:02d}:00 and {(best + 2) % 24:02d}:00 UTC"
            text += f" Most of them were {when}, so something may be scheduled then."
        raw.append({"type": "recurring", "strength": "likely" if near >= REPEATS else "possible", "ts": stamps[-1], "devices": [name], "text": text})

    if not raw:
        raw.append({"type": "quiet", "strength": "info", "ts": utcnow(), "devices": [], "text": f"No problems were recorded in {PERIODS[period]}."})
    raw.sort(key=lambda f: f["ts"], reverse=True)
    raw.sort(key=lambda f: STRENGTH[f["strength"]])           # stable: strongest first, newest first within a strength
    found = [{"id": f"F{n}", **f} for n, f in enumerate(raw[:MAX_FINDINGS], 1)]
    return {"period": period, "label": PERIODS[period], "since": since, "until": now.strftime(changes.STAMP), "findings": found,
            "counts": {"incidents": len(incs), "changes": len(made), "findings": len(found)}}


def plain_lines(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """The report without a model: the findings themselves, in order."""
    return [{"text": f["text"], "refs": [f["id"]], "kind": "line"} for f in facts["findings"][:6]]


def _prompt(facts: dict[str, Any]) -> str:
    lines = [f"Period: {facts['label']}.", "FINDINGS:"]
    lines += [f"{f['id']} ({f['strength']}): {f['text']}" for f in facts["findings"]]
    return "\n".join(lines)


NUMBER = re.compile(r"\d+(?:[.,:]\d+)*")


def _numbers(text: str) -> set[str]:
    return {n.replace(",", ".") for n in NUMBER.findall(text)}


def validate(raw: str, facts: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """The lines of a model's answer that can be trusted, and how many were thrown away. A line must name a finding that exists, and every number in it
    (except the finding numbers themselves) must also be in the findings it names or in the period."""
    by_id = {f["id"]: f for f in facts["findings"]}
    kept: list[dict[str, Any]] = []
    dropped = 0
    seen: set[str] = set()
    for line in (raw or "").splitlines():
        line = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", line.strip())
        if not line:
            continue
        check = bool(re.match(r"(?i)check\s*:", line))
        body = re.sub(r"(?i)^check\s*:\s*", "", line)
        refs: list[str] = []
        for group in re.findall(r"\[([^\]]*)\]", body):
            refs += [f"F{n}" for n in re.findall(r"F(\d+)", group, flags=re.I)]
        refs = [r for r in dict.fromkeys(refs) if r in by_id]
        text = re.sub(r"\s*\[[^\]]*\]", "", body).strip()
        text = re.sub(r"\s+([.,;])", r"\1", text)
        if not refs or len(text) < 8:
            dropped += 1
            continue
        corpus = " ".join(by_id[r]["text"] for r in refs) + " " + facts["label"]
        if not _numbers(text) <= _numbers(corpus):
            dropped += 1
            continue
        if text.lower() in seen:
            continue
        seen.add(text.lower())
        kept.append({"text": text[:400], "refs": refs, "kind": "check" if check else "line"})
    lines = [k for k in kept if k["kind"] == "line"][:6]
    checks = [k for k in kept if k["kind"] == "check"][:2]
    return lines + checks, dropped


def write(conn: sqlite3.Connection, period: str = "24h", ask=None, now: datetime | None = None, use_model: bool = True) -> dict[str, Any]:
    """Build the report, have the model word it when there is one, store it as the latest of its period and return it."""
    facts = collect(conn, period, now)
    names = [r[0] for r in conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) FROM devices") if r[0]] + [r["name"] for r in conn.execute("SELECT name FROM service_checks")]
    names += [d for f in facts["findings"] for d in f["devices"]]
    lines, dropped, source = [], 0, "plain"
    if use_model and (ask is not None or insights.llm_ready(conn)):
        answer = insights.complete(conn, SYSTEM, _prompt(facts), names=names, ask=ask)
        if answer:
            lines, dropped = validate(answer, facts)
            if any(k["kind"] == "line" for k in lines):
                source = "model"
            else:
                lines = []
    if not lines:
        lines = plain_lines(facts)
    report = {**facts, "lines": lines, "source": source, "model": engineer.settings(conn)["model"] if source == "model" else None, "dropped": dropped, "generated": utcnow()}
    set_setting(conn, f"aireport.{facts['period']}", json.dumps(report))
    return report


def latest(conn: sqlite3.Connection, period: str) -> dict[str, Any] | None:
    try:
        stored = json.loads(get_setting(conn, f"aireport.{period if period in PERIODS else '24h'}") or "null")
    except ValueError:
        return None
    return stored if isinstance(stored, dict) else None
