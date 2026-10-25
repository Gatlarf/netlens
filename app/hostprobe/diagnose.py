"""The digital engineer: from a symptom (or an incident) to a root cause, using the read-only probes.

1. plan      which probes answer this symptom? (rules; "what is wrong with this host" asks all of them)
2. collect   the newest snapshot of each, or a fresh one (live) -- always read-only, always in the audit log
3. analyze   each answer becomes evidence (app/hostprobe/analyze.py)
4. correlate evidence of different probes is chained: memory -> OOM kill -> restart loop -> log growth -> full disk
5. report    the chain with the most weight is the probable cause; the rest is context, and what was ruled out is said too

Names of files, folders and log lines are `private`: a language model only gets the `llm_text` of such a finding unless names are allowed.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from app.hostprobe import analyze, baseline, parse, scripts, service

PLANS = [
    (r"memory|\bram\b|oom|swap|out of memory|leak", ["memory", "apps", "cpu", "changes"]),
    (r"cpu|processor|load|busy|slow|sluggish|lag|freez|hang|unresponsive", ["cpu", "memory", "hardware", "schedule", "changes", "network"]),
    (r"network|bandwidth|latency|packet|ping|dns|connect|internet|wifi|throughput|timeout|timed out", ["network", "cpu", "apps", "changes"]),
    (r"disk|space|storage|full|filesystem|inode|i/o|io\b", ["storage", "hardware", "apps", "schedule", "changes"]),
    (r"crash|restart|reboot|down|stopped|failed|exit|container|service|application|app\b|unhealthy", ["apps", "memory", "cpu", "storage", "changes", "hardware"]),
    (r"secur|login|attack|brute|intrus|hack|breach|suspicious|exposed|patch|update|vulnerab", ["security", "changes", "network"]),
    (r"schedul|cron|timer|job|backup|nightly", ["schedule", "cpu", "storage", "network"]),
    (r"disk (fail|error)|smart|raid|zfs|hardware|temperature|overheat|power|ups", ["hardware", "storage", "memory"]),
]
ALL = list(scripts.PROBES)
MAX_AGE_S = 36 * 3600


def plan(symptom: str | None, metrics: list[str] | None = None) -> list[str]:
    """The probes that answer a symptom, the most useful first. A symptom nobody recognises asks for everything."""
    q = (symptom or "").lower()
    order: list[str] = []
    for pattern, probes in PLANS:
        if re.search(pattern, q):
            order += [p for p in probes if p not in order]
    for metric in metrics or []:
        for p in service.ALARM_PROBES.get(metric, []):
            if p not in order:
                order.append(p)
    return order or list(ALL)


def _epoch(stamp: str) -> float:
    return datetime.strptime(stamp, service.STAMP).replace(tzinfo=timezone.utc).timestamp()


def _pick(conn, device_id: int, probe: str, around: tuple[float, float] | None, now: float) -> dict[str, Any] | None:
    """The snapshot to use: the one closest to an incident (before it, or soon after), else the newest that is not too old."""
    if around:
        start, end = around
        near = [s for s in service.snapshots(conn, device_id, 40, with_data=True, probe=probe) if s["ok"] and s["data"] and start - 6 * 3600 <= _epoch(s["taken"]) <= end + 3 * 3600]
        if not near:
            return None
        # prefer one taken during the incident (an alarm look), then the nearest before it
        return min(near, key=lambda s: (0 if start - 600 <= _epoch(s["taken"]) <= end + 3600 else 1, abs(_epoch(s["taken"]) - start)))
    last = service.latest_ok(conn, device_id, probe=probe)
    if last and now - _epoch(last["taken"]) <= MAX_AGE_S:
        return {"taken": last["taken"], "mode": last["mode"], "data": last["data"], "ok": True}
    return None


def _storage_evidence(conn, device_id: int, name: str, around: tuple[float, float] | None, now: float) -> list[dict[str, Any]]:
    out = []
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime(service.STAMP)
    if around:
        found = service.explain(conn, device_id, iso(around[0]), iso(around[1]))
    else:
        snaps = [s for s in service.snapshots(conn, device_id, 3) if s["ok"]]
        found = None
        if len(snaps) >= 2:
            old, new = service.latest_ok(conn, device_id, before=snaps[1]["taken"]), service.latest_ok(conn, device_id)
            if old and new and old["id"] != new["id"]:
                found = {"from": old["taken"], "to": new["taken"], "baseline_is_later_than_start": False, **parse.compare(old["data"], new["data"])}
    if found and found["growth"]:
        top = found["growth"][0]
        lines = service.describe(found, 3)
        span = f"between the snapshots of {found['from'].replace('T', ' ')[:16]} and {found['to'].replace('T', ' ')[:16]} UTC"
        first = f"Probable cause: on {name}, {lines[0][0].lower() + lines[0][1:]} {span}."
        if found.get("baseline_is_later_than_start"):
            first += " (There is no snapshot from before the incident, so this is the growth since the first one.)"
        tags = ["disk_full", "disk_growth"]
        if top["kind"] == "container log":
            tags.append(f"log_growth:{top['path']}")
        out.append(analyze.ev("storage", "cause", 85, first, tags, private=True, llm_text=f"Probable cause: on {name} one {top['kind']} grew by {parse.nice_bytes(top['bytes'])} {span} (names withheld)."))
        for g, line in zip(found["growth"][1:3], lines[1:]):
            tags = [f"log_growth:{g['path']}"] if g["kind"] == "container log" else []
            out.append(analyze.ev("storage", "fact", 50, f"Also on {name}: {line[0].lower() + line[1:]}.", tags, private=True,
                                  llm_text=f"Also on {name}: another {g['kind']} grew by {parse.nice_bytes(g['bytes'])} (names withheld)."))
    last = service.latest_ok(conn, device_id)
    if last:
        for u in parse.unaccounted(last["data"]):
            out.append(analyze.ev("storage", "warn", 70, f"On {name}, {parse.describe_unaccounted(u)}.", ["disk_hidden"], private=True,
                                  llm_text=f"On {name}, {parse.nice_bytes(u['bytes'])} of {u['mount']} is not in any visible folder (names withheld)."))
        full = [m for m in last["data"]["mounts"] if m["size"] and m["used"] / m["size"] >= 0.9]
        if full and not out:
            m = full[0]
            top = [d for d in m["dirs"] if d["path"] != m["mount"]][:2]
            out.append(analyze.ev("storage", "warn", 60, f"{m['mount']} is {round(100 * m['used'] / m['size'])}% full" + (f"; the biggest folders are {top[0]['path']} ({parse.nice_bytes(top[0]['bytes'])})" + (f" and {top[1]['path']}" if len(top) > 1 else "") if top else "") + ".",
                                  ["disk_full"], private=True, llm_text=f"{m['mount']} is {round(100 * m['used'] / m['size'])}% full (names withheld)."))
        elif full:
            for e in out:
                if "disk_full" not in e["tags"]:
                    e["tags"].append("disk_full")
    return out


def analyze_device(conn, device_id: int, name: str, probes: list[str], around: tuple[float, float] | None = None, now: float | None = None) -> dict[str, Any]:
    """Evidence and chains from the snapshots that exist (no live run). `around` is an incident window (epoch start, end)."""
    now = now if now is not None else time.time()
    ctx: dict[str, Any] = {"onset": around[0] if around else None, "name": name}
    evidence: list[dict[str, Any]] = []
    taken, missing = {}, []
    for probe in probes:
        if probe == "storage":
            ev = _storage_evidence(conn, device_id, name, around, now)
            last_storage = service.latest_ok(conn, device_id)
            if last_storage:
                for e in baseline.compare("storage", last_storage["data"], service.history(conn, device_id, "storage", last_storage["taken"])):
                    e["at"] = _epoch(last_storage["taken"])
                    ev.append(e)
            snap = service.latest_ok(conn, device_id)
            if snap:
                taken[probe] = snap["taken"]
            else:
                missing.append(probe)
            evidence += ev
            continue
        snap = _pick(conn, device_id, probe, around, now)
        if snap is None:
            missing.append(probe)
            continue
        taken[probe] = snap["taken"]
        for e in analyze.analyze(probe, snap["data"], ctx):
            if e["at"] is None and probe not in ("changes", "schedule"):
                e["at"] = _epoch(snap["taken"])
            evidence.append(e)
        for e in baseline.compare(probe, snap["data"], service.history(conn, device_id, probe, snap["taken"])):          # and how it differs from normal
            e["at"] = _epoch(snap["taken"])
            evidence.append(e)
    chains = analyze.correlate(evidence, ctx)
    return {"evidence": evidence, "chains": chains, "taken": taken, "missing": missing}


def findings(result: dict[str, Any], name: str) -> list[dict[str, Any]]:
    """The report as findings in the form the investigation uses: {"level", "text", "private", "llm_text"}."""
    out = []
    for i, c in enumerate(result["chains"][:2]):
        out.append({"level": "cause", "text": f"Probable cause: {c['text']}", "private": c["private"], "llm_text": f"Probable cause: {c['llm_text']}" if c.get("llm_text") else None, "probes": c["probes"], "weight": c["weight"]})
    for e in sorted(result["evidence"], key=lambda e: -e["weight"]):
        if any(t.startswith("ok:") for t in e["tags"]) or (e["level"] == "fact" and e["weight"] < 25 and "cannot_read" not in e["tags"]):
            continue
        level = "cause" if e["level"] == "cause" else "warn" if e["level"] == "warn" and e["weight"] >= 60 else "fact"
        # a "Probable cause" sentence that is already the head of a chain is not repeated
        if e["text"].startswith("Probable cause") and any(c["private"] == e["private"] and e["text"][:60] == f"Probable cause: {c['text']}"[:60] for c in result["chains"][:2]):
            continue
        out.append({"level": level, "text": e["text"], "private": e["private"], "llm_text": e["llm_text"], "probes": [e["probe"]], "unusual": "unusual" in e["tags"], "weight": e["weight"]})
    ruled_out = sorted({t.split(":", 1)[1] for e in result["evidence"] for t in e["tags"] if t.startswith("ok:")})
    if ruled_out:
        words = {"cpu": "the processor", "memory": "memory", "changes": "recent changes", "schedule": "scheduled jobs"}
        out.append({"level": "fact", "text": "Ruled out: " + ", ".join(words.get(r, r) for r in ruled_out) + " (nothing unusual there).", "private": False, "llm_text": None, "probes": []})
    return out[:12]


def incident_findings(conn, device_id: int, name: str, start: str, end: str, symptoms: list[str] | None = None) -> list[dict[str, Any]]:
    """For the investigation of an incident: findings from the snapshots taken around it (an alarm makes the probes run while it is going on)."""
    around = (_epoch(start), _epoch(end))
    try:
        res = analyze_device(conn, device_id, name, plan(" ".join(symptoms or []), None) if symptoms else list(ALL), around=around)
    except Exception:  # noqa: BLE001 - the snapshots are an extra; they never break an investigation
        return []
    return findings(res, name)


def diagnose(conn, device_id: int, symptom: str | None = None, now: float | None = None) -> dict[str, Any]:
    """The report for one host from the snapshots that exist (see `diagnose_live` to look first)."""
    now = now if now is not None else time.time()
    row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (device_id,)).fetchone()
    name = row["n"] if row else f"device {device_id}"
    probes = plan(symptom)
    res = analyze_device(conn, device_id, name, probes, None, now)
    fl = findings(res, name)
    return {"device_id": device_id, "device": name, "symptom": symptom or "", "probes": probes, "taken": res["taken"], "missing": res["missing"], "chains": [{k: c[k] for k in ("text", "weight", "probes", "private", "llm_text")} for c in res["chains"]],
            "findings": fl, "cause": fl[0]["text"] if fl and fl[0]["level"] == "cause" else None}


async def diagnose_live(db_path: str, device_id: int, symptom: str | None, actor=None, probes: list[str] | None = None) -> dict[str, Any]:
    """Look first (the probes the symptom calls for, each in the audit log), then report."""
    from app.db import connect

    chosen = probes or plan(symptom)
    ran = await service.run_probes(db_path, device_id, chosen, actor=actor)
    conn = connect(db_path)
    try:
        out = diagnose(conn, device_id, symptom)
    finally:
        conn.close()
    out["ran"] = {p: {"ok": r["ok"], "error": r["error"], "mode": r["mode"]} for p, r in ran.items()}
    return out
