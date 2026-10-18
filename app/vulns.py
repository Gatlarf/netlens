"""What a vulnerability plugin (Greenbone, Tenable, Rapid7 ...) reports, tied to the devices Netlens knows.

Every finding names a host by address and/or MAC address and is matched to a device the same way Netlens recognises devices everywhere else (MAC first,
then address). Findings are replaced as a whole at every sync, so a vulnerability that was fixed simply disappears. An event (`vuln_critical`) is written
only for a finding that is *new*: critical ones, and high ones that are known to be exploited, grouped per device so a fresh scan does not flood anyone.
The first sync of a plugin is the baseline: what is already there is not announced.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app import kev
from app.db import add_event, get_setting, set_setting

STAMP = "%Y-%m-%dT%H:%M:%SZ"
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_EVENTS = 20


def _seen_key(plugin_id: str) -> str:
    return f"vuln.baseline.{plugin_id}"


def serious(f: dict) -> bool:
    """Worth an event when it is new: critical, or high and known to be exploited."""
    return f["severity"] == "critical" or (f["severity"] == "high" and bool(f["exploited"]))


def apply_vulns(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict | None = None, now: datetime | None = None) -> dict:
    """Store a vulnerability plugin's output, match the findings to devices and announce the new serious ones. Returns the summary."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime(STAMP)
    before = {r["finding_id"] for r in conn.execute("SELECT finding_id FROM vuln_findings WHERE plugin_id = ?", (plugin_id,))}
    baseline = get_setting(conn, _seen_key(plugin_id)) is None
    for table in ("vuln_servers", "vuln_findings"):
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    by_mac = {r["mac"].lower(): r["id"] for r in conn.execute("SELECT id, mac FROM devices WHERE mac IS NOT NULL")}
    by_ip = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices WHERE primary_ip IS NOT NULL")}
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices")}
    for s in data["servers"]:
        conn.execute("INSERT INTO vuln_servers (plugin_id, server_id, name, version, online, last_scan, warnings, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, s["id"], s["name"], s["version"], int(s["online"]), s["last_scan"], json.dumps(s["warnings"]), stamp))
    listed = kev.known(conn)                            # the CISA list of exploited vulnerabilities, when it has been fetched
    matched = 0
    fresh: dict[int | None, list[dict]] = {}
    for f in data["findings"]:
        f = {**f, "exploited": bool(f["exploited"]) or any(c in listed for c in f["cve"])}
        device_id = by_mac.get(f["host_mac"]) if f["host_mac"] else None
        if device_id is None and f["host_ip"]:
            device_id = by_ip.get(f["host_ip"])
        matched += 1 if device_id is not None else 0
        conn.execute(
            """INSERT INTO vuln_findings (plugin_id, finding_id, server_id, device_id, host_ip, host_mac, host_name, title, cves, severity, score, port, proto, first_seen, last_seen,
                                          exploited, solution, url, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_id, f["id"], f["server_id"], device_id, f["host_ip"], f["host_mac"], f["host_name"], f["title"], json.dumps(f["cve"]), f["severity"], f["score"], f["port"], f["proto"],
             f["first_seen"], f["last_seen"], int(f["exploited"]), f["solution"], f["url"], stamp))
        if not baseline and f["id"] not in before and serious(f):
            fresh.setdefault(device_id, []).append({**f, "host": names.get(device_id) or f["host_name"] or f["host_ip"] or f["host_mac"]})
    set_setting(conn, _seen_key(plugin_id), stamp)
    events = 0
    for device_id, items in list(fresh.items())[:MAX_EVENTS]:
        items.sort(key=lambda f: (RANK[f["severity"]], -(f["score"] or 0)))
        first = items[0]
        label = ", ".join(first["cve"][:2]) if first["cve"] else ""
        text = f"{first['host']}: {len(items)} new serious vulnerabilit{'ies' if len(items) != 1 else 'y'}: {first['title']}" + (f" ({label})" if label else "") + (f" and {len(items) - 1} more" if len(items) > 1 else "")
        if any(f["exploited"] for f in items):
            text += ". At least one is known to be exploited"
        add_event(conn, "vuln_critical", text[:600], device_id=device_id, now=stamp, subject=f"vuln:{device_id}" if device_id is not None else None)
        events += 1
    conn.commit()
    return {"servers": len(data["servers"]), "findings": len(data["findings"]), "matched": matched, "events": events}


def remove_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    for table in ("vuln_servers", "vuln_findings"):
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    conn.execute("DELETE FROM settings WHERE key = ?", (_seen_key(plugin_id),))
    conn.commit()


# ----------------------------------------------------------------------------- for the API and the dashboard
def counts(conn: sqlite3.Connection) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for r in conn.execute("SELECT severity, COUNT(*) AS n FROM vuln_findings GROUP BY severity"):
        out[r["severity"]] = r["n"]
    return out


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Small figures for the dashboard and the statistics: findings by severity, devices affected, how many are known to be exploited."""
    c = counts(conn)
    devices = conn.execute("SELECT COUNT(DISTINCT device_id) FROM vuln_findings WHERE device_id IS NOT NULL AND severity IN ('critical', 'high')").fetchone()[0]
    exploited = conn.execute("SELECT COUNT(*) FROM vuln_findings WHERE exploited = 1").fetchone()[0]
    servers = conn.execute("SELECT COUNT(*) FROM vuln_servers").fetchone()[0]
    last = conn.execute("SELECT MAX(last_scan) FROM vuln_servers").fetchone()[0]
    return {"configured": servers > 0, "servers": servers, "counts": c, "total": sum(c.values()), "devices": devices, "exploited": exploited, "last_scan": last}


def _present(r: sqlite3.Row, names: dict[int, str]) -> dict[str, Any]:
    return {"plugin_id": r["plugin_id"], "id": r["finding_id"], "device_id": r["device_id"], "device": names.get(r["device_id"]) or r["host_name"] or r["host_ip"] or r["host_mac"],
            "host_ip": r["host_ip"], "title": r["title"], "cve": json.loads(r["cves"] or "[]"), "severity": r["severity"], "score": r["score"], "port": r["port"], "proto": r["proto"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "exploited": bool(r["exploited"]), "solution": r["solution"], "url": r["url"]}


def findings(conn: sqlite3.Connection, device_id: int | None = None, severity: str | None = None, q: str = "", limit: int = 500) -> list[dict[str, Any]]:
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices")}
    where, args = [], []
    if device_id is not None:
        where.append("device_id = ?")
        args.append(device_id)
    if severity in SEVERITIES:
        where.append("severity = ?")
        args.append(severity)
    rows = conn.execute("SELECT * FROM vuln_findings" + (" WHERE " + " AND ".join(where) if where else ""), args).fetchall()
    out = [_present(r, names) for r in rows]
    q = q.strip().lower()
    if q:
        out = [f for f in out if q in f"{f['title']} {f['device']} {f['host_ip'] or ''} {' '.join(f['cve'])}".lower()]
    out.sort(key=lambda f: (RANK[f["severity"]], not f["exploited"], -(f["score"] or 0), f["device"] or "", f["title"]))
    return out[:limit]


def top_devices(conn: sqlite3.Connection, limit: int = 8) -> list[dict[str, Any]]:
    """The devices with the most serious findings, worst first."""
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices")}
    rows = conn.execute("SELECT device_id, host_name, host_ip, severity, exploited FROM vuln_findings").fetchall()
    per: dict[Any, dict] = {}
    for r in rows:
        key = r["device_id"] if r["device_id"] is not None else (r["host_ip"] or r["host_name"])
        d = per.setdefault(key, {"device_id": r["device_id"], "device": names.get(r["device_id"]) or r["host_name"] or r["host_ip"], "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "exploited": 0})
        d[r["severity"]] += 1
        d["exploited"] += r["exploited"]
    ranked = sorted(per.values(), key=lambda d: (-d["critical"], -d["exploited"], -d["high"], -d["medium"], d["device"] or ""))
    return ranked[:limit]


def servers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [{"plugin_id": r["plugin_id"], "id": r["server_id"], "name": r["name"], "version": r["version"], "online": bool(r["online"]), "last_scan": r["last_scan"],
             "warnings": json.loads(r["warnings"] or "[]")} for r in conn.execute("SELECT * FROM vuln_servers ORDER BY name")]
