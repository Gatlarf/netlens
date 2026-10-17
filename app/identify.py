"""What is this device? A suggestion for devices Netlens could not name (a paid feature, see app/insights.py).

The rules come first: the clues the scanner already weighs (vendor, open ports, names, operating system), listed with their reasons. A language
model, when one is set up, may add its own reading of the same facts. Either way it is only a suggestion: nothing is changed until the user
applies it, with the normal device editor.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app import insights
from app.scanner.classify import DEVICE_TYPES
from app.scanner.store import classification_inputs, identification_report

SYSTEM = ("You identify devices on a home or office network from technical facts. Answer with one JSON object and nothing else: "
          '{"type": one of the allowed types, "name": a short friendly name such as "Living room TV", "confidence": "low"|"medium"|"high", "reason": one sentence}. '
          "Use only the facts given. If they do not tell, answer type \"unknown\" with confidence \"low\".")


def unknown_devices(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, custom_name, hostname, primary_ip, vendor, online, last_seen FROM devices WHERE type_override IS NULL AND COALESCE(device_type, 'unknown') = 'unknown' "
        "ORDER BY online DESC, last_seen DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "name": r["custom_name"] or r["hostname"] or r["primary_ip"], "ip": r["primary_ip"], "vendor": r["vendor"], "online": bool(r["online"]), "last_seen": r["last_seen"]} for r in rows]


def facts(conn: sqlite3.Connection, device_id: int) -> dict[str, Any]:
    inputs = classification_inputs(conn, device_id)
    ports = [{"port": r["port"], "service": r["service"] or "", "product": r["product"] or ""} for r in
             conn.execute("SELECT port, service, product FROM ports WHERE device_id = ? AND state LIKE 'open%' ORDER BY port LIMIT 25", (device_id,))]
    row = conn.execute("SELECT custom_name, hostname, first_seen FROM devices WHERE id = ?", (device_id,)).fetchone()
    out = {"vendor": inputs["vendor"], "operating_system": inputs["os_name"], "hostnames": inputs["hostnames"][:6], "open_ports": ports, "hints": [h for h in inputs["hints"] if isinstance(h, str)][:12],
           "first_seen": row["first_seen"] if row else None}
    return {k: v for k, v in out.items() if v not in (None, "", [])}


def _rules(evidence: list[dict], vendor: str | None) -> dict[str, Any] | None:
    if not evidence:
        return None
    top = evidence[0]
    word = re.split(r"[\s,.(]", vendor or "", 1)[0]
    return {"type": top["type"], "name": f"{word} {top['type']}".strip() if word else None, "confidence": "high" if top["weight"] >= 70 else "medium" if top["weight"] >= 40 else "low",
            "reason": top["why"]}


def _parse(text: str) -> dict[str, Any] | None:
    match = re.search(r"\{.*\}", text or "", re.S)
    try:
        doc = json.loads(match.group(0)) if match else None
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get("type") not in DEVICE_TYPES:
        return None
    conf = str(doc.get("confidence") or "low").lower()
    return {"type": doc["type"], "name": str(doc.get("name") or "")[:60] or None, "confidence": conf if conf in ("low", "medium", "high") else "low", "reason": str(doc.get("reason") or "")[:300]}


def suggest(conn: sqlite3.Connection, device_id: int, ask=None) -> dict[str, Any] | None:
    row = conn.execute("SELECT id, vendor, custom_name, hostname, primary_ip FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    evidence = identification_report(conn, device_id)["evidence"]
    known = facts(conn, device_id)
    payload = json.dumps({"allowed_types": [t for t in DEVICE_TYPES if t != "unknown"], "facts": known}, indent=1)
    names = [n for n in (row["custom_name"], row["hostname"], *known.get("hostnames", [])) if n]
    answer = insights.complete(conn, SYSTEM, payload, names=names, ask=ask)
    return {"device_id": device_id, "facts": known, "clues": evidence[:6], "rules": _rules(evidence, row["vendor"]), "model": _parse(answer) if answer else None}
