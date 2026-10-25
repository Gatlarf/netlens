"""Analysis reports: what the digital engineer concluded, kept under an id.

INFORMATION ONLY. The engineer reads (read-only probes, the investigation of an incident) and reports. It never changes anything on a host. What to do about a finding is
for a person, or for another system that has the right to change things (an automation platform, a runbook tool, an AI agent with its own permissions).
That other system needs to know which problem is meant and to be able to fetch the analysis, so a report has:

  * a report id ("AR-12") and, for an incident, the incident id ("INC-3456": the id of the first event of the incident, stable);
  * a place to fetch it: GET /api/analysis/<id>, GET /api/insights/incidents/<incident id>/analysis, or the assistant (MCP) tools get_analysis_report /
    get_incident_analysis, which return the same document;
  * a push: the event `analysis_ready` goes to the alert channels that include it: a nice e-mail for people, JSON (with the whole report) for a webhook.

A report is generated automatically some minutes after an incident starts (so the probes that an alarm calls for have run) and on demand.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event, connect, get_setting, insert_id, set_setting, utcnow

log = logging.getLogger(__name__)
STAMP = "%Y-%m-%dT%H:%M:%SZ"
AUTO_AFTER = timedelta(minutes=10)         # an incident is analysed this long after it started (or at once when it is over)
DONE_KEY = "analysis.done"
BASE_URL_KEY = "analysis.base_url"
AUTO_KEY = "analysis.auto"
WORDS_KEY = "analysis.words"
WORDS_MODES = ("rules", "auto", "model")
WORDS_SYSTEM = ("You are an experienced systems engineer. Below are the findings of a read-only analysis of one or more hosts. Write a short summary in plain language for an administrator: "
                "what is most likely wrong, what supports that and what was ruled out. Two to five sentences, no lists, no advice to run commands, and only what the findings say. "
                "A finding that says names were withheld stays general.")
NOTE_BODY = ("This analysis was made from read-only probes and from what Netlens already knows. Nothing was changed on any host. "
             "Whoever acts on it (a person, an automation system) needs their own rights, and can fetch this report again with its id.")
NOTE = "Information only: " + NOTE_BODY
INCIDENT_RE = re.compile(r"\bINC-(\d+)\b", re.I)
REPORT_RE = re.compile(r"\bAR-(\d+)\b", re.I)


def incident_ref(incident_id: int | None) -> str | None:
    return f"INC-{incident_id}" if incident_id else None


def report_ref(report_id: int) -> str:
    return f"AR-{report_id}"


def auto_enabled(conn) -> bool:
    return (get_setting(conn, AUTO_KEY) or "1") != "0"


def set_auto(conn, on: bool) -> bool:
    set_setting(conn, AUTO_KEY, "1" if on else "0")
    conn.commit()
    return on


def words_mode(conn) -> str:
    """How the short summary of a report is written: "rules" (the built-in text only), "auto" (a language model when one is connected) or "model" (the model, and the report says when it was not available)."""
    value = get_setting(conn, WORDS_KEY) or "rules"
    return value if value in WORDS_MODES else "rules"


def set_words_mode(conn, mode: str) -> str:
    if mode not in WORDS_MODES:
        raise ValueError("the summary is written by 'rules', 'auto' or 'model'")
    set_setting(conn, WORDS_KEY, mode)
    conn.commit()
    return mode


def write_words(conn, doc: dict[str, Any], ask=None) -> None:
    """Adds `words` (a short plain-language summary by the language model) when the setting asks for it. The findings stay the built-in logic's; names are withheld from the model unless allowed."""
    from app import insights
    from app.hostprobe import service as probes

    doc["words"], doc["words_source"] = None, "rules"
    mode = words_mode(conn)
    if mode == "rules":
        return
    names_ok = bool(probes._load(conn)["names_to_llm"])
    facts = {"title": doc["title"], "devices": doc.get("devices", []), "symptom": doc.get("symptom", ""),
             "findings": [(f.get("llm_text") or "A finding with names was withheld.") if f.get("private") and not names_ok else f["text"] for f in doc["findings"] if f["level"] != "noise"][:12]}
    text = insights.complete(conn, WORDS_SYSTEM, json.dumps(facts, indent=1), names=list(doc.get("devices", [])), ask=ask, own_switch=True)
    if text:
        doc["words"], doc["words_source"] = text, "model"
    elif mode == "model":
        doc["words_source"] = "unavailable"


def base_url(conn) -> str:
    return (get_setting(conn, BASE_URL_KEY) or "").rstrip("/")


def set_base_url(conn, url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        raise ValueError("the address of this Netlens must start with http:// or https://")
    set_setting(conn, BASE_URL_KEY, url)
    conn.commit()
    return url


# ----------------------------------------------------------------------------- building
def _links(report_id: int, incident_id: int | None, base: str) -> dict[str, Any]:
    links: dict[str, Any] = {"report": f"{base}/api/analysis/{report_id}", "report_html": f"{base}/api/analysis/{report_id}/html",
                             "mcp": {"tool": "get_analysis_report", "arguments": {"report_id": report_id}}}
    if incident_id:
        links["incident"] = f"{base}/api/insights/incidents/{incident_id}/analysis"
        links["incident_page"] = f"{base}/#/insights"
        links["mcp_incident"] = {"tool": "get_incident_analysis", "arguments": {"incident_id": incident_id}}
    return links


def _finding(f: dict[str, Any]) -> dict[str, Any]:
    return {"level": f.get("level", "fact"), "text": f["text"], "probes": f.get("probes") or [], "private": bool(f.get("private")), "llm_text": f.get("llm_text"), "unusual": bool(f.get("unusual")),
            "weight": int(f.get("weight") or (70 if f.get("level") == "cause" else 30))}


def _causes(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings that name a cause, the one with most weight first (what the evidence of several probes together supports best)."""
    return sorted((f for f in findings if f["level"] == "cause"), key=lambda f: -f["weight"])


def _store(conn, doc: dict[str, Any], trigger: str) -> dict[str, Any]:
    write_words(conn, doc)
    doc["created"] = utcnow()
    doc["trigger"] = trigger
    doc["read_only"] = True
    doc["note"] = NOTE
    report_id = insert_id(conn, "INSERT INTO analysis_reports (kind, incident_id, device_id, created, trigger, title, cause, data) VALUES (?,?,?,?,?,?,?,?)",
                          (doc["kind"], doc.get("incident_id"), (doc.get("device_ids") or [None])[0], doc["created"], trigger, doc["title"][:200], (doc.get("probable_cause") or "")[:500], "{}"))
    doc["report_id"], doc["report_ref"] = report_id, report_ref(report_id)
    doc["incident_ref"] = incident_ref(doc.get("incident_id"))
    doc["links"] = _links(report_id, doc.get("incident_id"), base_url(conn))
    conn.execute("UPDATE analysis_reports SET data = ? WHERE id = ?", (json.dumps(doc, default=str), report_id))
    conn.commit()
    return doc


def create_for_incident(conn, incident_id: int, trigger: str = "manual", now: datetime | None = None) -> dict[str, Any] | None:
    """The analysis of an incident (the investigation, with what the host probes saw), stored under a new report id. None when the incident is gone."""
    from app import investigate

    rep = investigate.investigate(conn, incident_id, now=now)
    if rep is None:
        return None
    findings = [_finding(f) for f in rep["findings"] if f.get("level") != "noise"]
    causes = _causes(findings)
    cause = causes[0]["text"] if causes else None
    ruled = next((f["text"] for f in findings if f["text"].startswith("Ruled out")), None)
    doc = {"kind": "incident", "incident_id": incident_id, "device_ids": [d["id"] for d in rep["devices"]], "devices": [d["name"] for d in rep["devices"]],
           "title": rep["title"], "symptom": "", "window": {"start": rep["start"], "end": rep["end"], "resolved": rep["resolved"]}, "probable_cause": cause,
           "chains": [f["text"] for f in causes][:3], "findings": findings, "ruled_out": ruled,
           "left_out": [{"name": u["name"], "why": u["why"]} for u in rep["unrelated"]], "notified": [{"kind": n["kind"], "channels": n["channels"]} for n in rep.get("notifications", [])]}
    return _store(conn, doc, trigger)


def create_for_diagnosis(conn, diag: dict[str, Any], trigger: str = "manual") -> dict[str, Any]:
    """The analysis of one host (the digital engineer's diagnosis), stored under a new report id."""
    findings = [_finding(f) for f in diag["findings"]]
    chains = [c["text"] for c in diag.get("chains", [])]
    causes = _causes(findings)
    cause = causes[0]["text"] if causes else None
    ruled = next((f["text"] for f in findings if f["text"].startswith("Ruled out")), None)
    doc = {"kind": "diagnosis", "incident_id": None, "device_ids": [diag["device_id"]], "devices": [diag["device"]], "title": f"{diag['device']}: " + (diag.get("symptom") or "what is wrong?"),
           "symptom": diag.get("symptom") or "", "window": None, "probable_cause": cause, "chains": chains, "findings": findings, "ruled_out": ruled, "left_out": [], "notified": [],
           "looked_at": diag.get("taken", {}), "not_looked_at": diag.get("missing", [])}
    return _store(conn, doc, trigger)


# ----------------------------------------------------------------------------- reading
def get(conn, report_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT data FROM analysis_reports WHERE id = ?", (report_id,)).fetchone()
    if not r:
        return None
    doc = json.loads(r["data"])
    doc["links"] = _links(report_id, doc.get("incident_id"), base_url(conn))
    return doc


def latest_for_incident(conn, incident_id: int) -> dict[str, Any] | None:
    r = conn.execute("SELECT id FROM analysis_reports WHERE incident_id = ? ORDER BY id DESC LIMIT 1", (incident_id,)).fetchone()
    return get(conn, r["id"]) if r else None


def listing(conn, limit: int = 30, incident_id: int | None = None, device_id: int | None = None) -> list[dict[str, Any]]:
    where, args = [], []
    if incident_id:
        where.append("incident_id = ?")
        args.append(incident_id)
    if device_id:
        where.append("device_id = ?")
        args.append(device_id)
    sql = "SELECT id, kind, incident_id, device_id, created, trigger, title, cause FROM analysis_reports" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    return [{"report_id": r["id"], "report_ref": report_ref(r["id"]), "kind": r["kind"], "incident_id": r["incident_id"], "incident_ref": incident_ref(r["incident_id"]), "device_id": r["device_id"],
             "created": r["created"], "trigger": r["trigger"], "title": r["title"], "probable_cause": r["cause"] or None} for r in conn.execute(sql, (*args, max(1, min(int(limit), 200))))]


def prune(conn, days: int = 365) -> None:
    conn.execute("DELETE FROM analysis_reports WHERE created < ?", ((datetime.now(timezone.utc) - timedelta(days=days)).strftime(STAMP),))
    conn.commit()


# ----------------------------------------------------------------------------- the three shapes: text, HTML, JSON for other systems
def _title(doc: dict[str, Any]) -> str:
    return f"[Netlens] {doc['report_ref']}" + (f" / {doc['incident_ref']}" if doc.get("incident_ref") else "") + f": {doc['title']}"


def message_title(doc: dict[str, Any]) -> str:
    cause = doc.get("probable_cause")
    base = _title(doc)
    return (base + " — " + cause.removeprefix("Probable cause: "))[:200] if cause else base[:200]


def render_text(doc: dict[str, Any], hide_private: bool = False) -> str:
    lines = [f"{doc['report_ref']}" + (f"  ·  incident {doc['incident_ref']}" if doc.get("incident_ref") else "") + f"  ·  {doc['title']}"]
    if doc.get("window"):
        w = doc["window"]
        lines.append(f"From {w['start']}" + (f" to {w['end']}" if w["end"] != w["start"] else "") + f" ({'over' if w['resolved'] else 'still going'})")
    lines.append("")
    if doc.get("words"):
        lines += ["IN SHORT (written by a language model from the findings below)", doc["words"], ""]
    if doc.get("probable_cause"):
        lines += ["PROBABLE CAUSE", doc["probable_cause"].removeprefix("Probable cause: "), ""]
    shown = [f for f in doc["findings"] if f["text"] != doc.get("probable_cause") and not f["text"].startswith("Ruled out")]
    others = [f for f in shown if f["level"] == "cause"]
    normal = [f for f in shown if f.get("unusual") and f["level"] != "cause"]
    rest = [f for f in shown if not f.get("unusual") and f["level"] != "cause"]
    for heading, items in (("OTHER POSSIBLE CAUSES", others), ("WHAT WAS FOUND", rest), ("DIFFERENT FROM NORMAL", normal)):
        if items:
            lines.append(heading)
            lines += [f"  - {((f.get('llm_text') or 'A finding with names was withheld.') if f.get('private') and hide_private else f['text']).removeprefix('Probable cause: ')}" for f in items]
            lines.append("")
    if doc.get("ruled_out"):
        lines += [doc["ruled_out"], ""]
    if doc.get("notified"):
        lines += ["Alerts: " + "; ".join(f"{n['kind']}: " + (", ".join(n['channels']) if n['channels'] else "reached nobody") for n in doc["notified"][:4]), ""]
    lines += ["Fetch this report again:", f"  {doc['links']['report']}" + (f"\n  {doc['links'].get('incident', '')}" if doc.get("incident_ref") else ""),
              f"  assistant (MCP): get_analysis_report(report_id={doc['report_id']})", "", NOTE]
    return "\n".join(lines)


_COLORS = {"cause": "#b42318", "warn": "#b54708", "fact": "#344054"}


def render_chat(doc: dict[str, Any]) -> str:
    """For chat and push channels: short, with the ids, the cause and the best findings."""
    lines = [summary_line(doc)]
    if doc.get("words"):
        lines.append(doc["words"])
    top = [f["text"] for f in doc["findings"] if f["level"] in ("cause", "warn") and f["text"] != doc.get("probable_cause")][:4]
    lines += [f"- {t}" for t in top]
    lines += [f"Full report: {doc['links']['report_html']}" if doc["links"]["report_html"].startswith("http") else f"Fetch it: GET /api/analysis/{doc['report_id']} or MCP get_analysis_report({doc['report_id']})", "Information only: nothing was changed on any host."]
    return "\n".join(lines)


def render_html(doc: dict[str, Any]) -> str:
    e = html.escape
    parts = ['<!doctype html><html><body style="margin:0;background:#f2f4f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#101828">'
             '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">'
             '<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #e4e7ec">']
    parts.append(f'<tr><td style="background:#1d2939;color:#fff;padding:18px 24px"><div style="font-size:12px;letter-spacing:.08em;opacity:.75">NETLENS · DIGITAL ENGINEER</div>'
                 f'<div style="font-size:20px;font-weight:600;margin-top:4px">{e(doc["title"])}</div>'
                 f'<div style="font-size:13px;margin-top:6px;opacity:.85">{e(doc["report_ref"])}' + (f' · incident {e(doc["incident_ref"])}' if doc.get("incident_ref") else "")
                 + (f' · {e(doc["window"]["start"].replace("T", " ")[:16])}' + (f' to {e(doc["window"]["end"].replace("T", " ")[:16])}' if doc["window"]["end"] != doc["window"]["start"] else "") + f' UTC · {"over" if doc["window"]["resolved"] else "still going"}' if doc.get("window") else "") + '</div></td></tr>')
    if doc.get("words"):
        parts.append(f'<tr><td style="padding:18px 24px 0"><div style="font-size:12px;font-weight:700;color:#475467;letter-spacing:.06em">IN SHORT</div><div style="margin-top:6px;font-size:15px;line-height:1.5;color:#101828">{e(doc["words"])}</div>'
                     '<div style="margin-top:4px;font-size:11px;color:#98a2b3">Written by a language model from the findings below.</div></td></tr>')
    if doc.get("probable_cause"):
        parts.append(f'<tr><td style="padding:20px 24px 4px"><div style="font-size:12px;font-weight:700;color:#b42318;letter-spacing:.06em">PROBABLE CAUSE</div>'
                     f'<div style="margin-top:6px;padding:12px 14px;background:#fef3f2;border-left:4px solid #b42318;border-radius:6px;font-size:16px;line-height:1.45">{e(doc["probable_cause"].removeprefix("Probable cause: "))}</div></td></tr>')
    shown = [f for f in doc["findings"] if f["text"] != doc.get("probable_cause") and not f["text"].startswith("Ruled out")]
    for heading, items in (("Other possible causes", [f for f in shown if f["level"] == "cause"]), ("What was found", [f for f in shown if not f.get("unusual") and f["level"] != "cause"]),
                           ("Different from normal", [f for f in shown if f.get("unusual") and f["level"] != "cause"])):
        if not items:
            continue
        rows = "".join(f'<tr><td style="padding:6px 0;vertical-align:top;width:18px;color:{_COLORS.get(f["level"], "#344054")}">●</td><td style="padding:6px 0;font-size:14px;line-height:1.45;color:#344054">{e(f["text"].removeprefix("Probable cause: "))}'
                       + (f' <span style="color:#98a2b3;font-size:12px">[{e(", ".join(f["probes"]))}]</span>' if f.get("probes") else "") + "</td></tr>" for f in items)
        parts.append(f'<tr><td style="padding:16px 24px 0"><div style="font-size:12px;font-weight:700;color:#475467;letter-spacing:.06em">{e(heading.upper())}</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:4px">{rows}</table></td></tr>')
    if doc.get("ruled_out"):
        parts.append(f'<tr><td style="padding:12px 24px 0;font-size:13px;color:#027a48">✓ {e(doc["ruled_out"])}</td></tr>')
    if doc.get("left_out"):
        parts.append('<tr><td style="padding:12px 24px 0;font-size:13px;color:#667085">Left out as unrelated: ' + e("; ".join(f"{u['name']} ({u['why']})" for u in doc["left_out"][:4])) + "</td></tr>")
    if doc.get("notified"):
        parts.append('<tr><td style="padding:8px 24px 0;font-size:13px;color:#667085">Alerts: ' + e("; ".join(f"{n['kind']}: " + (", ".join(n["channels"]) if n["channels"] else "reached nobody") for n in doc["notified"][:4])) + "</td></tr>")
    link = doc["links"]
    parts.append('<tr><td style="padding:20px 24px 0"><div style="font-size:12px;font-weight:700;color:#475467;letter-spacing:.06em">FOR OTHER SYSTEMS</div>'
                 f'<div style="margin-top:6px;font-size:13px;line-height:1.6;color:#344054">Report <b>{e(doc["report_ref"])}</b>' + (f' of incident <b>{e(doc["incident_ref"])}</b>' if doc.get("incident_ref") else "")
                 + f'<br>JSON: <a href="{e(link["report"])}" style="color:#1570ef">{e(link["report"])}</a><br>Assistant (MCP): <code>get_analysis_report</code> with <code>report_id={doc["report_id"]}</code>'
                 + (f' or <code>get_incident_analysis</code> with <code>incident_id={doc["incident_id"]}</code>' if doc.get("incident_id") else "") + "</div></td></tr>")
    parts.append(f'<tr><td style="padding:20px 24px 24px"><div style="padding:10px 12px;background:#f9fafb;border:1px solid #e4e7ec;border-radius:6px;font-size:12px;line-height:1.5;color:#475467">'
                 f'<b>Information only.</b> {e(NOTE_BODY)}</div><div style="margin-top:10px;font-size:11px;color:#98a2b3">Created {e(doc["created"].replace("T", " ")[:16])} UTC by Netlens</div></td></tr>')
    parts.append("</table></td></tr></table></body></html>")
    return "".join(parts)


def payload(doc: dict[str, Any]) -> dict[str, Any]:
    """The report for another system (a webhook, an automation platform): the whole document, flat and stable."""
    return {"type": "netlens.analysis", "version": 1, "read_only": True, "report_id": doc["report_id"], "report_ref": doc["report_ref"], "incident_id": doc.get("incident_id"), "incident_ref": doc.get("incident_ref"),
            "kind": doc["kind"], "title": doc["title"], "created": doc["created"], "devices": doc["devices"], "device_ids": doc["device_ids"], "window": doc.get("window"), "symptom": doc.get("symptom", ""),
            "probable_cause": doc.get("probable_cause"), "summary": doc.get("words"), "summary_source": doc.get("words_source", "rules"), "chains": doc.get("chains", []), "findings": [{"level": f["level"], "text": f["text"], "probes": f["probes"], "unusual": f["unusual"], "weight": f["weight"]} for f in doc["findings"]],
            "ruled_out": doc.get("ruled_out"), "notified": doc.get("notified", []), "links": doc["links"], "note": NOTE}


# ----------------------------------------------------------------------------- telling people and systems
def summary_line(doc: dict[str, Any]) -> str:
    cause = (doc.get("probable_cause") or "").removeprefix("Probable cause: ")
    return f"{doc['report_ref']}" + (f" {doc['incident_ref']}" if doc.get("incident_ref") else "") + f": {doc['title']}" + (f". Probable cause: {cause}" if cause else ". No single cause stands out")


def announce(conn, doc: dict[str, Any]) -> int:
    """The event `analysis_ready`: the alert channels that include it send the report (e-mail: the nice version; webhook: the JSON)."""
    return add_event(conn, "analysis_ready", summary_line(doc)[:900], device_id=(doc.get("device_ids") or [None])[0])


def report_of_event(conn, event: dict[str, Any]) -> dict[str, Any] | None:
    m = REPORT_RE.search(event.get("detail") or "")
    return get(conn, int(m.group(1))) if m else None


def worth_announcing(doc: dict[str, Any]) -> bool:
    return bool(doc.get("probable_cause")) or sum(1 for f in doc["findings"] if f["level"] in ("cause", "warn")) >= 2


# ----------------------------------------------------------------------------- the schedule: an analysis for every incident
def _done(conn) -> list[int]:
    try:
        return [int(x) for x in json.loads(get_setting(conn, DONE_KEY) or "[]")]
    except (ValueError, TypeError):
        return []


def auto_analyse(conn, now: datetime | None = None) -> list[dict[str, Any]]:
    """Analyse the incidents that are old enough (or over) and have no report yet; announce the ones with something to say. Returns the new reports."""
    from app import incidents, licence

    now = now or datetime.now(timezone.utc)
    if not auto_enabled(conn) or not licence.allows(conn, "insights"):
        return []
    done = _done(conn)
    current = incidents.incidents(conn, 2, now=now)
    if get_setting(conn, DONE_KEY) is None:          # the first time: what already happened is history, not news (only incidents from now on are analysed by themselves)
        old = [i["id"] for i in current if i["resolved"] or now - datetime.strptime(i["start"], STAMP).replace(tzinfo=timezone.utc) >= AUTO_AFTER]
        set_setting(conn, DONE_KEY, json.dumps(old[-300:]))
        conn.commit()
        return []
    made = []
    for inc in current:
        if inc["id"] in done:
            continue
        started = datetime.strptime(inc["start"], STAMP).replace(tzinfo=timezone.utc)
        if not inc["resolved"] and now - started < AUTO_AFTER:
            continue
        doc = create_for_incident(conn, inc["id"], "auto", now)
        done.append(inc["id"])
        if doc:
            made.append(doc)
            if worth_announcing(doc):
                announce(conn, doc)
    if made:
        set_setting(conn, DONE_KEY, json.dumps(done[-300:]))
        conn.commit()
    return made


async def loop(db_path: str, interval: float = 60.0) -> None:
    await asyncio.sleep(45)
    while True:
        try:
            conn = connect(db_path)
            try:
                made = await asyncio.to_thread(auto_analyse, conn)
                if made:
                    from app.notify.channels import process_channels

                    await process_channels(db_path)
            finally:
                conn.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("analysis loop failed")
        await asyncio.sleep(interval)
