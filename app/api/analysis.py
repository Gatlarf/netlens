"""Analysis reports of the digital engineer (see app/analysis.py). INFORMATION ONLY: they describe, they never change anything on a host.
Administrators only (a report names devices, folders and log lines)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from app import analysis, audit, incidents, licence
from app.api.devices import get_conn
from app.auth import client_ip, require_admin

router = APIRouter(prefix="/api", tags=["analysis"])


def _who(request: Request):
    return getattr(request.state, "user", None)


def _insights(conn) -> None:
    if not licence.allows(conn, "insights"):
        raise HTTPException(status_code=402, detail="the analysis of incidents is part of the Insights feature: Settings → Licence")


def _doc(conn, report_id: int) -> dict[str, Any]:
    doc = analysis.get(conn, report_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="no such analysis report")
    return doc


@router.get("/analysis")
def list_reports(request: Request, limit: int = 30, incident_id: int | None = None, device_id: int | None = None, conn=Depends(get_conn)) -> dict[str, Any]:
    """The newest analysis reports (id, incident id, title, probable cause). Fetch one with /api/analysis/{id}."""
    require_admin(request)
    return {"reports": analysis.listing(conn, limit, incident_id, device_id), "read_only": True}


@router.get("/analysis/{report_id}")
def get_report(report_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """One analysis report as JSON: the ids, the probable cause, the findings, what was ruled out, and how to fetch it again."""
    require_admin(request)
    doc = _doc(conn, report_id)
    audit.record_read(conn, _who(request), client_ip(request), request.url.path, f"Opened analysis report {doc['report_ref']} ({doc['title'][:80]})")
    return {k: v for k, v in doc.items() if k != "facts"}


@router.get("/analysis/{report_id}/html", response_class=HTMLResponse)
def get_report_html(report_id: int, request: Request, conn=Depends(get_conn)) -> HTMLResponse:
    require_admin(request)
    return HTMLResponse(analysis.render_html(_doc(conn, report_id)))


@router.get("/analysis/{report_id}/text", response_class=PlainTextResponse)
def get_report_text(report_id: int, request: Request, conn=Depends(get_conn)) -> PlainTextResponse:
    require_admin(request)
    return PlainTextResponse(analysis.render_text(_doc(conn, report_id)))


@router.post("/analysis/{report_id}/send")
async def send_report(report_id: int, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Send a report now through the chosen alert channels (default: every enabled one): e-mail gets the formatted version, a webhook the JSON."""
    from app.notify import channels as ch

    require_admin(request)
    doc = _doc(conn, report_id)
    wanted = body.get("channels")
    chans = [c for c in ch.load_channels(conn) if c["enabled"] and (not wanted or str(c["id"]) in {str(x) for x in wanted})]
    if not chans:
        raise HTTPException(status_code=422, detail="no alert channel is switched on (Settings → Notifications → Channels)" if not wanted else "none of those channels is switched on")
    event = {"id": 0, "kind": "analysis_ready", "detail": analysis.summary_line(doc), "name": doc["devices"][0] if doc["devices"] else "", "ip": "", "device_id": (doc["device_ids"] or [None])[0]}
    sent, failed = [], []
    for c in chans:
        try:
            await asyncio.to_thread(ch._send_analysis, c, doc, event, ch.http_post, ch.send_mail)
            sent.append(c.get("name") or c["type"])
        except ch.ChannelError as exc:
            failed.append({"channel": c.get("name") or c["type"], "error": str(exc)})
    audit.record_by(conn, _who(request), client_ip(request), "POST", request.url.path, 200 if sent else 502,
                    f"Sent analysis report {doc['report_ref']} through: {', '.join(sent) or 'nothing (all failed)'}" + (f"; failed: {', '.join(f['channel'] for f in failed)}" if failed else ""))
    return {"sent": sent, "failed": failed, "report_ref": doc["report_ref"]}


@router.get("/insights/incidents/{incident_id}/analysis")
def incident_analysis(incident_id: int, request: Request, create: bool = True, conn=Depends(get_conn)) -> dict[str, Any]:
    """The newest analysis of an incident by its id (INC-<id>); one is made now when there is none and create is true. This is what an automation system asks for."""
    require_admin(request)
    _insights(conn)
    doc = analysis.latest_for_incident(conn, incident_id)
    if doc is None and create:
        doc = analysis.create_for_incident(conn, incident_id, "api")
    if doc is None:
        raise HTTPException(status_code=404, detail="no such incident (it is older than 30 days, or never existed)" if create else "no analysis of this incident yet")
    audit.record_read(conn, _who(request), client_ip(request), request.url.path, f"Fetched the analysis {doc['report_ref']} of incident {doc['incident_ref']}")
    return doc


@router.post("/insights/incidents/{incident_id}/analysis")
def new_incident_analysis(incident_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Analyse an incident again now (a new report id; the earlier ones are kept)."""
    require_admin(request)
    _insights(conn)
    doc = analysis.create_for_incident(conn, incident_id, "manual")
    if doc is None:
        raise HTTPException(status_code=404, detail="no such incident")
    return doc


@router.get("/events/{event_id}/incident")
def incident_of_event(event_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Which incident an event belongs to: an automation that received an alert (its `id`) learns the incident id and the newest analysis."""
    require_admin(request)
    found = incidents.incident_of(conn, event_id)
    if found is None:
        raise HTTPException(status_code=404, detail="that event is not part of an incident (or is older than 30 days)")
    latest = analysis.latest_for_incident(conn, found["id"])
    return {**found, "incident_id": found["id"], "incident_ref": analysis.incident_ref(found["id"]), "latest_report_id": latest["report_id"] if latest else None,
            "latest_report_ref": latest["report_ref"] if latest else None}
