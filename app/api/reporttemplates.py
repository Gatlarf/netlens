"""Report templates and the reports made from them (app/reporttemplates.py, app/reportdoc.py). Administrators only."""
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from app import groups as groups_mod, pdfimage, reportdoc, reportjobs, reporttemplates as rt
from app.api.devices import get_conn
from app.db import get_setting
from app.notify import channels as ch

router = APIRouter(prefix="/api", tags=["report templates"])


class SendBody(BaseModel):
    to: list[str] | None = None
    period: str | None = None
    month: str | None = None


def _present(conn, tpl: dict) -> dict:
    try:
        last = json.loads(get_setting(conn, rt.RESULT_KEY + tpl["id"]) or "null")
    except ValueError:
        last = None
    return {**tpl, "has_logo": rt.get_logo(conn, tpl["id"]) is not None, "last_sent": rt.last_sent(conn, tpl["id"]), "last_result": last}


def _need(conn, template_id: str) -> dict:
    tpl = rt.get(conn, template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="no such report")
    return tpl


@router.get("/report-templates")
def list_templates(conn=Depends(get_conn)) -> dict:
    mails = [{"id": c["id"], "name": c["name"], "enabled": c["enabled"]} for c in ch.load_channels(conn) if c["type"] == "email"]
    return {"templates": [_present(conn, t) for t in rt.load(conn)], "sections": [{"key": k, "label": v} for k, v in rt.SECTIONS.items()], "periods": [{"key": k, "label": v} for k, v in rt.PERIODS.items()],
            "channels": mails, "groups": [{"id": g["id"], "name": g["name"]} for g in groups_mod.list_groups(conn)], "max_templates": rt.MAX_TEMPLATES, "max_logo": rt.MAX_LOGO}


@router.post("/report-templates", status_code=201)
def create_template(body: dict[str, Any], conn=Depends(get_conn)) -> dict:
    from datetime import datetime, timezone

    body = {k: v for k, v in body.items() if k != "id"}
    try:
        tpl = rt.upsert(conn, body)
    except rt.TemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    rt.mark_sent(conn, tpl["id"], datetime.now(timezone.utc))        # a new schedule counts from now: the first report comes at the next slot, not at once
    return _present(conn, tpl)


@router.put("/report-templates/{template_id}")
def change_template(template_id: str, body: dict[str, Any], conn=Depends(get_conn)) -> dict:
    from datetime import datetime, timezone

    before = _need(conn, template_id)
    try:
        tpl = rt.upsert(conn, {**body, "id": template_id})
    except rt.TemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if tpl["schedule"] != before["schedule"] or (tpl["enabled"] and not before["enabled"]):
        rt.mark_sent(conn, tpl["id"], datetime.now(timezone.utc))    # changing when it is sent restarts the count: nothing is sent for a slot that has already passed
    return _present(conn, tpl)


@router.delete("/report-templates/{template_id}", status_code=204)
def delete_template(template_id: str, conn=Depends(get_conn)) -> None:
    if not rt.remove(conn, template_id):
        raise HTTPException(status_code=404, detail="no such report")


@router.put("/report-templates/{template_id}/logo")
async def put_logo(template_id: str, request: Request, conn=Depends(get_conn)) -> dict:
    _need(conn, template_id)
    if int(request.headers.get("content-length") or 0) > rt.MAX_LOGO:
        raise HTTPException(status_code=413, detail=f"the picture is larger than {rt.MAX_LOGO // 1000} KB")
    data = await request.body()
    try:
        return rt.set_logo(conn, template_id, data)
    except rt.TemplateError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/report-templates/{template_id}/logo")
def get_logo(template_id: str, conn=Depends(get_conn)) -> Response:
    _need(conn, template_id)
    logo = rt.get_logo(conn, template_id)
    if logo is None:
        raise HTTPException(status_code=404, detail="no logo")
    return Response(content=logo[0], media_type=logo[1], headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.delete("/report-templates/{template_id}/logo", status_code=204)
def delete_logo(template_id: str, conn=Depends(get_conn)) -> None:
    _need(conn, template_id)
    rt.clear_logo(conn, template_id)


@router.get("/report-templates/{template_id}/render")
def render(template_id: str, format: str = Query("pdf", pattern="^(pdf|html)$"), period: str | None = None, month: str | None = Query(None, pattern=r"^\d{4}-\d{2}$"), conn=Depends(get_conn)) -> Response:
    """The report made now: a PDF to download, or the same as a web page to look at (and print)."""
    tpl = _need(conn, template_id)
    if period is not None and period not in rt.PERIODS:
        raise HTTPException(status_code=422, detail="unknown period")
    try:
        doc = reportjobs.make(conn, tpl, period=period, month=month)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if format == "html":
        return Response(content=reportdoc.render_html(doc), media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-store"})
    name = reportjobs.filename(tpl, doc, "pdf")
    return Response(content=reportdoc.render_pdf(doc), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.post("/report-templates/{template_id}/send")
async def send(template_id: str, body: SendBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Make the report now and e-mail it (to its recipients, or to the addresses given here: a test to yourself)."""
    _need(conn, template_id)
    if body.to is not None and not all(rt.EMAIL.match(a.strip()) for a in body.to):
        raise HTTPException(status_code=422, detail="the e-mail addresses are not valid")
    try:
        return await reportjobs.send_now(request.app.state.db_path, template_id, to=[a.strip() for a in body.to] if body.to else None, period=body.period, month=body.month)
    except ch.ChannelError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
