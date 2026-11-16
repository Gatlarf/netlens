"""Making a report and sending it: now, or when a template's schedule says so."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable

from app import reportdoc, reporttemplates as rt

log = logging.getLogger(__name__)


def filename(tpl: dict, doc: dict, ext: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", tpl["title"].lower()).strip("-")[:40] or "report"
    return f"{slug}-{doc['meta']['start'][:10]}.{ext}"


def make(conn, tpl: dict, now: datetime | None = None, period: str | None = None, month: str | None = None) -> dict:
    """The document of a template, with its logo."""
    return reportdoc.build(conn, tpl, now=now, period=period, month=month, logo=rt.get_logo(conn, tpl["id"]))


def pick_channel(conn, tpl: dict) -> dict:
    """The e-mail channel a template sends through: the one it names, else the first enabled one."""
    from app.notify import channels as ch

    mails = [c for c in ch.load_channels(conn) if c["type"] == "email" and c["enabled"]]
    if tpl.get("channel_id"):
        named = [c for c in mails if c["id"] == tpl["channel_id"]]
        if not named:
            raise ch.ChannelError("the e-mail channel chosen for this report is switched off or gone")
        return named[0]
    if not mails:
        raise ch.ChannelError("no e-mail channel is set up: add one under Settings → Notifications → Alert channels")
    return mails[0]


def deliver(conn, tpl: dict, doc: dict, to: list[str] | None = None, mailer: Callable | None = None) -> dict[str, Any]:
    """Send a made report: the PDF as an attachment (unless the template says otherwise) and a short text. Returns {"sent_to": [...], "file": name}."""
    from app.notify import channels as ch

    channel = pick_channel(conn, tpl)
    recipients = to or tpl["recipients"] or None
    pdf = reportdoc.render_pdf(doc) if tpl["attach_pdf"] else None
    name = filename(tpl, doc, "pdf")
    body = reportdoc.text_summary(doc) + ("" if pdf else "")
    kwargs = {"mailer": mailer} if mailer is not None else {}
    sent = ch.send_report_email(channel, f"{doc['meta']['title']}: {doc['meta']['period']}", body + ("\n\nThe report is attached as a PDF." if pdf else ""),
                                [(name, pdf, "application/pdf")] if pdf else [], to=recipients, **kwargs)
    return {"sent_to": sent, "file": name if pdf else None}


async def send_now(db_path: str, template_id: str, to: list[str] | None = None, period: str | None = None, month: str | None = None, mailer: Callable | None = None) -> dict[str, Any]:
    from app.db import connect
    from app.notify import channels as ch

    def work() -> dict[str, Any]:
        conn = connect(db_path)
        try:
            tpl = rt.get(conn, template_id)
            if tpl is None:
                raise ch.ChannelError("no such report")
            doc = make(conn, tpl, period=period, month=month)
            return deliver(conn, tpl, doc, to=to, mailer=mailer)
        finally:
            conn.close()

    return await asyncio.to_thread(work)


async def send_due(db_path: str, now: datetime | None = None, mailer: Callable | None = None) -> list[dict[str, Any]]:
    """Every template whose time has come is made and sent. A failure is kept on the template (and tried again at the next round, not every minute) and never stops the others."""
    from app.db import connect, set_setting
    from app.notify import channels as ch

    now = now or datetime.now(timezone.utc)

    def due_list() -> list[dict]:
        conn = connect(db_path)
        try:
            return [t for t in rt.load(conn) if rt.due(conn, t, now)]
        finally:
            conn.close()

    results = []
    for tpl in await asyncio.to_thread(due_list):
        outcome: dict[str, Any] = {"template": tpl["id"], "name": tpl["name"]}
        try:
            sent = await send_now(db_path, tpl["id"], mailer=mailer)
            outcome.update(ok=True, **sent)
        except ch.ChannelError as exc:
            outcome.update(ok=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - one broken report must not stop the others
            log.exception("report %s failed", tpl["name"])
            outcome.update(ok=False, error=f"{type(exc).__name__}")

        def finish() -> None:
            conn = connect(db_path)
            try:
                rt.mark_sent(conn, tpl["id"], now)                           # also after a failure: it is tried again at the next slot, not every minute
                set_setting(conn, rt.RESULT_KEY + tpl["id"], json.dumps({"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "ok": outcome["ok"], "error": outcome.get("error"), "to": outcome.get("sent_to")}))
                conn.commit()
                if not outcome["ok"]:
                    from app.db import add_event

                    add_event(conn, "report_failed", f"The report “{tpl['name']}” could not be sent: {outcome.get('error')}", now=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
            finally:
                conn.close()

        await asyncio.to_thread(finish)
        results.append(outcome)
    return results
