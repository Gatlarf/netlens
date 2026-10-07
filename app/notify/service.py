"""Send e-mail notifications for new / offline devices after each scan."""

from __future__ import annotations

import asyncio
import json
import logging

from app.db import connect, set_setting, utcnow
from app.notify.config import is_configured, load_config, save_config
from app.notify.digest import build_message, collect_events, current_max_event_id
from app.notify.mail import MailError, send_mail

log = logging.getLogger(__name__)
STATUS_KEY = "notifications_status"


def record_status(conn, **fields) -> None:
    set_setting(conn, STATUS_KEY, json.dumps({"ts": utcnow(), **fields}))


async def process_notifications(db_path: str, *, sender=send_mail) -> dict:
    """Mail one digest of the events since the last run. Never raises for mail problems."""
    conn = connect(db_path)
    try:
        cfg = load_config(conn)
        if not cfg.enabled or not is_configured(cfg):
            return {"sent": 0, "reason": "disabled"}

        if cfg.last_event_id is None:  # first run: start from now, do not mail history
            cfg.last_event_id = current_max_event_id(conn)
            save_config(conn, cfg)
            return {"sent": 0, "reason": "initialised"}

        events, max_id = collect_events(conn, cfg.last_event_id, cfg)
        if not events:
            if max_id != cfg.last_event_id:
                cfg.last_event_id = max_id
                save_config(conn, cfg)
            return {"sent": 0, "reason": "nothing to report"}

        subject, body = build_message(events)
        try:
            await asyncio.to_thread(sender, cfg, subject, body)
        except MailError as exc:
            log.warning("notification mail failed: %s", exc)
            record_status(conn, ok=False, error=str(exc), pending=len(events))
            return {"sent": 0, "error": str(exc)}  # keep last_event_id: retried after the next scan

        cfg.last_event_id = max_id
        save_config(conn, cfg)
        record_status(conn, ok=True, sent=len(events), subject=subject)
        return {"sent": len(events), "subject": subject}
    finally:
        conn.close()
