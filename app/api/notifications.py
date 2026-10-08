import asyncio
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.db import connect, get_setting
from app.notify.config import (
    NotifyConfig,
    is_configured,
    load_config,
    parse_addresses,
    public_dict,
    save_config,
)
from app.notify.digest import current_max_event_id
from app.notify.mail import MailError, send_mail
from app.notify.service import STATUS_KEY, record_status

router = APIRouter(prefix="/api", tags=["notifications"])


def _payload(conn) -> dict:
    cfg = load_config(conn)
    status = None
    raw = get_setting(conn, STATUS_KEY)
    if raw:
        try:
            status = json.loads(raw)
        except ValueError:
            status = None
    return {**public_dict(cfg), "status": status}


@router.get("/notifications")
def get_notifications(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _payload(conn)
    finally:
        conn.close()


class NotificationsBody(BaseModel):
    """Every field is optional; only the fields sent are changed. A missing/null password keeps the old one."""

    enabled: bool | None = None
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    security: str | None = None
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, max_length=500)
    from_addr: str | None = None
    to_addrs: list[str] | str | None = None
    notify_new: bool | None = None
    notify_offline: bool | None = None
    notify_services: bool | None = None


@router.put("/notifications")
def put_notifications(request: Request, body: NotificationsBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        cfg = load_config(conn)
        was_enabled = cfg.enabled
        fields = body.model_fields_set

        if "security" in fields and body.security not in ("none", "starttls", "ssl"):
            raise HTTPException(status_code=422, detail="security must be none, starttls or ssl")
        try:
            if "to_addrs" in fields:
                cfg.to_addrs = parse_addresses(body.to_addrs)
            if "from_addr" in fields:
                addrs = parse_addresses(body.from_addr)
                if len(addrs) > 1:
                    raise ValueError("from address must be a single address")
                cfg.from_addr = addrs[0] if addrs else ""
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        for name in ("enabled", "smtp_port", "security", "notify_new", "notify_offline", "notify_services"):
            if name in fields and getattr(body, name) is not None:
                setattr(cfg, name, getattr(body, name))
        for name in ("smtp_host", "username"):
            if name in fields and getattr(body, name) is not None:
                setattr(cfg, name, getattr(body, name).strip())
        if body.password is not None:
            cfg.password = body.password

        if cfg.enabled and not is_configured(cfg):
            raise HTTPException(
                status_code=422,
                detail="to enable notifications set the SMTP host, a sender address and at least one recipient",
            )
        if cfg.enabled and not was_enabled:
            # Only report events from now on, never the backlog from before it was switched on.
            cfg.last_event_id = current_max_event_id(conn)

        save_config(conn, cfg)
        return _payload(conn)
    finally:
        conn.close()


@router.post("/notifications/test")
async def send_test(request: Request) -> dict:
    """Send a test mail with the saved settings (works even while notifications are disabled)."""
    conn = connect(request.app.state.db_path)
    try:
        cfg: NotifyConfig = load_config(conn)
    finally:
        conn.close()
    if not is_configured(cfg):
        raise HTTPException(status_code=422, detail="set the SMTP host, a sender address and a recipient first")

    sender = getattr(request.app.state, "mail_sender", send_mail)
    try:
        await asyncio.to_thread(sender, cfg, "[Netlens] Test email", "This is a test message from Netlens.\n\nIf you can read this, e-mail notifications work.\n")
    except MailError as exc:
        conn = connect(request.app.state.db_path)
        try:
            record_status(conn, ok=False, error=f"test mail failed: {exc}")
        finally:
            conn.close()
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True, "to": cfg.to_addrs}
