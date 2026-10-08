import asyncio
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.db import connect
from app.notify import channels as ch

router = APIRouter(prefix="/api", tags=["notifications"])
MAX_NAME = 60


def _overview(conn) -> dict:
    return {
        "channels": [ch.public_channel(c) for c in ch.load_channels(conn)],
        "types": {k: {"label": v["label"], "fields": v["fields"]} for k, v in ch.TYPES.items()},
        "events": [{"key": k, "label": v} for k, v in ch.EVENT_LABELS.items()],
        "default_events": ch.DEFAULT_EVENTS,
        "quiet": ch.load_quiet(conn),
    }


class ChannelBody(BaseModel):
    type: str | None = None
    name: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None
    settings: dict[str, str | int | float | bool | None] | None = None


@router.get("/notify-channels")
def get_channels(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _overview(conn)
    finally:
        conn.close()


def _find(channels: list[dict], channel_id: str) -> dict:
    found = next((c for c in channels if c["id"] == channel_id), None)
    if found is None:
        raise HTTPException(status_code=404, detail="no such channel")
    return found


@router.post("/notify-channels", status_code=201)
def create_channel(request: Request, body: ChannelBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        channels = ch.load_channels(conn)
        if len(channels) >= ch.MAX_CHANNELS:
            raise HTTPException(status_code=422, detail=f"at most {ch.MAX_CHANNELS} channels")
        if body.type not in ch.TYPES:
            raise HTTPException(status_code=422, detail=f"type must be one of {', '.join(ch.TYPES)}")
        name = (body.name or ch.TYPES[body.type]["label"]).strip()[:MAX_NAME]
        try:
            settings = ch.clean_settings(body.type, body.settings or {})
            events = ch.clean_events(body.events if body.events is not None else ch.DEFAULT_EVENTS)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        channel = {"id": ch.new_channel_id(), "type": body.type, "name": name, "enabled": body.enabled is not False, "events": events,
                   "settings": settings, "last_event_id": ch.current_max_event_id(conn)}  # only report what happens from now on
        channels.append(channel)
        ch.save_channels(conn, channels)
        return ch.public_channel(channel)
    finally:
        conn.close()


@router.put("/notify-channels/{channel_id}")
def update_channel(request: Request, channel_id: str, body: ChannelBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        channels = ch.load_channels(conn)
        channel = _find(channels, channel_id)
        try:
            if body.settings is not None:
                channel["settings"] = ch.clean_settings(channel["type"], body.settings, channel["settings"])
            if body.events is not None:
                channel["events"] = ch.clean_events(body.events)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if body.name is not None and body.name.strip():
            channel["name"] = body.name.strip()[:MAX_NAME]
        if body.enabled is not None:
            if body.enabled and not channel["enabled"]:
                channel["last_event_id"] = ch.current_max_event_id(conn)  # not the backlog from while it was off
            channel["enabled"] = body.enabled
        ch.save_channels(conn, channels)
        return ch.public_channel(channel)
    finally:
        conn.close()


@router.delete("/notify-channels/{channel_id}")
def delete_channel(request: Request, channel_id: str) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        channels = ch.load_channels(conn)
        _find(channels, channel_id)
        ch.save_channels(conn, [c for c in channels if c["id"] != channel_id])
        return {"removed": channel_id}
    finally:
        conn.close()


@router.post("/notify-channels/{channel_id}/test")
async def test_channel(request: Request, channel_id: str) -> dict:
    """Send a test message through the saved channel settings (works while the channel is switched off)."""
    conn = connect(request.app.state.db_path)
    try:
        channel = _find(ch.load_channels(conn), channel_id)
    finally:
        conn.close()
    poster = getattr(request.app.state, "channel_poster", ch.http_post)
    sample = [{"id": 0, "ts": "", "kind": "device_new", "name": "Test device", "ip": "192.168.0.99", "mac": None, "vendor": "Netlens", "trusted": 0, "detail": "", "device_id": None}]
    try:
        await asyncio.to_thread(ch.send_channel, channel, "[Netlens] Test message", "This is a test from Netlens. If you can read this, the channel works.", sample, poster=poster)
    except ch.ChannelError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True}


class QuietBody(BaseModel):
    enabled: bool = False
    start: str = "23:00"
    end: str = "07:00"
    tz: str = "UTC"
    offset_min: int = 0
    bypass_critical: bool = True


@router.put("/notify-quiet")
def put_quiet(request: Request, body: QuietBody) -> dict:
    try:
        quiet = ch.clean_quiet(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    conn = connect(request.app.state.db_path)
    try:
        ch.set_setting(conn, ch.QUIET_KEY, json.dumps(quiet))
        return quiet
    finally:
        conn.close()
