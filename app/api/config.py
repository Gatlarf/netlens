import asyncio
import dataclasses
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import normalize_ranges
from app.db import connect, delete_setting, get_setting, set_setting

VERSION = "0.1.0"
RANGES_KEY = "ranges"
MAX_RANGES = 16

router = APIRouter(prefix="/api", tags=["config"])


def apply_ranges(app, ranges: list[str]) -> None:
    """Make `ranges` the effective scan ranges (empty = env value / auto-detect)."""
    effective = tuple(ranges) if ranges else app.state.env_ranges
    new_settings = dataclasses.replace(app.state.settings, ranges=effective)
    app.state.settings = new_settings
    app.state.scan_manager.settings = new_settings
    app.state.ranges_override = bool(ranges)


def load_saved_ranges(app) -> None:
    """Apply a range override saved through the web UI, if any (called at startup)."""
    conn = connect(app.state.db_path)
    try:
        raw = get_setting(conn, RANGES_KEY)
    finally:
        conn.close()
    if not raw:
        return
    try:
        saved = normalize_ranges(json.loads(raw))
    except (ValueError, TypeError):
        return
    if saved:
        apply_ranges(app, saved)


async def _detected_ranges(request: Request) -> list[str]:
    try:
        provider = request.app.state.scan_manager.ranges_provider
        return list(await asyncio.wait_for(provider(), timeout=3))
    except Exception:
        return []


async def _config_payload(request: Request) -> dict:
    settings = request.app.state.settings
    override = getattr(request.app.state, "ranges_override", False)
    if override:
        source = "ui"
    elif getattr(request.app.state, "env_ranges", settings.ranges):
        source = "env"
    else:
        source = "auto"

    return {
        "version": VERSION,
        "ranges": list(settings.ranges),
        "ranges_source": source,
        "detected_ranges": await _detected_ranges(request),
        "quick_interval": settings.quick_interval,
        "deep_interval": settings.deep_interval,
        "terminal_enabled": settings.terminal_enabled,
        "snmp_enabled": settings.snmp_community is not None,
        "bind": f"{settings.bind_host}:{settings.bind_port}",
    }


@router.get("/config")
async def get_config(request: Request) -> dict:
    return await _config_payload(request)


class RangesBody(BaseModel):
    ranges: list[str] = Field(default_factory=list, max_length=MAX_RANGES)


@router.put("/config/ranges")
async def put_ranges(request: Request, body: RangesBody) -> dict:
    """Set the scan ranges. An empty list removes the override (env value or auto-detect)."""
    try:
        ranges = normalize_ranges(body.ranges)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    conn = connect(request.app.state.db_path)
    try:
        if ranges:
            set_setting(conn, RANGES_KEY, json.dumps(ranges))
        else:
            delete_setting(conn, RANGES_KEY)
    finally:
        conn.close()

    apply_ranges(request.app, ranges)
    return await _config_payload(request)
