import asyncio
import dataclasses
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from typing import Any

from app.config import normalize_ranges
from app.db import connect, delete_setting, get_setting, set_setting
from app.scanner.options import (
    PRESETS,
    ScanOptions,
    command_preview,
    options_from_dict,
    options_from_json,
    options_to_dict,
    preset_dict,
)
from app.version import VERSION

RANGES_KEY = "ranges"
INTERVAL_KEYS = ("quick_interval", "deep_interval")
TERMINAL_KEY = "terminal_enabled"
SCAN_OPTIONS_KEY = "scan_options"
MAX_RANGES = 16
MIN_INTERVAL = 60
MAX_INTERVAL = 30 * 86400

router = APIRouter(prefix="/api", tags=["config"])


def _read_overrides(db_path: str) -> dict:
    """Overrides saved through the web UI: {ranges, quick_interval, deep_interval, terminal_enabled}."""
    conn = connect(db_path)
    try:
        out: dict = {}
        raw = get_setting(conn, RANGES_KEY)
        if raw:
            try:
                ranges = normalize_ranges(json.loads(raw))
                if ranges:
                    out["ranges"] = tuple(ranges)
            except (ValueError, TypeError):
                pass
        for key in INTERVAL_KEYS:
            raw = get_setting(conn, key)
            if raw and raw.isdigit() and MIN_INTERVAL <= int(raw) <= MAX_INTERVAL:
                out[key] = int(raw)
        raw = get_setting(conn, TERMINAL_KEY)
        if raw in ("on", "off"):
            out[TERMINAL_KEY] = raw == "on"
        return out
    finally:
        conn.close()


def apply_overrides(app) -> None:
    """Make UI overrides on top of the environment settings the effective settings."""
    overrides = _read_overrides(app.state.db_path)
    new_settings = dataclasses.replace(app.state.env_settings, **overrides)
    app.state.settings = new_settings
    app.state.scan_manager.settings = new_settings
    app.state.overrides = set(overrides)

    conn = connect(app.state.db_path)
    try:
        saved = get_setting(conn, SCAN_OPTIONS_KEY)
    finally:
        conn.close()
    app.state.scan_manager.options = options_from_json(saved)


# kept for callers/tests that used the earlier names
def load_saved_ranges(app) -> None:
    apply_overrides(app)


async def _detected_ranges(request: Request) -> list[str]:
    try:
        provider = request.app.state.scan_manager.ranges_provider
        return list(await asyncio.wait_for(provider(), timeout=3))
    except Exception:
        return []


def _source(request: Request, key: str, env_value) -> str:
    if key in getattr(request.app.state, "overrides", set()):
        return "ui"
    if key == "ranges":
        return "env" if env_value else "auto"
    return "env"


async def _config_payload(request: Request) -> dict:
    from app.terminal.access import classify

    settings = request.app.state.settings
    allowed_here, why_here = classify(request, settings.terminal_remote)
    env = request.app.state.env_settings
    return {
        "version": VERSION,
        "ranges": list(settings.ranges),
        "ranges_source": _source(request, "ranges", env.ranges),
        "detected_ranges": await _detected_ranges(request),
        "quick_interval": settings.quick_interval,
        "deep_interval": settings.deep_interval,
        "quick_interval_source": _source(request, "quick_interval", env.quick_interval),
        "deep_interval_source": _source(request, "deep_interval", env.deep_interval),
        "env_quick_interval": env.quick_interval,
        "env_deep_interval": env.deep_interval,
        "terminal_enabled": settings.terminal_enabled,
        "terminal_source": _source(request, "terminal_enabled", env.terminal_enabled),
        "env_terminal_enabled": env.terminal_enabled,
        "terminal_remote": settings.terminal_remote,
        "terminal_allowed_here": allowed_here,
        "terminal_available": settings.terminal_enabled and allowed_here,   # for THIS request
        "terminal_here": why_here,
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

    apply_overrides(request.app)
    return await _config_payload(request)


class GeneralBody(BaseModel):
    """Each field present in the request is applied; null resets it to the environment value."""

    quick_interval: int | None = None
    deep_interval: int | None = None
    terminal_enabled: bool | None = None


@router.put("/config/general")
async def put_general(request: Request, body: GeneralBody) -> dict:
    fields = body.model_fields_set
    conn = connect(request.app.state.db_path)
    try:
        for key in INTERVAL_KEYS:
            if key not in fields:
                continue
            value = getattr(body, key)
            if value is None:
                delete_setting(conn, key)
            elif not MIN_INTERVAL <= value <= MAX_INTERVAL:
                raise HTTPException(
                    status_code=422,
                    detail=f"{key} must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds",
                )
            else:
                set_setting(conn, key, str(value))
        if "terminal_enabled" in fields:
            from app.terminal.access import classify

            settings = request.app.state.settings
            allowed_here, why_here = classify(request, settings.terminal_remote)
            wanted = request.app.state.env_settings.terminal_enabled if body.terminal_enabled is None else body.terminal_enabled
            if wanted != settings.terminal_enabled and not allowed_here:  # whoever can reach Netlens from outside must not be able to switch a shell on
                raise HTTPException(status_code=403, detail=f"the terminal setting can only be changed from the local network: {why_here}")
            if body.terminal_enabled is None:
                delete_setting(conn, TERMINAL_KEY)
            else:
                set_setting(conn, TERMINAL_KEY, "on" if body.terminal_enabled else "off")
    finally:
        conn.close()

    apply_overrides(request.app)
    return await _config_payload(request)


def _scan_options_payload(request: Request) -> dict:
    opts: ScanOptions = request.app.state.scan_manager.options
    defaults = ScanOptions()
    return {
        "options": options_to_dict(opts),
        "defaults": options_to_dict(defaults),
        "is_default": opts == defaults,
        "presets": {name: preset_dict(name) for name in PRESETS},
        "preview": {kind: command_preview(kind, opts) for kind in ("quick", "deep", "full")},
    }


@router.get("/scan-options")
def get_scan_options(request: Request) -> dict:
    """nmap options (ports, timing, detection) used by scans, plus presets and the resulting command lines."""
    return _scan_options_payload(request)


@router.put("/scan-options")
def put_scan_options(request: Request, body: dict[str, Any]) -> dict:
    """Change the nmap options; only the keys sent are changed. Applies from the next scan."""
    try:
        opts = options_from_dict(body, base=request.app.state.scan_manager.options)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    conn = connect(request.app.state.db_path)
    try:
        set_setting(conn, SCAN_OPTIONS_KEY, json.dumps(options_to_dict(opts)))
    finally:
        conn.close()
    request.app.state.scan_manager.options = opts
    return _scan_options_payload(request)


@router.delete("/scan-options")
def reset_scan_options(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        delete_setting(conn, SCAN_OPTIONS_KEY)
    finally:
        conn.close()
    request.app.state.scan_manager.options = ScanOptions()
    return _scan_options_payload(request)
