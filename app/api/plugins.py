from pathlib import Path

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

import json
import logging
import re

from app.db import connect, get_setting, set_setting, utcnow
from app.plugins import autoupdate
from app.plugins import index_install as inst
from app.plugins import registry
from app.plugins.categories import category_of, listing as category_listing
from app.plugins.index import category_map
from app.plugins.contract import API_VERSION, ContractError, KINDS, clean_config, missing_required
from app.plugins.example import build_example_zip
from app.plugins.registry import InstallError
from app.plugins import runner
from app.plugins.runner import PluginRunError
from app.plugins.service import (
    PluginService,
    clear_plugin_data,
    failure_grace,
    forget_plugin,
    get_state,
    install_state,
    missing_plugins,
    merge_config,
    public_state,
    save_state,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["plugins"])
GUIDE = Path(__file__).resolve().parent.parent / "plugins" / "PLUGINS.md"


def _service(request: Request) -> PluginService:
    return PluginService(
        request.app.state.db_path, request.app.state.settings.data_dir, getattr(request.app.state, "plugin_runner", None)
    )


def _plugin(service: PluginService, plugin_id: str):
    plugin = service.plugins().get(plugin_id)
    if plugin is None:
        raise HTTPException(status_code=404, detail="no such plugin")
    return plugin


def _summary(conn, plugin, categories: dict | None = None, auto: dict | None = None) -> dict:
    full = public_state(conn, plugin)
    manifest = full["manifest"] or {}
    return {
        "id": plugin.id,
        "name": plugin.name,
        "version": manifest.get("version"),
        "kind": manifest.get("kind"),
        "category": category_of(manifest.get("kind"), (categories or {}).get(plugin.id)),
        "description": manifest.get("description", ""),
        "author": manifest.get("author", ""),
        "builtin": plugin.builtin,
        "problem": plugin.problem,
        "enabled": full["enabled"],
        "configured": full["configured"],
        "status": full["status"],
        "auto_update": bool(auto.get(plugin.id)) if auto is not None else False,
        "auto_update_possible": (not plugin.builtin) and ((inst.provenance(conn, plugin.id) or {}).get("source") in ("index", "rollback")),
    }


class PluginSettings(BaseModel):
    failure_grace: int | None = Field(default=None, ge=1, le=48)
    ca_certs: str | None = Field(default=None, max_length=65536)


CA_KEY = "plugins.ca_certs"
PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def load_extra_ca(conn) -> str:
    """Hand the saved CA certificates to the plugin runner (at start and after a change)."""
    from app.plugins import runner

    pem = get_setting(conn, CA_KEY) or ""
    runner.set_extra_ca(pem)
    return pem


def clean_ca(text: str) -> str:
    """The certificates of a PEM text, one after the other, or HTTPException 422 when something in it is not a certificate."""
    import ssl

    blocks = PEM_BLOCK.findall(text or "")
    if (text or "").strip() and not blocks:
        raise HTTPException(status_code=422, detail="that is not a PEM certificate (it starts with -----BEGIN CERTIFICATE-----)")
    if len(blocks) > 50:
        raise HTTPException(status_code=422, detail="at most 50 certificates")
    leftover = PEM_BLOCK.sub("", text or "").strip()
    if leftover:
        raise HTTPException(status_code=422, detail="the text holds more than certificates: paste only the -----BEGIN CERTIFICATE----- blocks (never a private key)")
    pem = "\n".join(" ".join(b.split()).replace("-----BEGIN CERTIFICATE----- ", "-----BEGIN CERTIFICATE-----\n").replace(" -----END CERTIFICATE-----", "\n-----END CERTIFICATE-----") for b in blocks)
    if pem:
        try:
            ssl.create_default_context().load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError):
            raise HTTPException(status_code=422, detail="one of the certificates is not valid") from None
    return pem


def _settings_answer(conn) -> dict:
    pem = get_setting(conn, CA_KEY) or ""
    return {"failure_grace": failure_grace(conn), "ca_certs": pem, "ca_count": len(PEM_BLOCK.findall(pem))}


@router.get("/plugin-settings")
def get_plugin_settings(request: Request) -> dict:
    """How many failed syncs in a row make a plugin a problem (dashboard, problem count), and the extra certificate authorities plugins trust."""
    conn = connect(request.app.state.db_path)
    try:
        return _settings_answer(conn)
    finally:
        conn.close()


@router.put("/plugin-settings")
def put_plugin_settings(request: Request, body: PluginSettings) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        if body.failure_grace is None and body.ca_certs is None:
            raise HTTPException(status_code=422, detail="nothing to change")
        pem = clean_ca(body.ca_certs) if body.ca_certs is not None else None
        if body.failure_grace is not None:
            set_setting(conn, "plugins.failure_grace", str(body.failure_grace))
        if pem is not None:
            set_setting(conn, CA_KEY, pem)
            audit_note = "removed" if not pem else f"set ({len(PEM_BLOCK.findall(pem))})"
            log.info("plugin CA certificates %s", audit_note)
        conn.commit()
        load_extra_ca(conn)
        return _settings_answer(conn)
    finally:
        conn.close()


@router.get("/plugin-runs")
def plugin_runs(request: Request, limit: int = 60) -> list[dict]:
    """The enabled plugins as monitored things, like the service checks: the outcome of the recent syncs, the share of good ones in 24 hours and how long a sync takes."""
    from app.plugins import runs

    conn = connect(request.app.state.db_path)
    try:
        out = []
        for p in _service(request).plugins().values():
            if p.manifest is None:
                continue
            state = public_state(conn, p)
            if not state["enabled"]:
                continue
            beats = runs.history(conn, p.id, max(1, min(limit, 200)))
            last = beats[-1] if beats else None
            ok_ms = [b["ms"] for b in beats if b["ms"] is not None]
            out.append({"id": p.id, "name": p.name, "kind": p.manifest.get("kind"), "series_id": runs.series_id(p.id), "builtin": p.builtin,
                        "state": None if last is None else ("up" if last["up"] else "down"), "last_ts": last["ts"] if last else None, "last_ms": ok_ms[-1] if ok_ms else None,
                        "last_detail": (last["detail"] if last and not last["up"] else ""), "uptime_24h": runs.uptime_24h(conn, p.id), "beats": beats})
        out.sort(key=lambda r: r["name"].lower())
        return out
    finally:
        conn.close()


@router.get("/plugins")
def list_plugins(request: Request) -> dict:
    service = _service(request)
    conn = connect(request.app.state.db_path)
    try:
        plugins = service.plugins()
        categories = category_map(conn)
        auto = autoupdate.enabled_map(conn)
        items = [_summary(conn, p, categories, auto) for p in plugins.values()]
        missing = missing_plugins(conn, plugins)
    finally:
        conn.close()
    return {"plugins": items, "missing": missing, "api_version": API_VERSION, "kinds": list(KINDS), "categories": category_listing(), "isolation": runner.isolation()}


@router.get("/plugins/guide")
def plugin_guide() -> Response:
    try:
        text = GUIDE.read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(status_code=404, detail="the plugin guide is not installed")
    return Response(text, media_type="text/markdown; charset=utf-8")


@router.get("/plugins/example.zip")
def plugin_example() -> Response:
    return Response(
        build_example_zip(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="netlens-example-plugin.zip"'},
    )


@router.get("/plugins/{plugin_id}")
def get_plugin(request: Request, plugin_id: str) -> dict:
    service = _service(request)
    plugin = _plugin(service, plugin_id)
    conn = connect(request.app.state.db_path)
    try:
        return public_state(conn, plugin)
    finally:
        conn.close()


class PluginBody(BaseModel):
    """Only what is sent changes. Secret fields left empty keep their saved value."""

    enabled: bool | None = None
    config: dict[str, Any] | None = Field(default=None)


def _merged(plugin, conn, body: PluginBody) -> dict:
    if plugin.manifest is None:
        raise HTTPException(status_code=422, detail=plugin.problem or "the plugin is broken")
    current = get_state(conn, plugin)["config"]
    try:
        return merge_config(plugin, current, body.config or {})
    except ContractError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/plugins/{plugin_id}")
async def put_plugin(request: Request, plugin_id: str, body: PluginBody) -> dict:
    service = _service(request)
    plugin = _plugin(service, plugin_id)
    conn = connect(request.app.state.db_path)
    try:
        config = _merged(plugin, conn, body)
        enabled = get_state(conn, plugin)["enabled"] if body.enabled is None else body.enabled
        if enabled:
            missing = missing_required(plugin.manifest, config)
            if missing:
                raise HTTPException(status_code=422, detail="to turn the plugin on, fill in: " + ", ".join(missing))
        was_enabled = get_state(conn, plugin)["enabled"]
        save_state(conn, plugin.id, enabled, config)
        if was_enabled and not enabled:
            clear_plugin_data(conn, plugin.id)  # its links and guests leave the map; the settings stay
    finally:
        conn.close()
    if enabled:
        await service.sync(plugin.id)  # saving is the user's "try again" after a refused login
    conn = connect(request.app.state.db_path)
    try:
        return public_state(conn, plugin)
    finally:
        conn.close()


@router.post("/plugins/{plugin_id}/test")
async def test_plugin(request: Request, plugin_id: str, body: PluginBody) -> dict:
    """Try the values in the form (saved secrets are used when none is typed). Saves nothing."""
    service = _service(request)
    plugin = _plugin(service, plugin_id)
    conn = connect(request.app.state.db_path)
    try:
        config = _merged(plugin, conn, body)
    finally:
        conn.close()
    missing = missing_required(plugin.manifest, config)
    if missing:
        raise HTTPException(status_code=422, detail="fill in: " + ", ".join(missing))
    try:
        return await service.test(plugin, config)
    except PluginRunError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/plugins/{plugin_id}/diagnose")
async def diagnose_plugin(request: Request, plugin_id: str, body: PluginBody) -> dict:
    """Run the plugin's diagnostic with the values in the form (saved secrets are used when none is typed). Saves nothing."""
    from app.plugins.diagnose import DiagnoseError

    service = _service(request)
    plugin = _plugin(service, plugin_id)
    if not plugin.manifest.get("diagnose"):
        raise HTTPException(status_code=404, detail="this plugin has no diagnostic")
    conn = connect(request.app.state.db_path)
    try:
        config = _merged(plugin, conn, body)
    finally:
        conn.close()
    missing = missing_required(plugin.manifest, config)
    if missing:
        raise HTTPException(status_code=422, detail="fill in: " + ", ".join(missing))
    try:
        report = await service.diagnose(plugin, config)
    except (PluginRunError, DiagnoseError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"report": report, "plugin": plugin.id, "version": plugin.manifest["version"]}


@router.post("/plugins/{plugin_id}/sync")
async def sync_plugin(request: Request, plugin_id: str) -> dict:
    service = _service(request)
    _plugin(service, plugin_id)
    result = await service.sync(plugin_id)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@router.post("/plugins")
async def upload_plugin(request: Request, replace: bool = False) -> dict:
    """Install a plugin from a zip file sent as the request body (Content-Type: application/zip)."""
    limit = registry.MAX_ZIP_BYTES
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="the file is too large")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > limit:
            raise HTTPException(status_code=413, detail="the file is too large")
    try:
        result = registry.install(request.app.state.settings.data_dir, bytes(data), replace=replace)
    except InstallError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"could not store the plugin: {exc}")
    manifest = result["manifest"]
    # a freshly uploaded plugin is always off until the user turns it on
    conn = connect(request.app.state.db_path)
    try:
        if not result["replaced"]:
            install_state(conn, manifest, result["sha256"])
        inst.remember_zip(request.app.state.settings.data_dir, manifest["id"], manifest["version"], bytes(data))
        set_setting(conn, f"plugin.{manifest['id']}.install", json.dumps({"source": "upload", "version": manifest["version"], "sha256": result["sha256"], "level": None, "installed": utcnow()}))
    finally:
        conn.close()
    return {"id": manifest["id"], "name": manifest["name"], "version": manifest["version"], "kind": manifest["kind"],
            "sha256": result["sha256"], "replaced": result["replaced"]}


@router.delete("/plugins/{plugin_id}")
def delete_plugin(request: Request, plugin_id: str) -> dict:
    service = _service(request)
    plugin = _plugin(service, plugin_id)
    if plugin.builtin:
        raise HTTPException(status_code=400, detail="built-in plugins cannot be removed; turn them off instead")
    conn = connect(request.app.state.db_path)
    try:
        forget_plugin(conn, plugin_id)
    finally:
        conn.close()
    try:
        registry.uninstall(request.app.state.settings.data_dir, plugin_id)
    except InstallError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"removed": plugin_id}
