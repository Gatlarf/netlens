from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

import json

from app.db import connect, set_setting, utcnow
from app.plugins import index_install as inst
from app.plugins import registry
from app.plugins.contract import API_VERSION, ContractError, KINDS, clean_config, missing_required
from app.plugins.example import build_example_zip
from app.plugins.registry import InstallError
from app.plugins.runner import PluginRunError
from app.plugins.service import (
    PluginService,
    clear_plugin_data,
    forget_plugin,
    get_state,
    merge_config,
    public_state,
    save_state,
)

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


def _summary(conn, plugin) -> dict:
    full = public_state(conn, plugin)
    manifest = full["manifest"] or {}
    return {
        "id": plugin.id,
        "name": plugin.name,
        "version": manifest.get("version"),
        "kind": manifest.get("kind"),
        "description": manifest.get("description", ""),
        "author": manifest.get("author", ""),
        "builtin": plugin.builtin,
        "problem": plugin.problem,
        "enabled": full["enabled"],
        "configured": full["configured"],
        "status": full["status"],
    }


@router.get("/plugins")
def list_plugins(request: Request) -> dict:
    service = _service(request)
    conn = connect(request.app.state.db_path)
    try:
        items = [_summary(conn, p) for p in service.plugins().values()]
    finally:
        conn.close()
    return {"plugins": items, "api_version": API_VERSION, "kinds": list(KINDS)}


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
    config: dict[str, str | int | float | bool | None] | None = Field(default=None)


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
            save_state(conn, manifest["id"], False, clean_config(manifest, {}))
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
