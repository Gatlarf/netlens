import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.db import connect
from app.plugins import index as idx
from app.plugins import autoupdate
from app.plugins import index_install as inst
from app.plugins.categories import listing as category_listing
from app.plugins.registry import InstallError, discover
from app.version import VERSION

router = APIRouter(prefix="/api", tags=["plugins"])


def _getter(request: Request):
    return getattr(request.app.state, "index_getter", idx.http_get)


def _build(request: Request, force: bool = False, offline: bool = False) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        data_dir = request.app.state.settings.data_dir
        index = idx.get_index(conn, force=force, getter=_getter(request), offline=offline)
        installed = inst.installed_map(conn, discover(data_dir), data_dir)
        plugins = idx.view(index["entries"], installed, VERSION)
        auto = autoupdate.enabled_map(conn)
        for p in plugins:
            p["auto_update"] = bool(auto.get(p["id"]))
            p["auto_update_possible"] = bool(p["installed"] and not p["builtin"] and p["installed_source"] in ("index", "rollback"))
        return {
            "index": {k: index[k] for k in ("enabled", "url", "fetched", "stale", "error", "skipped")},
            "plugins": plugins,
            "updates": sum(1 for p in plugins if p["update_available"]),
            "netlens_version": VERSION,
            "levels": {level: idx.level_text(level) for level in idx.LEVELS},
            "categories": category_listing(),
        }
    finally:
        conn.close()


@router.get("/plugin-index")
async def get_plugin_index(request: Request, refresh: bool = False, cache_only: bool = False) -> dict:
    """The index joined with what is installed. Served from a six-hour cache unless `refresh` is set; `cache_only` never uses the network."""
    return await asyncio.to_thread(_build, request, refresh, cache_only)


class IndexSettings(BaseModel):
    enabled: bool = True
    url: str | None = None


@router.get("/plugin-index/settings")
def get_index_settings(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return {**idx.load_settings(conn), "official_url": idx.OFFICIAL_URL}
    finally:
        conn.close()


@router.put("/plugin-index/settings")
def put_index_settings(request: Request, body: IndexSettings) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            return {**idx.save_settings(conn, body.enabled, body.url or idx.OFFICIAL_URL), "official_url": idx.OFFICIAL_URL}
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()


class InstallBody(BaseModel):
    version: str | None = None
    accept_risk: bool = False  # must be true for plugins that have not been reviewed


def _install(request: Request, plugin_id: str, body: InstallBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        index = idx.get_index(conn, getter=_getter(request))
        entry = next((e for e in index["entries"] if e["id"] == plugin_id), None)
        if entry is None:
            raise HTTPException(status_code=404, detail="this plugin is not in the index" + (f" ({index['error']})" if index["error"] else ""))
        release, reason = idx.pick_release(entry, VERSION, body.version)
        if release is None:
            raise HTTPException(status_code=422, detail=f"cannot install: {reason}")
        if release["review"]["level"] == "community" and not body.accept_risk:
            raise HTTPException(status_code=409, detail="this plugin has not been reviewed: it is code that runs inside Netlens. Confirm that you trust its author to install it.")
        try:
            return inst.install_release(conn, request.app.state.settings.data_dir, entry, release, getter=_getter(request), index_url=index["url"])
        except idx.PluginIndexError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        except InstallError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()


@router.post("/plugin-index/{plugin_id}/install")
async def install_plugin(request: Request, plugin_id: str, body: InstallBody) -> dict:
    """Install or update a plugin from the index (checksum verified; a new plugin starts switched off)."""
    return await asyncio.to_thread(_install, request, plugin_id, body)


@router.post("/plugin-index/{plugin_id}/rollback")
def rollback_plugin(request: Request, plugin_id: str) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            result = inst.rollback(conn, request.app.state.settings.data_dir, plugin_id)
            autoupdate.skip_version(conn, plugin_id, result["from"])        # the user went back on purpose: no automatic update to that version again
            return result
        except InstallError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()


class AutoUpdateBody(BaseModel):
    enabled: bool


@router.put("/plugin-index/{plugin_id}/auto-update")
def put_auto_update(request: Request, plugin_id: str, body: AutoUpdateBody) -> dict:
    """Switch automatic updating of one plugin on or off (only plugins installed from the index can be updated automatically)."""
    conn = connect(request.app.state.db_path)
    try:
        data_dir = request.app.state.settings.data_dir
        plugin = discover(data_dir).get(plugin_id)
        if plugin is None or plugin.builtin:
            raise HTTPException(status_code=404, detail="only installed plugins that are not built in can be updated automatically")
        if body.enabled and (inst.provenance(conn, plugin_id) or {}).get("source") not in ("index", "rollback"):
            raise HTTPException(status_code=422, detail="this plugin was uploaded by hand: install it from the Plugin store to let Netlens update it")
        return autoupdate.set_enabled(conn, plugin_id, body.enabled)
    finally:
        conn.close()


@router.get("/plugin-compat")
def plugin_compat(request: Request) -> dict:
    """After a Netlens upgrade: which installed plugins may no longer work, and what fixes it."""
    conn = connect(request.app.state.db_path)
    try:
        return autoupdate.check(conn, request.app.state.settings.data_dir)
    finally:
        conn.close()


@router.post("/plugin-compat/dismiss")
def plugin_compat_dismiss(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        autoupdate.dismiss(conn)
        return {"dismissed": True}
    finally:
        conn.close()
