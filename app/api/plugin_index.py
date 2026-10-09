import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.db import connect
from app.plugins import index as idx
from app.plugins import index_install as inst
from app.plugins.registry import InstallError, discover
from app.version import VERSION

router = APIRouter(prefix="/api", tags=["plugins"])


def _getter(request: Request):
    return getattr(request.app.state, "index_getter", idx.http_get)


def _build(request: Request, force: bool = False) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        data_dir = request.app.state.settings.data_dir
        index = idx.get_index(conn, force=force, getter=_getter(request))
        installed = inst.installed_map(conn, discover(data_dir), data_dir)
        plugins = idx.view(index["entries"], installed, VERSION)
        return {
            "index": {k: index[k] for k in ("enabled", "url", "fetched", "stale", "error", "skipped")},
            "plugins": plugins,
            "updates": sum(1 for p in plugins if p["update_available"]),
            "netlens_version": VERSION,
            "levels": {level: idx.level_text(level) for level in idx.LEVELS},
        }
    finally:
        conn.close()


@router.get("/plugin-index")
async def get_plugin_index(request: Request, refresh: bool = False) -> dict:
    """The index joined with what is installed. Served from a six-hour cache unless `refresh` is set."""
    return await asyncio.to_thread(_build, request, refresh)


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
            return inst.rollback(conn, request.app.state.settings.data_dir, plugin_id)
        except InstallError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()
