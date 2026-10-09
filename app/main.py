"""Netlens application entry point."""

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from starlette.requests import HTTPConnection
from fastapi.staticfiles import StaticFiles

from app.api import passive as passive_api, backup as backup_api, backups as backups_api, channels as channels_api, config, devices, events, export, groups as groups_api, hierarchy as hierarchy_api, ignored, mapsettings, metrics as metrics_api, notifications, plugin_index, plugins, relations, scans, services as services_api, stats as stats_api, netchecks as netchecks_api, public_share, setup as setup_api, vendor_db as vendor_db_api, shares as shares_api, update as update_api, users as users_api, uptime, wifi
from app.api.auth import router as auth_router
from app.api.terminal import router as terminal_router
from app.auth import LoginLimiter, require_auth
from app.config import load_settings
from app.db import connect, init_db
from app.scanner.orchestrator import ScanManager
from app.scanner.scheduler import scheduler_loop
from app.security import SecurityHeadersMiddleware
from app.terminal.ssh import SSHBackend
from app.terminal.telnet import TelnetBackend
from app.services import service_loop
from app.version import VERSION



async def require_terminal_enabled(conn: HTTPConnection) -> None:
    from app.terminal.access import classify

    if not conn.app.state.settings.terminal_enabled:
        raise HTTPException(status_code=404, detail="web terminal is disabled")
    allowed, why = classify(conn, conn.app.state.settings.terminal_remote)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"the web terminal is not available here: {why}")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    conn = connect(app.state.db_path)
    init_db(conn)
    config.apply_overrides(app)
    app.state.scan_manager.recover()
    # identification: use the vendor registry copy in the data directory, and apply the current rules to what is already known
    # (new vendor table, new device types), so an update shows its effect without waiting for the next scan
    from app.scanner import vendor as vendor_db
    from app.scanner.store import refresh_identification

    vendor_db.configure(app.state.settings.data_dir)
    try:
        refresh_identification(conn)
    except Exception:  # noqa: BLE001 - never block the start
        import logging

        logging.getLogger(__name__).exception("could not refresh the device identification")

    tasks = []
    if getattr(app.state, "scheduler", False):
        tasks.append(asyncio.create_task(
            scheduler_loop(
                app.state.scan_manager,
                lambda: app.state.settings.quick_interval,
                lambda: app.state.settings.deep_interval,
            )
        ))
        tasks.append(asyncio.create_task(service_loop(app.state.db_path)))
        from app.scanner.passive import Control

        app.state.passive = Control(app.state.db_path)
        if app.state.passive.enabled():
            app.state.passive.start()

    try:
        yield
    finally:
        if getattr(app.state, "passive", None) is not None:
            app.state.passive.stop()
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        conn.close()


def create_app(
    settings: Any,
    db_path: str | os.PathLike | None = None,
    *,
    scheduler: bool = False,
    scan_manager: ScanManager | None = None,
) -> FastAPI:
    app = FastAPI(title="Netlens", lifespan=lifespan)

    app.add_middleware(SecurityHeadersMiddleware)

    app.state.settings = settings
    app.state.env_settings = settings
    app.state.overrides = set()
    app.state.db_path = str(db_path) if db_path is not None else str(settings.data_dir / "netlens.db")
    app.state.scheduler = scheduler
    app.state.scan_manager = scan_manager or ScanManager(app.state.db_path, settings)
    app.state.login_limiter = LoginLimiter()
    app.state.share_limiter = LoginLimiter(max_failures=30, window=60.0)
    app.state.terminal_backends = {"ssh": SSHBackend, "telnet": TelnetBackend}
    app.state.terminal_sessions = 0

    app.include_router(auth_router)
    app.include_router(setup_api.router)  # public only while no user exists (it checks that itself)
    app.include_router(public_share.router)  # the only routes that need no login: they check the link token themselves

    auth_deps = [Depends(require_auth)]
    app.include_router(devices.router, dependencies=auth_deps)
    app.include_router(scans.router, dependencies=auth_deps)
    app.include_router(events.router, dependencies=auth_deps)
    app.include_router(config.router, dependencies=auth_deps)
    app.include_router(relations.router, dependencies=auth_deps)
    app.include_router(export.router, dependencies=auth_deps)
    app.include_router(uptime.router, dependencies=auth_deps)
    app.include_router(notifications.router, dependencies=auth_deps)
    app.include_router(backup_api.router, dependencies=auth_deps)
    app.include_router(backups_api.router, dependencies=auth_deps)
    app.include_router(users_api.router, dependencies=auth_deps)
    app.include_router(netchecks_api.router, dependencies=auth_deps)
    app.include_router(groups_api.router, dependencies=auth_deps)
    app.include_router(vendor_db_api.router, dependencies=auth_deps)
    app.include_router(passive_api.router, dependencies=auth_deps)
    app.include_router(shares_api.router, dependencies=auth_deps)
    app.include_router(plugin_index.router, dependencies=auth_deps)
    app.include_router(update_api.router, dependencies=auth_deps)
    app.include_router(plugins.router, dependencies=auth_deps)
    app.include_router(stats_api.router, dependencies=auth_deps)
    app.include_router(wifi.router, dependencies=auth_deps)
    app.include_router(services_api.router, dependencies=auth_deps)
    app.include_router(channels_api.router, dependencies=auth_deps)
    app.include_router(metrics_api.router, dependencies=auth_deps)
    app.include_router(mapsettings.router, dependencies=auth_deps)
    app.include_router(hierarchy_api.router, dependencies=auth_deps)
    app.include_router(ignored.router, dependencies=auth_deps)

    # Always mounted; each request is refused (404) while the terminal is switched off,
    # so it can be toggled at runtime from the Settings page.
    app.include_router(terminal_router, dependencies=[Depends(require_terminal_enabled)])

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": VERSION}

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


def main() -> None:
    settings = load_settings()
    app = create_app(settings, scheduler=True)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()