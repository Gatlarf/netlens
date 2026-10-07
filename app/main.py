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

from app.api import backup as backup_api, config, devices, events, export, notifications, relations, scans, uptime
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
from app.version import VERSION



async def require_terminal_enabled(conn: HTTPConnection) -> None:
    if not conn.app.state.settings.terminal_enabled:
        raise HTTPException(status_code=404, detail="web terminal is disabled")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    conn = connect(app.state.db_path)
    init_db(conn)
    config.apply_overrides(app)
    app.state.scan_manager.recover()

    task = None
    if getattr(app.state, "scheduler", False):
        task = asyncio.create_task(
            scheduler_loop(
                app.state.scan_manager,
                lambda: app.state.settings.quick_interval,
                lambda: app.state.settings.deep_interval,
            )
        )

    try:
        yield
    finally:
        if task is not None:
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
    app.state.terminal_backends = {"ssh": SSHBackend, "telnet": TelnetBackend}
    app.state.terminal_sessions = 0

    app.include_router(auth_router)

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