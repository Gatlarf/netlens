Rewrite app/main.py (COMPLETE file; current file below). Keep everything. Additionally include two more routers, each with dependencies=[Depends(require_auth)] exactly like the existing protected routers: app.api.relations.router and app.api.export.router (import them with the others).
CURRENT FILE:
"""Netlens application entry point."""

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import config, devices, events, scans
from app.api.auth import router as auth_router
from app.auth import LoginLimiter, require_auth
from app.config import load_settings
from app.db import connect, init_db
from app.scanner.orchestrator import ScanManager
from app.scanner.scheduler import scheduler_loop

VERSION = "0.1.0"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    conn = connect(app.state.db_path)
    init_db(conn)
    app.state.scan_manager.recover()

    task = None
    if getattr(app.state, "scheduler", False):
        task = asyncio.create_task(
            scheduler_loop(
                app.state.scan_manager,
                app.state.settings.quick_interval,
                app.state.settings.deep_interval,
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

    app.state.settings = settings
    app.state.db_path = str(db_path) if db_path is not None else str(settings.data_dir / "netlens.db")
    app.state.scheduler = scheduler
    app.state.scan_manager = scan_manager or ScanManager(app.state.db_path, settings)
    app.state.login_limiter = LoginLimiter()

    app.include_router(auth_router)

    auth_deps = [Depends(require_auth)]
    app.include_router(devices.router, dependencies=auth_deps)
    app.include_router(scans.router, dependencies=auth_deps)
    app.include_router(events.router, dependencies=auth_deps)
    app.include_router(config.router, dependencies=auth_deps)

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