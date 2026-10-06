Rewrite app/main.py (COMPLETE file; the current file is the CURRENT FILE below). Keep all existing behaviour. Changes:
1. app.state.login_limiter = app.auth.LoginLimiter() in create_app.
2. Routers: include app.api.auth.router publicly (no dependency); include devices, scans, events and the new app.api.config router each with dependencies=[Depends(require_auth)] (from app.auth import require_auth). /api/health stays public.
3. After all routes, if the directory Path(__file__).parent / "static" exists, mount it: app.mount("/", StaticFiles(directory=static_dir, html=True), name="static") (from fastapi.staticfiles import StaticFiles). It must be the last thing registered.
CURRENT FILE:
"""Netlens application entry point."""

import asyncio
import contextlib
import os
from typing import Any

import uvicorn
from fastapi import FastAPI

from app.api import devices, events, scans
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

    app.include_router(devices.router)
    app.include_router(scans.router)
    app.include_router(events.router)

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": VERSION}

    return app


def main() -> None:
    settings = load_settings()
    app = create_app(settings, scheduler=True)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()