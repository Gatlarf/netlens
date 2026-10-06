INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/main.py
24:VERSION = "0.1.0"
28:async def lifespan(app: FastAPI):
55:def create_app(
56:    settings: Any,
57:    db_path: str | os.PathLike | None = None,
59:    scheduler: bool = False,
60:    scan_manager: ScanManager | None = None,
86:    async def health() -> dict[str, str]:
96:def main() -> None:

## app/security.py
7:class SecurityHeadersMiddleware:
12:    def __init__(self, app: ASGIApp) -> None:
15:    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:

TASK:
Rewrite app/main.py (COMPLETE file; current file below). Keep everything. Add app.add_middleware(SecurityHeadersMiddleware) (from app.security import SecurityHeadersMiddleware) in create_app right after the FastAPI object is created.
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

from app.api import config, devices, events, export, relations, scans
from app.api.auth import router as auth_router
from app.api.terminal import router as terminal_router
from app.auth import LoginLimiter, require_auth
from app.config import load_settings
from app.db import connect, init_db
from app.scanner.orchestrator import ScanManager
from app.scanner.scheduler import scheduler_loop
from app.terminal.ssh import SSHBackend
from app.terminal.telnet import TelnetBackend

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

    if getattr(settings, "terminal_enabled", False):
        app.include_router(terminal_router)

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