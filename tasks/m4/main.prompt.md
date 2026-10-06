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
21:VERSION = "0.1.0"
25:async def lifespan(app: FastAPI):
52:def create_app(
53:    settings: Any,
54:    db_path: str | os.PathLike | None = None,
56:    scheduler: bool = False,
57:    scan_manager: ScanManager | None = None,
76:    async def health() -> dict[str, str]:
86:def main() -> None:

## app/api/relations.py
13:class RelationCreate(BaseModel):
14:    src_id: int
15:    dst_id: int
16:    kind: str = "manual"
20:def get_relations(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict[str, Any]]:
25:def create_relation(
26:    body: RelationCreate,
27:    conn: sqlite3.Connection = Depends(get_conn),
37:def remove_relation(
38:    relation_id: int,
39:    conn: sqlite3.Connection = Depends(get_conn),
46:def get_map(conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
47:    nodes: list[dict[str, Any]] = []
77:    edges: list[dict[str, Any]] = []

## app/api/export.py
15:def _csv_safe(value: str) -> str:
21:def _build_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
22:    rows: list[dict[str, Any]] = []
104:def export_devices_json(
105:    request: Request,
106:    conn: sqlite3.Connection = Depends(get_conn),
117:def export_devices_csv(
118:    request: Request,
119:    conn: sqlite3.Connection = Depends(get_conn),

TASK:
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