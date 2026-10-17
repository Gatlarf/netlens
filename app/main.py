"""Netlens application entry point."""

import asyncio
import logging
import contextlib
import os
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from starlette.requests import HTTPConnection
from fastapi.staticfiles import StaticFiles

from starlette.middleware.gzip import GZipMiddleware

from app.api import changelog as changelog_api, dns as dns_api, passive as passive_api, backup as backup_api, backups as backups_api, channels as channels_api, config, devices, events, export, groups as groups_api, hierarchy as hierarchy_api, ignored, maintenance as maintenance_api, mapsettings, sites as sites_api, guest_backups as guest_backups_api, metrics as metrics_api, plugin_index, plugins, relations, scans, services as services_api, speedtest as speedtest_api, stats as stats_api, dashboard as dashboard_api, netchecks as netchecks_api, public_share, setup as setup_api, vendor_db as vendor_db_api, shares as shares_api, update as update_api, users as users_api, uptime, wifi, wizard as wizard_api, vault as vault_api, remote as remote_api, timeseries as timeseries_api, monitors as monitors_api, probes as probes_api, central as central_api, licence as licence_api, ipv6 as ipv6_api, inventory as inventory_api, reports as reports_api, preferences as preferences_api, snoozes as snoozes_api, audit as audit_api, changes as changes_api
from app.api.auth import router as auth_router
from app.api.terminal import router as terminal_router
from app.auth import LoginLimiter, identify, require_auth
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


def _backfill_graphs(db_path: str) -> None:
    """Once, after the update that brought the graphs: fill them from the uptime history Netlens already has."""
    import logging

    from app import tsdb

    try:
        main = connect(db_path)
        try:
            tsdb.for_path(db_path).backfill(main)
        finally:
            main.close()
    except Exception:  # noqa: BLE001 - graphs are a convenience
        logging.getLogger(__name__).exception("could not fill the graphs from the history")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    conn = connect(app.state.db_path)
    init_db(conn)
    from app import vault

    vault.migrate(conn)                      # passwords and tokens that are still plain text get encrypted (once)
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
    settings = app.state.settings
    if getattr(settings, "demo", False):
        # demo mode: a made-up network that keeps moving; nothing real is scanned, checked or run
        from app.demo.live import demo_loop
        from app.demo.seed import seed

        seed(conn, settings.data_dir)
        tasks.append(asyncio.create_task(demo_loop(app.state.db_path, settings.data_dir, settings.demo_reset)))
    elif getattr(app.state, "scheduler", False):
        tasks.append(asyncio.create_task(
            scheduler_loop(
                app.state.scan_manager,
                lambda: app.state.settings.quick_interval,
                lambda: app.state.settings.deep_interval,
            )
        ))
        tasks.append(asyncio.create_task(service_loop(app.state.db_path)))
        tasks.append(asyncio.create_task(asyncio.to_thread(_backfill_graphs, app.state.db_path)))
        from app.hostmetrics import service as host_monitors

        tasks.append(asyncio.create_task(host_monitors.loop(app.state.db_path)))
        from app import central

        tasks.append(asyncio.create_task(central.loop(app.state.db_path)))
        from app.scanner.passive import Control

        app.state.passive = Control(app.state.db_path)
        if app.state.passive.enabled():
            app.state.passive.start()
        import logging

        from app import speedtest as speedtest_mod

        wanted = speedtest_mod.get_iperf_settings(conn)
        if wanted["enabled"]:  # the iperf3 server the owner switched on stays on after a restart
            try:
                app.state.iperf.start(wanted["port"])
            except RuntimeError as exc:
                logging.getLogger(__name__).warning("iperf3 server not started: %s", exc)

    try:
        yield
    finally:
        if getattr(app.state, "passive", None) is not None:
            app.state.passive.stop()
        app.state.iperf.stop()
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
    docs = bool(getattr(settings, "api_docs", False))      # the API map is for the owner, not for the internet: off unless NETLENS_API_DOCS=on
    app = FastAPI(title="Netlens", lifespan=lifespan, docs_url="/docs" if docs else None, redoc_url="/redoc" if docs else None,
                  openapi_url="/openapi.json" if docs else None)

    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)     # the JSON lists and the script files shrink to a quarter; streams and images are left alone
    app.add_middleware(SecurityHeadersMiddleware)

    @app.middleware("http")
    async def audit_requests(request, call_next):
        """Write down who changed what (see app/audit.py). It never changes the answer, and a failure to write is only logged."""
        response = await call_next(request)
        try:
            if request.method in ("POST", "PUT", "PATCH", "DELETE") and 200 <= response.status_code < 300 and request.url.path.startswith("/api/"):
                principal = getattr(request.state, "user", None)
                if principal is not None:
                    from app import audit
                    from app.auth import client_ip
                    from app.db import connect as db_connect

                    db = db_connect(request.app.state.db_path)
                    try:
                        audit.log_request(db, principal, client_ip(request), request.method, request.url.path, response.status_code)
                    finally:
                        db.close()
        except Exception:  # noqa: BLE001
            logging.getLogger(__name__).exception("could not write the audit log")
        return response
    if getattr(settings, "demo", False):
        from app.demo import guard

        guard.install(app)

    app.state.settings = settings
    app.state.env_settings = settings
    app.state.overrides = set()
    app.state.db_path = str(db_path) if db_path is not None else str(settings.data_dir / "netlens.db")
    app.state.scheduler = scheduler
    app.state.scan_manager = scan_manager or ScanManager(app.state.db_path, settings)
    from app import iperf

    app.state.iperf = iperf.Server(app.state.db_path)
    app.state.login_limiter = LoginLimiter()
    app.state.user_limiter = LoginLimiter(max_failures=20, window=900.0)
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
    app.include_router(backup_api.router, dependencies=auth_deps)
    app.include_router(backups_api.router, dependencies=auth_deps)
    app.include_router(users_api.router, dependencies=auth_deps)
    app.include_router(netchecks_api.router, dependencies=auth_deps)
    app.include_router(groups_api.router, dependencies=auth_deps)
    app.include_router(vendor_db_api.router, dependencies=auth_deps)
    app.include_router(passive_api.router, dependencies=auth_deps)
    app.include_router(dns_api.router, dependencies=auth_deps)
    app.include_router(shares_api.router, dependencies=auth_deps)
    app.include_router(plugin_index.router, dependencies=auth_deps)
    app.include_router(update_api.router, dependencies=auth_deps)
    app.include_router(changelog_api.router, dependencies=auth_deps)
    app.include_router(plugins.router, dependencies=auth_deps)
    app.include_router(stats_api.router, dependencies=auth_deps)
    app.include_router(dashboard_api.router, dependencies=auth_deps)
    app.include_router(wizard_api.router, dependencies=auth_deps)
    app.include_router(vault_api.router, dependencies=auth_deps)
    app.include_router(remote_api.router)         # its routes check the sign-in and the terminal rules themselves (the WebSocket cannot use the dependency)
    app.include_router(timeseries_api.router, dependencies=auth_deps)
    app.include_router(monitors_api.router, dependencies=auth_deps)
    app.include_router(probes_api.router, dependencies=auth_deps)
    app.include_router(central_api.router, dependencies=auth_deps)
    app.include_router(licence_api.router, dependencies=auth_deps)
    app.include_router(ipv6_api.router, dependencies=auth_deps)
    app.include_router(inventory_api.router, dependencies=auth_deps)
    app.include_router(reports_api.router, dependencies=auth_deps)
    app.include_router(preferences_api.router, dependencies=auth_deps)
    app.include_router(snoozes_api.router, dependencies=auth_deps)
    app.include_router(audit_api.router, dependencies=auth_deps)
    app.include_router(changes_api.router, dependencies=auth_deps)
    app.include_router(probes_api.push_router)       # a probe signs in with its own token (checked there), not with a user session
    app.include_router(speedtest_api.router, dependencies=auth_deps)
    app.include_router(wifi.router, dependencies=auth_deps)
    app.include_router(services_api.router, dependencies=auth_deps)
    app.include_router(channels_api.router, dependencies=auth_deps)
    app.include_router(metrics_api.router, dependencies=auth_deps)
    app.include_router(mapsettings.router, dependencies=auth_deps)
    app.include_router(hierarchy_api.router, dependencies=auth_deps)
    app.include_router(ignored.router, dependencies=auth_deps)
    app.include_router(maintenance_api.router, dependencies=auth_deps)
    app.include_router(sites_api.router, dependencies=auth_deps)
    app.include_router(guest_backups_api.router, dependencies=auth_deps)

    # Always mounted; each request is refused (404) while the terminal is switched off,
    # so it can be toggled at runtime from the Settings page.
    app.include_router(terminal_router, dependencies=[Depends(require_terminal_enabled)])

    @app.get("/api/health")
    async def health(request: Request) -> dict[str, str]:
        if identify(request) is None:       # the version tells a stranger which known flaws to try
            return {"status": "ok"}
        return {"status": "ok", "version": VERSION}

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        from app import assets

        @app.get("/", include_in_schema=False)
        @app.get("/index.html", include_in_schema=False)
        async def index_page(request: Request):
            return assets.page_response("index.html", request.headers.get("if-none-match"))

        app.mount("/v", assets.VersionedStatic(directory=static_dir), name="static-versioned")
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


def main() -> None:
    settings = load_settings()
    app = create_app(settings, scheduler=True)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()