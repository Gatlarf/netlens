Rewrite app/main.py (full file). Current behaviour to keep: VERSION = "0.1.0"; create_app builds FastAPI(title="Netlens"), stores settings in app.state.settings, GET /api/health returns {"status": "ok", "version": VERSION} unauthenticated; main() loads settings with app.config.load_settings() and runs uvicorn on settings.bind_host/bind_port; no module-level app instance.
Changes:
- def create_app(settings, db_path: str | os.PathLike | None = None) -> FastAPI. db_path defaults to settings.data_dir / "netlens.db". Store str(db_path) in app.state.db_path.
- Use a FastAPI lifespan context manager: on startup open app.db.connect(app.state.db_path), run app.db.init_db(conn), close it. (Do NOT touch the database inside create_app itself, so tests that never start the app work without a writable data dir.)
- Include the routers: from app.api.devices import router as devices_router; from app.api.scans import router as scans_router.
