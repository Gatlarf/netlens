Create app/main.py with FastAPI.

- VERSION = "0.1.0".
- def create_app(settings) -> FastAPI: settings is an app.config.Settings instance (import it only for typing). Stores settings in app.state.settings. Defines GET /api/health returning {"status": "ok", "version": VERSION} with no authentication. Title "Netlens".
- No module-level app instance and no auth yet (added in a later milestone). Add a `def main()` that loads settings via app.config.load_settings(), builds the app and runs uvicorn.run(app, host=settings.bind_host, port=settings.bind_port); guarded by if __name__ == "__main__".
