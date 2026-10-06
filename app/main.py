import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from app.api.devices import router as devices_router
from app.api.scans import router as scans_router
from app.db import connect, init_db
from app.config import load_settings

VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db_path = app.state.db_path
    conn = connect(db_path)
    try:
        init_db(conn)
        yield
    finally:
        conn.close()


def create_app(settings: Any, db_path: str | os.PathLike | None = None) -> FastAPI:
    if db_path is None:
        db_path = settings.data_dir / "netlens.db"

    app = FastAPI(title="Netlens", lifespan=lifespan)
    app.state.settings = settings
    app.state.db_path = str(db_path)

    app.include_router(devices_router)
    app.include_router(scans_router)

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": VERSION}

    return app


def main() -> None:
    import uvicorn

    settings = load_settings()
    app = create_app(settings)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()