from __future__ import annotations

from typing import TYPE_CHECKING

import uvicorn
from fastapi import FastAPI

if TYPE_CHECKING:
    from app.config import Settings

VERSION = "0.1.0"


def create_app(settings: "Settings") -> FastAPI:
    app = FastAPI(title="Netlens", version=VERSION)
    app.state.settings = settings

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": VERSION}

    return app


def main() -> None:
    from app.config import load_settings

    settings = load_settings()
    app = create_app(settings)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port)


if __name__ == "__main__":
    main()