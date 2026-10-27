"""Keeps visitors of the demo from changing anything. The demo account is an administrator (so every page shows), but every request
that would change something is refused with a friendly message; only signing in and out work."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

ALLOWED_WRITES = ("/api/login", "/api/logout", "/api/speedtest/up", "/api/speedtest/browser", "/api/insights/ask")   # the browser speed test only measures; a question only reads
MESSAGE = "This is a demo with made-up data: changes are switched off here. Install Netlens yourself to try them."


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def demo_guard(request: Request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path not in ALLOWED_WRITES:
            return JSONResponse({"detail": MESSAGE}, status_code=403)
        return await call_next(request)
