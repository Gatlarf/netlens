import re
from typing import Any, Callable, Optional

from starlette.types import ASGIApp, Receive, Scope, Send


class SecurityHeadersMiddleware:
    """
    Plain ASGI middleware that adds security headers to HTTP responses.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        is_api = path.startswith("/api/")

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                existing_keys = {
                    key.decode("latin-1").lower() for key, _ in headers
                }

                def add_header(name: str, value: str) -> None:
                    if name.lower() not in existing_keys:
                        headers.append((name.encode("latin-1"), value.encode("latin-1")))

                add_header("X-Content-Type-Options", "nosniff")
                add_header("X-Frame-Options", "DENY")
                add_header("Referrer-Policy", "no-referrer")
                add_header("Cross-Origin-Opener-Policy", "same-origin")
                add_header(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=()",
                )
                add_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                )

                if is_api:
                    add_header("Cache-Control", "no-store")

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_headers)