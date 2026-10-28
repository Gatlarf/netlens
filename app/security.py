import json
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
        forwarded = dict(scope.get("headers") or []).get(b"x-forwarded-proto", b"").decode("latin-1").split(",")[0].strip().lower()
        https = scope.get("scheme") == "https" or forwarded == "https"      # browsers only honour HSTS received over https anyway

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                existing_keys = {
                    key.decode("latin-1").lower() for key, _ in headers
                }

                def add_header(name: str, value: str) -> None:
                    if name.lower() not in existing_keys:
                        headers.append((name.encode("latin-1"), value.encode("latin-1")))

                if https:
                    add_header("Strict-Transport-Security", "max-age=31536000")
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

                from app import assets

                if is_api:
                    add_header("Cache-Control", "no-store")
                elif path.startswith(f"/v/{assets.VERSION}/") and message.get("status") == 200 and assets.cacheable():
                    add_header("Cache-Control", assets.IMMUTABLE)       # the address contains the version: a new version is a new address
                else:
                    # Static UI files: always revalidate (cheap 304 via ETag) so a
                    # redeploy is picked up immediately instead of a stale cached module.
                    add_header("Cache-Control", "no-cache")
                    # A CDN in front (Cloudflare caches .js and .css by default, for hours) must not keep an old
                    # copy either; this header is for the CDN only and leaves the browser behaviour above alone.
                    add_header("Cloudflare-CDN-Cache-Control", "no-store")

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_headers)


# ----------------------------------------------------------------------------- request size
MIB = 1024 * 1024
DEFAULT_LIMIT = 4 * MIB                  # an ordinary API request (settings, a list of ids ...) is tiny; nothing legitimate needs more
LIMITS: list[tuple[str, int]] = [        # (path prefix, bytes): the few requests that carry a file or a whole report
    ("/api/restore", 1024 * MIB),          # a backup of the database
    ("/api/plugins", 3 * MIB),             # a plugin archive (the plugin loader allows 2 MiB)
    ("/api/probe/", 64 * MIB),             # what a remote site reports to the central Netlens
    ("/api/siteview/", 8 * MIB),
    ("/api/speedtest/up", 1024 * MIB),     # the upload test sends data on purpose (and has its own limit)
    ("/api/login", 16 * 1024),
    ("/share-api/", 16 * 1024),
]


def limit_for(path: str) -> int:
    for prefix, limit in LIMITS:
        if path.startswith(prefix):
            return limit
    return DEFAULT_LIMIT


class _TooLarge(BaseException):        # not an Exception: the framework's own error handling must not turn it into a 500
    pass


class BodyLimitMiddleware:
    """Refuses a request whose body is larger than its limit: by the declared Content-Length, and again while the body arrives (a chunked body declares nothing).
    Without it the framework reads whatever it is sent into memory before the application sees it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        limit = limit_for(scope.get("path", ""))
        declared = dict(scope.get("headers") or []).get(b"content-length")
        try:
            if declared is not None and int(declared) > limit:
                await self._refuse(send, limit)
                return
        except ValueError:
            await self._refuse(send, limit, 400, "the Content-Length is not a number")
            return
        received = 0
        started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _TooLarge()
            return message

        async def tracking_send(message: dict[str, Any]) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._refuse(send, limit)

    @staticmethod
    async def _refuse(send: Send, limit: int, status: int = 413, text: str | None = None) -> None:
        size = f"{limit // 1024} KiB" if limit < MIB else f"{limit // MIB} MiB"
        body = json.dumps({"detail": text or f"the request is too large (at most {size} for this address)"}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
