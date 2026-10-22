"""Look at a remote site through the central Netlens, with the same pages as at the site itself.

Nothing is copied: the remote Netlens keeps one outgoing request open to the central one (a long poll). When somebody at the central Netlens opens the site,
the central side puts the page's API requests in a queue, the remote picks them up with that open request, answers them from its own data, and posts the
answers back. So the connection still always goes out from the remote site, the central Netlens stores nothing extra, and the remote site shows exactly
what its own interface would show.

Only reads are relayed (GET), only for administrators of the central Netlens, only when the remote site ticked *Let the central Netlens show this site*,
and never the parts that hand out secrets or the whole database (backup, users, vault, licence...).
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import logging
import re
import secrets
import time
import urllib.parse
from typing import Any

log = logging.getLogger(__name__)

POLL_WAIT = 25.0                   # seconds the central side holds a poll open when nothing is queued
CONNECTED_FOR = 60.0               # a site counts as connected this long after its last poll
ANSWER_TIMEOUT = 30.0
MAX_BODY = 6 * 1024 * 1024
MAX_PATH = 2000

# what the remote never relays, even to the central Netlens: everything that hands out secrets, accounts or the database itself
DENIED = re.compile(
    r"^/api/(probe|probes|probes-search|site-view|central|users|me|tokens|api-tokens|vault|backup|restore|database|licence|license|sso|shares?|assistant|mcp|remote|export|"
    r"setup|login|logout|session|siem|inbound|update|terminal|audit)(/|$|\?)")


def allowed_path(path: str) -> bool:
    return (isinstance(path, str) and path.startswith("/api/") and len(path) <= MAX_PATH and ".." not in path and "//" not in path
            and not DENIED.match(path.split("?", 1)[0] + "/"))


# ----------------------------------------------------------------------------- central side: a queue per site
class Hub:
    def __init__(self) -> None:
        self.queues: dict[int, asyncio.Queue] = {}
        self.waiting: dict[str, tuple[int, asyncio.Future]] = {}
        self.polling: dict[int, int] = {}
        self.last_poll: dict[int, float] = {}

    def connected(self, probe_id: int) -> bool:
        return self.polling.get(probe_id, 0) > 0 or time.monotonic() - self.last_poll.get(probe_id, -1e9) < CONNECTED_FOR

    def _queue(self, probe_id: int) -> asyncio.Queue:
        return self.queues.setdefault(probe_id, asyncio.Queue())

    async def poll(self, probe_id: int, wait: float = POLL_WAIT) -> list[dict]:
        """What the site should answer now (empty after `wait` seconds when nothing came)."""
        queue = self._queue(probe_id)
        self.polling[probe_id] = self.polling.get(probe_id, 0) + 1
        try:
            items = [await asyncio.wait_for(queue.get(), wait)]
            while not queue.empty() and len(items) < 20:
                items.append(queue.get_nowait())
            return items
        except asyncio.TimeoutError:
            return []
        finally:
            self.polling[probe_id] -= 1
            self.last_poll[probe_id] = time.monotonic()

    async def ask(self, probe_id: int, path: str, timeout: float = ANSWER_TIMEOUT) -> dict:
        if not self.connected(probe_id):
            raise SiteOffline("this site is not connected right now (it opens the connection itself; check that it is running and that it allows viewing)")
        request_id = secrets.token_hex(8)
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.waiting[request_id] = (probe_id, future)
        try:
            await self._queue(probe_id).put({"id": request_id, "method": "GET", "path": path})
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            raise SiteOffline("the site did not answer in time") from None
        finally:
            self.waiting.pop(request_id, None)

    def answer(self, probe_id: int, request_id: str, response: dict) -> bool:
        entry = self.waiting.get(request_id)
        if entry is None or entry[0] != probe_id or entry[1].done():
            return False
        entry[1].set_result(response)
        return True

    def forget(self, probe_id: int) -> None:
        self.queues.pop(probe_id, None)
        self.last_poll.pop(probe_id, None)


class SiteOffline(Exception):
    pass


HUB = Hub()


# ----------------------------------------------------------------------------- remote side: answer from the local application
def secret_for(app) -> str:
    if not getattr(app.state, "relay_secret", None):
        app.state.relay_secret = secrets.token_hex(24)
    return app.state.relay_secret


async def call_app(app, path: str) -> tuple[int, str, bytes]:
    """Run one GET through the application itself (all its middleware and checks), as the central Netlens."""
    raw_path, _, query = path.partition("?")
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http", "path": urllib.parse.unquote(raw_path),
             "raw_path": raw_path.encode(), "query_string": query.encode(), "root_path": "", "client": ("relay", 0), "server": ("relay", 80),
             "headers": [(b"host", b"relay"), (b"accept", b"application/json"), (b"x-netlens-relay", secret_for(app).encode())]}
    status, ctype, chunks, size = 500, "application/json", [], 0
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status, ctype, size
        if message["type"] == "http.response.start":
            status = message["status"]
            for k, v in message.get("headers", []):
                if k.lower() == b"content-type":
                    ctype = v.decode("latin-1")
        elif message["type"] == "http.response.body":
            size += len(message.get("body", b""))
            if size <= MAX_BODY:
                chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    if size > MAX_BODY:
        return 413, "application/json", json.dumps({"detail": "the answer is too large to send through the central Netlens"}).encode()
    return status, ctype, b"".join(chunks)


def is_relay(request) -> bool:
    """True for a request that came through call_app (same process, with this application's secret)."""
    client = request.client
    header = request.headers.get("x-netlens-relay")
    return bool(client and client.host == "relay" and header and secrets.compare_digest(header, secret_for(request.app)))


async def serve(app, send_answer, item: dict[str, Any]) -> None:
    """Answer one queued request and hand the answer back with `send_answer(request_id, payload)` (a blocking call, run in a thread)."""
    path = item.get("path")
    if item.get("method") != "GET" or not allowed_path(path):
        status, ctype, body = 403, "application/json", json.dumps({"detail": "this part is not shown through the central Netlens"}).encode()
    else:
        try:
            status, ctype, body = await asyncio.wait_for(call_app(app, path), 25)
        except Exception:  # noqa: BLE001 - one failing page must not stop the relay
            log.exception("relayed request failed")
            status, ctype, body = 500, "application/json", json.dumps({"detail": "the site could not answer"}).encode()
    payload = {"status": status, "content_type": ctype, "body": base64.b64encode(body).decode()}
    await asyncio.to_thread(send_answer, str(item.get("id")), payload)
