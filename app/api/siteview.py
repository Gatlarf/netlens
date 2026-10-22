"""Looking at a remote site with the pages of this Netlens (see app/relay.py): the endpoint the web interface calls, and the two a remote site polls."""

from __future__ import annotations

import base64
import binascii
import json
import zlib

from fastapi import APIRouter, HTTPException, Request, Response

from app import probes as probes_mod, relay
from app.auth import LoginLimiter, client_ip
from app.db import connect

router = APIRouter(prefix="/api", tags=["remote-sites"])
push_router = APIRouter(tags=["remote-sites"])
MAX_ANSWER = 9 * 1024 * 1024


def _probe(request: Request):
    """The remote site that signs in with its token (the same one it reports with), or 401."""
    limiter: LoginLimiter = request.app.state.share_limiter
    host = client_ip(request)
    if not limiter.allowed(host):
        raise HTTPException(status_code=429, detail="too many attempts")
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    conn = connect(request.app.state.db_path)
    try:
        probe = probes_mod.find_by_token(conn, token) if token else None
        if probe is None or not probe["enabled"]:
            limiter.record_failure(host)
            raise HTTPException(status_code=401, detail="this token is not valid")
        if probe["id"] in probes_mod.locked_ids(conn):
            raise HTTPException(status_code=402, detail="this site is frozen until a licence key is added")
        return dict(probe)
    finally:
        conn.close()


@push_router.get("/api/probe/relay")
async def poll(request: Request, wait: float = relay.POLL_WAIT) -> dict:
    """A remote site asks: is somebody looking at me? Answers at once when a request is queued, otherwise after `wait` seconds with nothing."""
    probe = _probe(request)
    return {"requests": await relay.HUB.poll(probe["id"], max(1.0, min(wait, relay.POLL_WAIT)))}


@push_router.post("/api/probe/relay/{request_id}")
async def answer(request_id: str, request: Request) -> dict:
    probe = _probe(request)
    body = await request.body()
    if len(body) > MAX_ANSWER:
        raise HTTPException(status_code=413, detail="the answer is too large")
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            body = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, MAX_ANSWER * 2)
        except zlib.error:
            raise HTTPException(status_code=400, detail="not valid gzip")
    try:
        payload = json.loads(body)
        int(payload["status"])
        base64.b64decode(payload["body"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise HTTPException(status_code=400, detail="not a valid answer")
    return {"ok": relay.HUB.answer(probe["id"], request_id, payload)}


@router.get("/site-view/{probe_id}/{path:path}")
async def view(probe_id: int, path: str, request: Request) -> Response:
    """One read of a remote site's own API, answered by that site (administrators only; the site must have allowed it)."""
    conn = connect(request.app.state.db_path)
    try:
        row = conn.execute("SELECT * FROM probes WHERE id = ?", (probe_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="remote site not found")
        if probe_id in probes_mod.locked_ids(conn):
            raise HTTPException(status_code=402, detail="this site is frozen: there is no licence for this many remote sites")
        summary = json.loads(row["summary"] or "{}")
    finally:
        conn.close()
    if not summary.get("accepts_view"):
        raise HTTPException(status_code=403, detail="this site does not allow viewing from here: tick “Let the central Netlens show this site” in its Settings > Report to a central Netlens")
    target = "/" + path + (f"?{request.url.query}" if request.url.query else "")
    if not relay.allowed_path(target):
        raise HTTPException(status_code=403, detail="this part is not shown through the central Netlens")
    try:
        answer_ = await relay.HUB.ask(probe_id, target)
    except relay.SiteOffline as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    return Response(content=base64.b64decode(answer_.get("body") or ""), status_code=int(answer_.get("status") or 502),
                    media_type=str(answer_.get("content_type") or "application/json").split(";")[0] or "application/json",
                    headers={"Cache-Control": "no-store", "X-Netlens-Site": str(probe_id)})
