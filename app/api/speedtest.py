import asyncio
import os
import threading
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from app import iperf, speedtest
from app.api.devices import get_conn
from app.auth import client_ip

router = APIRouter(prefix="/api/speedtest", tags=["speedtest"])
BLOCK = os.urandom(262144)           # not compressible, so a proxy that gzips cannot fake a fast line
MAX_DOWNLOAD = 256_000_000
MAX_UPLOAD = 256_000_000


def _server(request: Request) -> iperf.Server:
    return request.app.state.iperf


def _demo(request: Request) -> bool:
    return bool(getattr(request.app.state.settings, "demo", False))


def _iperf_view(request: Request, conn) -> dict:
    settings = speedtest.get_iperf_settings(conn)
    if _demo(request):  # nothing runs in the demo: it only shows what the page looks like with a server listening
        status = {"installed": True, "running": True, "port": settings["port"], "since": None, "error": None, "last_test": None, "demo": True}
    else:
        status = _server(request).status()
    return {**status, "enabled": settings["enabled"], "configured_port": settings["port"], "addresses": speedtest.local_addresses()}


@router.get("")
def overview(request: Request, conn=Depends(get_conn)) -> dict:
    return {
        "current": speedtest.PROGRESS.snapshot(),
        "internet": {"schedule": speedtest.get_schedule(conn), "last": speedtest.latest(conn, "internet")},
        "iperf": _iperf_view(request, conn),
        "history": speedtest.history(conn, limit=200),
    }


@router.get("/status")
def status() -> dict:
    """What a running test is doing (polled once a second by the page)."""
    return {"current": speedtest.PROGRESS.snapshot()}


class ScheduleBody(BaseModel):
    enabled: bool
    every_hours: int


@router.put("/schedule")
def put_schedule(body: ScheduleBody, conn=Depends(get_conn)) -> dict:
    try:
        return speedtest.set_schedule(conn, body.enabled, body.every_hours)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/internet", status_code=202)
def run_internet(request: Request) -> dict:
    if not speedtest.PROGRESS.start("internet", "Cloudflare"):
        raise HTTPException(status_code=409, detail="A speed test is already running.")
    threading.Thread(target=speedtest.run_and_record, args=(request.app.state.db_path, speedtest.PROGRESS), daemon=True).start()
    return {"started": True}


class IperfServerBody(BaseModel):
    enabled: bool
    port: int = Field(5201, ge=1, le=65535)


@router.put("/iperf/server")
def put_iperf_server(body: IperfServerBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        speedtest.set_iperf_settings(conn, body.enabled, body.port)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not _demo(request):
        server = _server(request)
        if body.enabled:
            try:
                server.start(body.port)
            except RuntimeError as exc:
                speedtest.set_iperf_settings(conn, False, body.port)  # do not try again at every start
                raise HTTPException(status_code=409, detail=str(exc))
        else:
            server.stop()
    return _iperf_view(request, conn)


class IperfRunBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(5201, ge=1, le=65535)
    seconds: int = Field(10, ge=3, le=60)
    direction: Literal["up", "down", "both"] = "both"
    streams: int = Field(4, ge=1, le=16)


@router.post("/iperf/run", status_code=202)
def run_iperf(body: IperfRunBody, request: Request) -> dict:
    if not iperf.available():
        raise HTTPException(status_code=409, detail="iperf3 is not installed in this container.")
    host = body.host.strip()
    if not iperf.valid_host(host):
        raise HTTPException(status_code=422, detail="That is not a valid host name or address.")
    if not speedtest.PROGRESS.start("iperf-out", f"{host}:{body.port}"):
        raise HTTPException(status_code=409, detail="A speed test is already running.")
    threading.Thread(target=iperf.run_client_and_record, args=(request.app.state.db_path, host, body.port, body.seconds, body.direction, body.streams), daemon=True).start()
    return {"started": True}


@router.delete("/history")
def clear_history(conn=Depends(get_conn)) -> dict:
    speedtest.clear(conn)
    return {"ok": True}


# ---- the browser test: the page measures the line between this device and Netlens ----

@router.get("/ping")
def ping() -> Response:
    return Response(b"", headers={"Cache-Control": "no-store"})


@router.get("/down")
def download(bytes: int = Query(10_000_000, ge=0, le=MAX_DOWNLOAD)) -> StreamingResponse:
    def blocks():
        left = bytes
        while left > 0:
            chunk = BLOCK if left >= len(BLOCK) else BLOCK[:left]
            left -= len(chunk)
            yield chunk

    return StreamingResponse(blocks(), media_type="application/octet-stream", headers={"Content-Length": str(bytes), "Cache-Control": "no-store", "Content-Encoding": "identity"})


@router.post("/up")
async def upload(request: Request) -> dict:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="too much data for one request")
    return {"bytes": total}


class BrowserResult(BaseModel):
    down_mbps: float | None = Field(None, ge=0, le=1e6)
    up_mbps: float | None = Field(None, ge=0, le=1e6)
    latency_ms: float | None = Field(None, ge=0, le=1e5)
    jitter_ms: float | None = Field(None, ge=0, le=1e5)
    label: str = Field("", max_length=60)


@router.post("/browser", status_code=201)
def save_browser(body: BrowserResult, request: Request, conn=Depends(get_conn)) -> dict:
    """Stores what the page measured (the page is the only one who can know)."""
    address = client_ip(request)
    rid = speedtest.record(conn, "browser", address, down=body.down_mbps, up=body.up_mbps, latency=body.latency_ms, jitter=body.jitter_ms, detail={"label": body.label})
    speedtest.prune(conn)
    return {"id": rid}
