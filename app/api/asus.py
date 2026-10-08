import asyncio

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.db import connect
from app.integrations.asus_client import AsusClient, AsusError
from app.integrations.asus_config import AsusConfig, is_configured, load_config, normalize_url, public_dict, save_config
from app.integrations.asus_sync import SOURCE, load_status, sync_now

router = APIRouter(prefix="/api", tags=["asus"])


def _payload(conn) -> dict:
    return {**public_dict(load_config(conn)), "status": load_status(conn)}


class AsusBody(BaseModel):
    """Only the fields sent are changed. A missing or empty password keeps the saved one."""

    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=300)
    verify_tls: bool | None = None
    username: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, max_length=500)


def _merge(cfg: AsusConfig, body: AsusBody) -> AsusConfig:
    fields = body.model_fields_set
    if "url" in fields and body.url is not None:
        try:
            cfg.url = normalize_url(body.url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    for name in ("enabled", "verify_tls"):
        if name in fields and getattr(body, name) is not None:
            setattr(cfg, name, getattr(body, name))
    if "username" in fields and body.username is not None:
        cfg.username = body.username.strip()
    if body.password:
        cfg.password = body.password
    return cfg


def _factory(request: Request):
    return getattr(request.app.state, "asus_factory", AsusClient)


@router.get("/asus")
def get_asus(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _payload(conn)
    finally:
        conn.close()


@router.put("/asus")
async def put_asus(request: Request, body: AsusBody) -> dict:
    db_path = request.app.state.db_path
    conn = connect(db_path)
    try:
        cfg = _merge(load_config(conn), body)
        if cfg.enabled and not is_configured(cfg):
            raise HTTPException(status_code=422, detail="to enable the connector set the router address, username and password")
        save_config(conn, cfg)
        if not cfg.enabled:
            conn.execute("DELETE FROM relations WHERE source = ? AND manual = 0", (SOURCE,))
            conn.commit()
        result = _payload(conn)
    finally:
        conn.close()
    if cfg.enabled:
        await sync_now(db_path, client_factory=_factory(request))  # saving is the user's "try again" after a refused login
        conn = connect(db_path)
        try:
            result = _payload(conn)
        finally:
            conn.close()
    return result


@router.post("/asus/test")
async def test_asus(request: Request, body: AsusBody) -> dict:
    """Try the connection with the form's values (a saved password is used when none is typed). Saves nothing."""
    conn = connect(request.app.state.db_path)
    try:
        cfg = _merge(load_config(conn), body)
    finally:
        conn.close()
    if not is_configured(cfg):
        raise HTTPException(status_code=422, detail="enter the router address, username and password")
    try:
        snap = await asyncio.to_thread(lambda: _factory(request)(cfg).snapshot())
    except AsusError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True, "nodes": len(snap["nodes"]), "clients": len(snap["clients"])}


@router.post("/asus/sync")
async def sync_asus(request: Request) -> dict:
    result = await sync_now(request.app.state.db_path, client_factory=_factory(request))
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
