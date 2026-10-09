from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import netchecks
from app.db import connect

router = APIRouter(prefix="/api", tags=["netchecks"])


class NetchecksBody(BaseModel):
    dhcp_enabled: bool | None = None
    dhcp_hours: int | None = None


class TrustBody(BaseModel):
    trusted: bool = True


def _view(conn) -> dict:
    return {
        "settings": netchecks.get_settings(conn), "intervals": list(netchecks.INTERVALS),
        "last": netchecks.get_last(conn), "servers": netchecks.list_servers(conn), "gateway": netchecks.get_gateway(conn),
    }


@router.get("/netchecks")
def get_netchecks(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _view(conn)
    finally:
        conn.close()


@router.put("/netchecks")
def put_netchecks(request: Request, body: NetchecksBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            netchecks.set_settings(conn, body.dhcp_enabled, body.dhcp_hours)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return _view(conn)
    finally:
        conn.close()


@router.post("/netchecks/dhcp/run")
async def run_dhcp(request: Request) -> dict:
    """Look for DHCP servers right now (about ten seconds)."""
    conn = connect(request.app.state.db_path)
    try:
        result = await netchecks.check_dhcp(conn, getattr(request.app.state, "action_runner", None))
        if result["rogue"]:
            from app.notify.channels import process_channels
            from app.notify.service import process_notifications

            await process_channels(request.app.state.db_path)
            await process_notifications(request.app.state.db_path)
        if not result["ok"]:
            raise HTTPException(status_code=502, detail=result["error"])
        return {**_view(conn), "result": result}
    finally:
        conn.close()


@router.put("/netchecks/dhcp/{ip}")
def trust_dhcp(request: Request, ip: str, body: TrustBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            netchecks.set_trusted(conn, ip, body.trusted)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such DHCP server")
        return _view(conn)
    finally:
        conn.close()


@router.delete("/netchecks/dhcp/{ip}")
def forget_dhcp(request: Request, ip: str) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            netchecks.forget_server(conn, ip)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such DHCP server")
        return _view(conn)
    finally:
        conn.close()
