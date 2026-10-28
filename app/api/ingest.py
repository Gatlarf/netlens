"""Agent ingest (Enterprise): settings, agents and certificates. Administrators only, and only from where the terminal may be used (the local network by default),
because this part hands out the means to send data into Netlens. The listeners themselves are in app/ingest/server.py."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app import licence
from app.api.devices import get_conn
from app.auth import require_admin
from app.ingest import core, pki
from app.terminal.access import ensure_allowed

router = APIRouter(prefix="/api", tags=["ingest"])


def _control(request: Request):
    control = getattr(request.app.state, "ingest", None)
    if control is None:                                   # the background jobs are off (a test, a read-only copy): the settings can still be edited, nothing listens
        from app.ingest import server

        control = request.app.state.ingest = server.Control(request.app.state.db_path)
    return control


def _need_licence(conn) -> None:
    if not licence.allows(conn, "agents"):
        raise HTTPException(status_code=402, detail="receiving data from locked-down hosts is part of the Enterprise edition (or the free trial): Settings → Licence")


def _doc(conn, control) -> dict[str, Any]:
    policy = core.get_policy(conn)
    server = core._load(conn, core.SERVER_KEY)
    cert_info: dict[str, Any] | None = None
    if server:
        try:
            c = pki.load_cert(server["cert"].split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----")
            cert_info = {"source": server.get("source"), "names": server.get("names", []), "expires": c.not_valid_after_utc.strftime(core.STAMP)}
        except pki.PkiError:
            cert_info = None
    ca = core.ca_info(conn) if policy["enabled"] or core._load(conn, core.CA_KEY) else None
    byo = core.byo_bundle(conn)
    return {
        "allowed": licence.allows(conn, "agents"), "policy": policy, "window_open": core.window_open(policy), "status": control.status(),
        "server_certificate": cert_info, "ca": ca, "ca_fingerprint": ca["fingerprint"] if ca else None,
        "own_ca": len(pki.parse_bundle(byo)) if byo else 0, "agents": core.list_agents(conn), "problems": core.problems(conn),
    }


def _fail(exc: Exception) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/agent-status")
def agent_status(conn=Depends(get_conn)) -> dict[str, Any]:
    """Read-only overview for viewers, reports and assistants: which hosts push their readings through an agent and whether they are healthy."""
    return core.status_summary(conn)


@router.get("/ingest")
def get_ingest(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return _doc(conn, _control(request))


@router.put("/ingest", dependencies=[Depends(ensure_allowed)])
async def put_ingest(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        core.save_policy(conn, body)
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.post("/ingest/window", dependencies=[Depends(ensure_allowed)])
async def open_window(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        core.open_window(conn, body.get("minutes", core.ENROL_WINDOW_DEFAULT))
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.delete("/ingest/window", dependencies=[Depends(ensure_allowed)])
async def close_window(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    core.close_window(conn)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.get("/ingest/ca.pem", dependencies=[Depends(ensure_allowed)])
def download_ca(request: Request, conn=Depends(get_conn)) -> PlainTextResponse:
    """The certificate the collectors trust to recognise Netlens. Public data, but handed out to administrators only so it is not a way to find the listener."""
    require_admin(request)
    _need_licence(conn)
    return PlainTextResponse(core.ca_certificate(conn), headers={"Content-Disposition": 'attachment; filename="netlens-ingest-ca.pem"', "Cache-Control": "no-store"})


@router.post("/ingest/ca/rotate", dependencies=[Depends(ensure_allowed)])
async def rotate_ca(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        core.rotate_ca(conn)
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.post("/ingest/ca/finish", dependencies=[Depends(ensure_allowed)])
async def finish_rotation(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        core.finish_rotation(conn, force=body.get("force") is True)
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.post("/ingest/ca/cancel", dependencies=[Depends(ensure_allowed)])
async def cancel_rotation(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        core.cancel_rotation(conn)
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.put("/ingest/own-ca", dependencies=[Depends(ensure_allowed)])
async def put_own_ca(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        core.save_byo(conn, str(body.get("pem", "")))
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


@router.put("/ingest/server-certificate", dependencies=[Depends(ensure_allowed)])
async def put_server_certificate(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        if body.get("use_generated"):
            core.use_generated_server(conn)
        else:
            core.upload_server(conn, str(body.get("certificate", "")), str(body.get("key", "")))
    except core.IngestError as exc:
        raise _fail(exc)
    control = _control(request)
    await control.apply()
    return _doc(conn, control)


def _token_reply(agent: dict[str, Any] | None, token: str | None, conn, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = core.get_policy(conn)
    out = {"agent": agent, "token": token, "token_hours": core.TOKEN_HOURS, "server": (policy["server_names"] or [""])[0], "port": policy["port"], "enrol_port": policy["enrol_port"]}
    out.update(extra or {})
    return out


@router.post("/ingest/agents", dependencies=[Depends(ensure_allowed)])
def create_agent(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        agent, token = core.create_agent(conn, body.get("name", ""), body.get("targets"), str(body.get("identity") or ""), body.get("interval_s", core.DEFAULT_INTERVAL))
    except core.IngestError as exc:
        raise _fail(exc)
    return _token_reply(agent, token, conn)


@router.put("/ingest/agents/{agent_id}", dependencies=[Depends(ensure_allowed)])
def update_agent(agent_id: int, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        return core.update_agent(conn, agent_id, body)
    except core.IngestError as exc:
        raise _fail(exc)


@router.post("/ingest/agents/{agent_id}/token", dependencies=[Depends(ensure_allowed)])
def new_token(agent_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _need_licence(conn)
    try:
        token = core.new_token(conn, agent_id)
    except core.IngestError as exc:
        raise _fail(exc)
    return _token_reply(core.get_agent(conn, agent_id), token, conn)


@router.post("/ingest/agents/{agent_id}/revoke", dependencies=[Depends(ensure_allowed)])
def revoke(agent_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        core.revoke(conn, agent_id)
    except core.IngestError as exc:
        raise _fail(exc)
    return core.get_agent(conn, agent_id)


@router.post("/ingest/agents/{agent_id}/reinstate", dependencies=[Depends(ensure_allowed)])
def reinstate(agent_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        core.reinstate(conn, agent_id)
    except core.IngestError as exc:
        raise _fail(exc)
    return core.get_agent(conn, agent_id)


@router.delete("/ingest/agents/{agent_id}", dependencies=[Depends(ensure_allowed)])
def delete_agent(agent_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        core.delete_agent(conn, agent_id)
    except core.IngestError as exc:
        raise _fail(exc)
    return {"deleted": agent_id}
