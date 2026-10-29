"""Remote access: the devices that can be reached by SSH, Telnet, RDP or VNC, and RDP/VNC sessions through guacd.

SSH and Telnet sessions are the existing web terminal (app/api/terminal.py). RDP and VNC need Apache Guacamole's guacd, a small
helper service in its own container (NETLENS_GUACD, default 127.0.0.1:4822); see app/remote/guac.py. Access follows the terminal's rules:
administrators only, switched off by NETLENS_TERMINAL=off, direct local connections only unless NETLENS_TERMINAL_REMOTE widens that,
and only devices of the inventory with a private address and that port seen open.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from pydantic import BaseModel

from app import audit, credstore
from app.auth import client_ip, identify, require_admin
from app.db import connect, get_setting, set_setting
from app.remote import guac
from app.terminal.access import classify
from app.terminal.policy import target_allowed

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["remote"])
MAX_SESSIONS = 5
TICKET_SECONDS = 30
CREDENTIALS_KEY = "remote.credentials"
GRAPHICAL = ("rdp", "vnc")
GUAC_PROTOCOL = {"rdp": "rdp", "vnc": "vnc"}
DEFAULT_PORT = {"ssh": 22, "telnet": 23, "rdp": 3389, "vnc": 5900}
LABEL = {"ssh": "SSH", "telnet": "Telnet", "rdp": "Remote Desktop (RDP)", "vnc": "VNC"}


# ---------------------------------------------------------------- what a device offers
def services_of(ports: list[dict]) -> list[dict]:
    """The remote access services among a device's open TCP ports: [{proto, port}], one per protocol."""
    found: dict[str, int] = {}
    for p in ports:
        if p.get("proto") != "tcp" or not str(p.get("state") or "").startswith("open"):
            continue
        port, name = int(p["port"]), (p.get("service") or "").lower()
        kinds = []
        if port == 22 or name == "ssh":
            kinds.append("ssh")
        if port == 23 or name == "telnet":
            kinds.append("telnet")
        if port == 3389 or name in ("ms-wbt-server", "rdp"):
            kinds.append("rdp")
        if 5900 <= port <= 5909 or "vnc" in name:
            kinds.append("vnc")
        for kind in kinds:
            if kind not in found or port < found[kind]:
                found[kind] = port
    return [{"proto": k, "port": found[k], "label": LABEL[k]} for k in ("ssh", "telnet", "rdp", "vnc") if k in found]


def guacd_address(request_or_app) -> tuple[str, int] | None:
    import os

    value = os.environ.get("NETLENS_GUACD", "127.0.0.1:4822").strip()
    if not value or value.lower() == "off":
        return None
    host, _, port = value.rpartition(":")
    if not host:
        host, port = value, "4822"
    try:
        return host, int(port)
    except ValueError:
        return None


async def helper_status() -> dict:
    address = guacd_address(None)
    if address is None:
        return {"configured": False, "address": "", "reachable": False, "error": "switched off (NETLENS_GUACD)"}
    text = f"{address[0]}:{address[1]}"
    try:
        conn = await guac.Connection.open(address[0], address[1], timeout=1.5)
        conn.close()
        return {"configured": True, "address": text, "reachable": True, "error": None}
    except asyncio.TimeoutError:
        return {"configured": True, "address": text, "reachable": False, "error": "no answer (timed out)"}
    except OSError as exc:
        reason = "the name is not known (is the guacd container running on the same Docker network?)" if "Name or service" in str(exc) or "nodename" in str(exc) else "connection refused"
        return {"configured": True, "address": text, "reachable": False, "error": reason}


def _gate(request: Request) -> tuple[bool, str]:
    settings = request.app.state.settings
    if settings.demo:
        return False, "Remote access is switched off in the demo."
    if not settings.terminal_enabled:
        return False, "Remote access is switched off (NETLENS_TERMINAL=off)."
    allowed, why = classify(request, settings.terminal_remote)
    if not allowed:
        return False, f"Remote access is not available on this connection: {why}."
    return True, why


@router.get("/remote")
async def get_remote(request: Request) -> dict:
    require_admin(request)
    available, why = _gate(request)
    conn = connect(request.app.state.db_path)
    try:
        ports: dict[int, list[dict]] = {}
        for r in conn.execute("SELECT device_id, proto, port, state, service FROM ports WHERE state LIKE 'open%'").fetchall():
            ports.setdefault(r["device_id"], []).append(dict(r))
        devices = []
        for d in conn.execute(
            "SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip, online, device_type FROM devices ORDER BY online DESC, LOWER(COALESCE(custom_name, hostname, primary_ip))"
        ).fetchall():
            services = services_of(ports.get(d["id"], []))
            if services and target_allowed(d["primary_ip"], request.app.state.settings.ranges):
                devices.append({"id": d["id"], "name": d["name"], "ip": d["primary_ip"], "online": bool(d["online"]), "type": d["device_type"], "services": services})
        saved = _saved(conn)
        who = _username(request)
        for d in devices:
            for s in d["services"]:
                bound = _binding(saved, who, d["id"], s["proto"])
                entry = credstore.peek(conn, who, bound["credential_id"]) if bound else None
                s["saved"] = {"username": entry.get("username", ""), "domain": entry.get("domain", ""), "name": entry["name"]} if entry else None
    finally:
        conn.close()
    return {"available": available, "why": why, "helper": await helper_status(), "devices": devices}


# ---------------------------------------------------------------- saved credentials (encrypted at rest: see app/vault.py)
def _saved(conn) -> dict:
    """device:proto (or user|device:proto) -> {"credential_id"}. Logins an older version kept here are moved into the credential store the first time they are read."""
    try:
        data = json.loads(get_setting(conn, CREDENTIALS_KEY) or "{}")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    moved = False
    for key, entry in list(data.items()):
        if isinstance(entry, dict) and "credential_id" not in entry and (entry.get("password") or entry.get("username")):
            device_id, _, proto = key.rpartition(":")
            row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS name FROM devices WHERE id = ?", (device_id,)).fetchone()
            try:
                cred_id = credstore.adopt(conn, f"{proto.upper()} {row['name'] if row else device_id}", "login",
                                          {"username": entry.get("username", ""), "password": entry.get("password") or "-", "domain": entry.get("domain", "")}, f"moved from the saved {proto.upper()} logins")
            except credstore.CredentialError:
                continue
            data[key] = {"credential_id": cred_id}
            moved = True
    if moved:
        set_setting(conn, CREDENTIALS_KEY, json.dumps(data))
        conn.commit()
    return data


def _username(request) -> str:
    principal = getattr(request.state, "user", None) or identify(request)
    return getattr(principal, "username", "") or ""


def _binding(saved: dict, user: str, device_id, proto: str) -> dict | None:
    return saved.get(f"{user}|{device_id}:{proto}") or saved.get(f"{device_id}:{proto}")


def _save(conn, data: dict) -> None:
    set_setting(conn, CREDENTIALS_KEY, json.dumps(data))


@router.delete("/remote/{device_id}/saved/{proto}")
def forget_credentials(request: Request, device_id: int, proto: str) -> dict:
    require_admin(request)
    conn = connect(request.app.state.db_path)
    try:
        data = _saved(conn)
        who = _username(request)
        key = f"{who}|{device_id}:{proto}" if f"{who}|{device_id}:{proto}" in data else f"{device_id}:{proto}"
        if data.pop(key, None) is None:
            raise HTTPException(status_code=404, detail="nothing saved")
        _save(conn, data)                         # only the link to this device goes; the login stays in the credential store (Settings → Credentials)
        return {"forgotten": True}
    finally:
        conn.close()


# ---------------------------------------------------------------- a session: a ticket first, then the WebSocket
class SessionBody(BaseModel):
    proto: str
    port: Optional[int] = None
    username: str = ""
    password: str = ""
    domain: str = ""
    width: int = 1280
    height: int = 720
    dpi: int = 96
    timezone: str = "UTC"
    use_saved: bool = False
    credential_id: str = ""
    remember: bool = False
    reason: str = ""


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


@router.post("/remote/{device_id}/session")
async def open_session(request: Request, device_id: int, body: SessionBody) -> dict:
    """Check everything and hand out a one-time ticket for the WebSocket, so the password never appears in an address."""
    require_admin(request)
    available, why = _gate(request)
    if not available:
        raise HTTPException(status_code=403, detail=why)
    if body.proto not in GRAPHICAL:
        raise HTTPException(status_code=422, detail="use the terminal for SSH and Telnet")
    helper = await helper_status()
    if not helper["reachable"]:
        raise HTTPException(status_code=503, detail=f"the remote desktop helper (guacd) cannot be reached: {helper['error']}")
    conn = connect(request.app.state.db_path)
    try:
        device = conn.execute("SELECT id, primary_ip, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices WHERE id = ?", (device_id,)).fetchone()
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        if not target_allowed(device["primary_ip"], request.app.state.settings.ranges):
            raise HTTPException(status_code=403, detail="target not allowed")
        open_ports = [dict(r) for r in conn.execute("SELECT proto, port, state, service FROM ports WHERE device_id = ? AND state LIKE 'open%'", (device_id,)).fetchall()]
        port = body.port or next((s["port"] for s in services_of(open_ports) if s["proto"] == body.proto), None)
        if port is None or not any(p["proto"] == "tcp" and int(p["port"]) == port for p in open_ports):
            raise HTTPException(status_code=422, detail="that port is not open on this device")
        creds = {"username": body.username, "password": body.password, "domain": body.domain}
        who = _username(request)
        if body.credential_id or body.use_saved:
            try:
                bound = None if body.credential_id else _binding(_saved(conn), who, device_id, body.proto)
                cred_id = body.credential_id or (bound or {}).get("credential_id")
                creds = await credstore.resolve_async(conn, who, cred_id, f"remote {body.proto.upper()} to {device['name']}", body.reason, device["name"]) if cred_id else None
            except credstore.CredentialError as exc:
                if str(exc) != "no such login":
                    raise HTTPException(status_code=403, detail=str(exc))                # the PAM said no, or wants a reason: say so
                creds = None
            if not creds:
                raise HTTPException(status_code=404, detail="no such stored login for this device")
            audit.record_by(conn, getattr(request.state, "user", None) or identify(request), client_ip(request), "POST", request.url.path, 200,
                            f"Opened {body.proto.upper()} to {device['name']} with the stored login \"{creds['name']}\"")
    finally:
        conn.close()
    for key, limit in (("username", 256), ("password", 1024), ("domain", 256)):
        if len(creds.get(key, "")) > limit:
            raise HTTPException(status_code=422, detail=f"{key} is too long")
    tickets = getattr(request.app.state, "remote_tickets", None)
    if tickets is None:
        tickets = request.app.state.remote_tickets = {}
    now = time.monotonic()
    for old in [t for t, v in tickets.items() if v["expires"] < now]:
        tickets.pop(old, None)
    ticket = secrets.token_urlsafe(24)
    tickets[ticket] = {
        "device_id": device_id, "proto": body.proto, "port": port, "ip": device["primary_ip"], "name": device["name"], "creds": creds,
        "width": _clamp(body.width, 320, 4096), "height": _clamp(body.height, 200, 2304), "dpi": _clamp(body.dpi, 48, 384),
        "timezone": body.timezone[:64] or "UTC", "remember": bool(body.remember and not body.use_saved and not body.credential_id), "expires": now + TICKET_SECONDS,
        "user": (identify(request) or None) and identify(request).username,
    }
    return {"ticket": ticket, "port": port}


def _params(proto: str, ip: str, port: int, creds: dict) -> dict[str, str]:
    common = {"hostname": ip, "port": str(port), "password": creds.get("password", ""), "username": creds.get("username", ""),
              "disable-copy": "false", "disable-paste": "false", "client-name": "Netlens"}
    if proto == "rdp":
        return {**common, "domain": creds.get("domain", ""), "security": "any", "ignore-cert": "true", "resize-method": "display-update",
                "disable-audio": "true", "enable-audio-input": "false", "enable-drive": "false", "enable-printing": "false",
                "enable-wallpaper": "false", "enable-font-smoothing": "true"}
    return {**common, "read-only": "false", "cursor": "remote"}


async def _error(websocket: WebSocket, message: str, status: str = "512") -> None:
    try:
        await websocket.send_text(guac.encode("error", message, status))
        await websocket.close(code=1000)
    except Exception:  # noqa: BLE001
        pass


@router.websocket("/remote/ws")
async def remote_ws(websocket: WebSocket, ticket: str = "") -> None:
    origin = websocket.headers.get("origin")
    if origin is not None and urlparse(origin).netloc != websocket.headers.get("host"):
        await websocket.close(code=1008)
        return
    principal = identify(websocket)
    if principal is None or not principal.is_admin:
        await websocket.close(code=1008)
        return
    settings = websocket.app.state.settings
    allowed, _why = classify(websocket, settings.terminal_remote)
    if not settings.terminal_enabled or settings.demo or not allowed:
        await websocket.close(code=1008)
        return
    from fastapi import HTTPException

    from app import stepup

    try:
        stepup.check(websocket, principal, "WS", websocket.url.path)
    except HTTPException:                                                    # the ticket was made by a privileged request; this is the second look
        await websocket.close(code=1008)
        return
    await websocket.accept(subprotocol="guacamole" if "guacamole" in (websocket.headers.get("sec-websocket-protocol") or "") else None)
    session = getattr(websocket.app.state, "remote_tickets", {}).pop(ticket, None)
    if session is None or session["expires"] < time.monotonic():
        await _error(websocket, "This connection request has expired. Press Connect again.", "769")
        return
    if (session.get("user") or "") != (getattr(principal, "username", "") or ""):          # a ticket is for the person who asked for it
        await _error(websocket, "This connection request was made by someone else.", "769")
        return
    if websocket.app.state.terminal_sessions >= MAX_SESSIONS:
        await _error(websocket, "Too many remote sessions are open.", "513")
        return
    address = guacd_address(websocket.app)
    if address is None:
        await _error(websocket, "The remote desktop helper is switched off.")
        return
    websocket.app.state.terminal_sessions += 1
    conn = None
    try:
        try:
            conn = await guac.Connection.open(address[0], address[1])
            session_id = await guac.handshake(conn, GUAC_PROTOCOL[session["proto"]], _params(session["proto"], session["ip"], session["port"], session["creds"]),
                                              session["width"], session["height"], session["dpi"], session["timezone"])
        except (OSError, asyncio.TimeoutError, guac.ProtocolError) as exc:
            log.info("remote session to %s failed: %s", session["ip"], exc)
            await _error(websocket, f"Could not connect: {exc}" if str(exc) else "Could not connect", "519")
            return
        log.info("remote session opened: %s -> %s %s:%s", session["user"], session["proto"], session["ip"], session["port"])
        if session["remember"]:
            db = connect(websocket.app.state.db_path)
            try:
                data = _saved(db)
                who = session["user"] or ""
                label = f"{session['proto'].upper()} {session['name']}"
                try:
                    made = credstore.create(db, who, label, "login", {"username": session["creds"].get("username", ""), "password": session["creds"].get("password") or "-", "domain": session["creds"].get("domain", "")})
                except credstore.CredentialError:
                    made = None
                if made:
                    data[f"{who}|{session['device_id']}:{session['proto']}"] = {"credential_id": made["id"]}
                    _save(db, data)
                    audit.record(db, who, "admin", "", "POST", "/api/remote/ws", 200, f"Stored the login \"{made['name']}\" in the credential store (remembered from a remote session)")
            finally:
                db.close()
        session["creds"] = None
        await websocket.send_text(guac.tunnel_ready(session_id))
        await _relay(websocket, conn, getattr(websocket.app.state, "terminal_idle_timeout", 900.0))
    finally:
        websocket.app.state.terminal_sessions -= 1
        if conn is not None:
            conn.close()
        try:
            await websocket.close(code=1000)
        except Exception:  # noqa: BLE001
            pass


async def _relay(websocket: WebSocket, conn: "guac.Connection", idle_timeout: float) -> None:
    async def to_browser() -> None:
        while True:
            batch = await conn.read()
            if not batch:
                return
            await websocket.send_text("".join(guac.encode(op, *args) for op, args in batch))

    async def to_guacd() -> None:
        parser = guac.Parser()
        last_input = time.monotonic()
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive(), timeout=30.0)
            except asyncio.TimeoutError:
                if time.monotonic() - last_input > idle_timeout:
                    await websocket.send_text(guac.encode("error", "Disconnected: no activity for a while.", "520"))
                    return
                continue
            if msg["type"] == "websocket.disconnect":
                return
            text = msg.get("text")
            if text is None:
                continue
            for op, args in parser.feed(text):
                if op == guac.INTERNAL:
                    if args and args[0] == "ping" and len(args) > 1:
                        await websocket.send_text(guac.encode(guac.INTERNAL, "ping", args[1]))
                    continue
                last_input = time.monotonic()
                await conn.send(op, *args)

    tasks = [asyncio.create_task(to_browser()), asyncio.create_task(to_guacd())]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    for task in done:
        try:
            task.result()
        except Exception:  # noqa: BLE001
            pass
