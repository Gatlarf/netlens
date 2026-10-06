Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
After the asyncio.wait(..., return_when=FIRST_COMPLETED) call and cancelling the pending tasks, retrieve the result/exception of every task that finished or was cancelled (for t in tasks: try: t.result() except BaseException: pass, taking care not to swallow KeyboardInterrupt in the main task: catch (asyncio.CancelledError, Exception)), so that asyncio never logs 'Task exception was never retrieved'. Also await the cancelled tasks (asyncio.gather(*pending, return_exceptions=True)).

CURRENT FILE:
import asyncio
import json
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from fastapi.responses import Response

from app.auth import COOKIE_NAME, is_authorized, require_auth
from app.db import connect
from app.terminal.base import AuthFailed, ConnectFailed, HostKeyMismatch
from app.terminal.hostkeys import forget_fingerprint, get_fingerprint, remember_fingerprint
from app.terminal.policy import pick_port, target_allowed

MAX_SESSIONS = 5

router = APIRouter(prefix="/api", tags=["terminal"])


def _clamp_cols(cols: int) -> int:
    return max(10, min(500, cols))


def _clamp_rows(rows: int) -> int:
    return max(5, min(200, rows))


async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
    await websocket.send_json({"type": "error", "code": code, "message": message})
    await websocket.close(code=1008)


@router.websocket("/terminal/{device_id}/ws")
async def terminal_ws(
    websocket: WebSocket,
    device_id: int,
    proto: str = "ssh",
    port: Optional[int] = None,
) -> None:
    # 1. Origin check
    origin = websocket.headers.get("origin")
    if origin is not None:
        parsed = urlparse(origin)
        if parsed.netloc != websocket.headers.get("host"):
            await websocket.close(code=1008)
            return

    # Auth check
    token = websocket.app.state.settings.token
    cookie = websocket.cookies.get(COOKIE_NAME)
    authorization = websocket.headers.get("authorization")
    if not is_authorized(token, cookie, authorization):
        await websocket.close(code=1008)
        return

    # 2. Accept
    await websocket.accept()

    if websocket.app.state.terminal_sessions >= MAX_SESSIONS:
        await websocket.send_json({"type": "error", "code": "limit", "message": "too many terminal sessions"})
        await websocket.close(code=1008)
        return

    if proto not in ("ssh", "telnet"):
        await websocket.send_json({"type": "error", "code": "proto", "message": "invalid protocol"})
        await websocket.close(code=1008)
        return

    # 3. Device lookup and policy checks
    conn = connect(websocket.app.state.db_path)
    try:
        device = conn.execute("SELECT id, primary_ip FROM devices WHERE id = ?", (device_id,)).fetchone()
        if device is None:
            await websocket.send_json({"type": "error", "code": "device", "message": "device not found"})
            await websocket.close(code=1008)
            return

        primary_ip = device["primary_ip"]
        if not target_allowed(primary_ip, websocket.app.state.settings.ranges):
            await websocket.send_json({"type": "error", "code": "policy", "message": "target not allowed"})
            await websocket.close(code=1008)
            return

        open_ports = [
            (row["proto"], row["port"])
            for row in conn.execute(
                "SELECT proto, port FROM ports WHERE device_id = ? AND state LIKE 'open%'",
                (device_id,),
            ).fetchall()
        ]

        try:
            port = pick_port(proto, port, open_ports)
        except ValueError as exc:
            await websocket.send_json({"type": "error", "code": "port", "message": str(exc)})
            await websocket.close(code=1008)
            return

        # 4. Wait for auth message
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "error", "code": "auth_message", "message": "timeout waiting for auth message"})
            await websocket.close(code=1008)
            return
        except WebSocketDisconnect:
            return

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid auth message"})
            await websocket.close(code=1008)
            return

        if not isinstance(data, dict):
            await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid auth message"})
            await websocket.close(code=1008)
            return

        if data.get("type") != "auth":
            await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid message type"})
            await websocket.close(code=1008)
            return

        username = data.get("username", "")
        password = data.get("password")
        private_key = data.get("private_key")
        passphrase = data.get("passphrase")
        cols = data.get("cols", 80)
        rows = data.get("rows", 24)

        if proto == "ssh":
            if not username or len(username) > 128:
                await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid username"})
                await websocket.close(code=1008)
                return
            if password is not None and len(password) > 1024:
                await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid password"})
                await websocket.close(code=1008)
                return
            if private_key is not None and len(private_key) > 16384:
                await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid private key"})
                await websocket.close(code=1008)
                return
            if passphrase is not None and len(passphrase) > 1024:
                await websocket.send_json({"type": "error", "code": "auth_message", "message": "invalid passphrase"})
                await websocket.close(code=1008)
                return

        cols = _clamp_cols(cols)
        rows = _clamp_rows(rows)

        # 5. Create backend
        kwargs: dict = {"host": primary_ip, "port": port, "cols": cols, "rows": rows}
        if proto == "ssh":
            kwargs["username"] = username
            kwargs["password"] = password
            kwargs["private_key"] = private_key
            kwargs["passphrase"] = passphrase
            kwargs["known_fingerprint"] = get_fingerprint(conn, device_id)

        backend = websocket.app.state.terminal_backends[proto](**kwargs)

        try:
            await backend.connect()
        except HostKeyMismatch as exc:
            await websocket.send_json({"type": "hostkey_mismatch", "expected": exc.expected, "actual": exc.actual})
            await websocket.close(code=1008)
            return
        except AuthFailed:
            await websocket.send_json({"type": "error", "code": "auth", "message": "authentication failed"})
            await websocket.close(code=1008)
            return
        except ConnectFailed as exc:
            await websocket.send_json({"type": "error", "code": "connect", "message": str(exc)})
            await websocket.close(code=1008)
            return
        except Exception:
            await websocket.send_json({"type": "error", "code": "connect", "message": "connection failed"})
            await websocket.close(code=1008)
            return

        # 6. On success
        if proto == "ssh" and backend.new_key:
            remember_fingerprint(conn, device_id, backend.fingerprint)

        websocket.app.state.terminal_sessions += 1

        try:
            await websocket.send_json({
                "type": "status",
                "state": "connected",
                "proto": proto,
                "port": port,
                "fingerprint": backend.fingerprint,
                "new_key": backend.new_key,
            })

            # 7. Run two coroutines
            idle_timeout = getattr(websocket.app.state, "terminal_idle_timeout", 900.0)

            async def output_pump() -> None:
                while True:
                    data = await backend.read()
                    if not data:
                        break
                    await websocket.send_bytes(data)

            async def input_pump() -> None:
                while True:
                    try:
                        msg = await asyncio.wait_for(websocket.receive(), timeout=idle_timeout)
                    except asyncio.TimeoutError:
                        await websocket.send_json({"type": "closed", "reason": "idle timeout"})
                        return
                    if msg["type"] == "websocket.disconnect":
                        return
                    if msg.get("bytes") is not None:
                        await backend.write(msg["bytes"])
                    elif msg.get("text") is not None:
                        try:
                            control = json.loads(msg["text"])
                        except json.JSONDecodeError:
                            continue
                        if control.get("type") == "resize":
                            new_cols = _clamp_cols(control.get("cols", cols))
                            new_rows = _clamp_rows(control.get("rows", rows))
                            await backend.resize(new_cols, new_rows)
                        elif control.get("type") == "ping":
                            pass

            tasks = [
                asyncio.create_task(output_pump()),
                asyncio.create_task(input_pump()),
            ]

            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        finally:
            # 8. Cleanup
            try:
                await backend.close()
            except Exception:
                pass

            websocket.app.state.terminal_sessions -= 1

            try:
                await websocket.send_json({"type": "closed", "reason": "session ended"})
            except Exception:
                pass

            try:
                await websocket.close(code=1000)
            except Exception:
                pass

    finally:
        conn.close()


@router.delete("/devices/{device_id}/hostkey", dependencies=[Depends(require_auth)])
async def delete_hostkey(device_id: int, request: Request) -> Response:
    conn = connect(request.app.state.db_path)
    try:
        if forget_fingerprint(conn, device_id):
            return Response(status_code=204)
        else:
            raise HTTPException(status_code=404, detail="no stored host key")
    finally:
        conn.close()