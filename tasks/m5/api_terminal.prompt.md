INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/auth.py
10:COOKIE_NAME = "netlens_session"
13:def session_value(token: str) -> str:
17:def is_authorized(token: str, cookie: Optional[str], authorization: Optional[str]) -> bool:
37:class LoginLimiter:
38:    def __init__(self, max_failures: int = 5, window: float = 60.0, clock=time.monotonic):
44:    def allowed(self, key: str) -> bool:
52:    def record_failure(self, key: str) -> None:
63:    def reset(self, key: str) -> None:
67:def require_auth(request: Request) -> None:

## app/terminal/base.py
6:class TerminalError(Exception):
10:class AuthFailed(TerminalError):
14:class ConnectFailed(TerminalError):
18:class HostKeyMismatch(TerminalError):
21:    def __init__(self, expected: str, actual: str) -> None:
27:class TerminalBackend:
30:    fingerprint: str | None = None
31:    new_key: bool = False
33:    async def connect(self) -> None:
36:    async def read(self) -> bytes:
39:    async def write(self, data: bytes) -> None:
42:    async def resize(self, cols: int, rows: int) -> None:
45:    async def close(self) -> None:

## app/terminal/policy.py
7:def target_allowed(ip: str, ranges: Iterable[str]) -> bool:
44:def pick_port(
45:    proto: str,
46:    requested: int | None,
47:    open_ports: list[tuple[str, int]],

## app/terminal/hostkeys.py
9:def get_fingerprint(conn: sqlite3.Connection, device_id: int) -> Optional[str]:
20:def remember_fingerprint(
21:    conn: sqlite3.Connection,
22:    device_id: int,
23:    fingerprint: str,
24:    now: Optional[str] = None,
35:def forget_fingerprint(conn: sqlite3.Connection, device_id: int) -> bool:
45:def check_fingerprint(
46:    conn: sqlite3.Connection,
47:    device_id: int,
48:    fingerprint: str,

TASK:
Create app/api/terminal.py (FastAPI WebSocket + REST). Existing pieces you use (exact names):
- app.auth: COOKIE_NAME, is_authorized(token, cookie, authorization) -> bool, require_auth (FastAPI dependency for HTTP routes).
- app.db: connect(path) -> sqlite3.Connection (row_factory Row). Tables: devices(id, primary_ip, ...), ports(device_id, proto, port, state, service, ...).
- app.terminal.policy: target_allowed(ip, ranges) -> bool; pick_port(proto, requested, open_ports: list[tuple[str,int]]) -> int (raises ValueError with a message).
- app.terminal.hostkeys: get_fingerprint(conn, device_id) -> str|None; remember_fingerprint(conn, device_id, fingerprint); forget_fingerprint(conn, device_id) -> bool.
- app.terminal.base: TerminalBackend (async connect/read/write/resize/close; attributes fingerprint, new_key), AuthFailed, ConnectFailed, HostKeyMismatch(expected, actual attributes).
- app.state: settings (Settings: .token, .ranges tuple of CIDR str), db_path (str), terminal_backends (dict {"ssh": factory, "telnet": factory}; each factory is called with keyword arguments and returns a TerminalBackend), terminal_sessions (int counter), optional terminal_idle_timeout (float seconds; use getattr(app.state, "terminal_idle_timeout", 900.0)).
router = APIRouter(prefix="/api", tags=["terminal"]). MAX_SESSIONS = 5.

WebSocket route @router.websocket("/terminal/{device_id}/ws") with query params proto: str = "ssh" and port: int | None = None. Protocol (binary frames = raw terminal bytes; text frames = JSON control messages):
1. Before accepting: Origin check - origin = websocket.headers.get("origin"); if origin is present and urlparse(origin).netloc != websocket.headers.get("host"): await websocket.close(code=1008); return. Auth - if not is_authorized(websocket.app.state.settings.token, websocket.cookies.get(COOKIE_NAME), websocket.headers.get("authorization")): await websocket.close(code=1008); return.
2. await websocket.accept(). If app.state.terminal_sessions >= MAX_SESSIONS send_json {"type":"error","code":"limit","message":"too many terminal sessions"} and close 1008. Validate proto in ("ssh","telnet") else error code "proto".
3. Look up the device row (error code "device", message "device not found"); require target_allowed(primary_ip, settings.ranges) (error code "policy", "target not allowed"); open ports = [(proto, port) for ports rows with state LIKE 'open%']; port = pick_port(proto, port, open_ports) (ValueError -> error code "port" with the message). Close the DB connection when done with these lookups. Errors are sent as {"type":"error","code":...,"message":...} then websocket.close(code=1008).
4. Wait up to 30 s (asyncio.wait_for) for the first text message, JSON {"type":"auth","username":str,"password":str|null,"private_key":str|null,"passphrase":str|null,"cols":int,"rows":int}. Validate: type must be "auth"; username <= 128 chars (required for ssh), password <= 1024, private_key <= 16384, passphrase <= 1024; cols 10-500 and rows 5-200 (default 80x24). Invalid -> error code "auth_message". For telnet only cols/rows are used.
5. Create the backend: kwargs for ssh: host=<primary_ip>, port=port, username, password, private_key, passphrase, cols, rows, known_fingerprint=get_fingerprint(conn, device_id) (open a short-lived connection); for telnet: host, port, cols, rows. backend = websocket.app.state.terminal_backends[proto](**kwargs). await backend.connect(). Exceptions: HostKeyMismatch -> send {"type":"hostkey_mismatch","expected":exc.expected,"actual":exc.actual} and close 1008; AuthFailed -> {"type":"error","code":"auth","message":"authentication failed"}; ConnectFailed -> {"type":"error","code":"connect","message":str(exc)}; any other Exception -> code "connect", message "connection failed". Always close the websocket after an error. NEVER log or echo passwords/keys.
6. On success: if proto == "ssh" and backend.new_key: remember_fingerprint(conn, device_id, backend.fingerprint). Increment app.state.terminal_sessions (decrement in a finally). Send {"type":"status","state":"connected","proto":proto,"port":port,"fingerprint":backend.fingerprint,"new_key":backend.new_key}.
7. Run two coroutines with asyncio.wait(..., return_when=FIRST_COMPLETED) and cancel the other afterwards: (a) output pump: loop data = await backend.read(); if not data break; await websocket.send_bytes(data). (b) input pump: loop msg = await asyncio.wait_for(websocket.receive(), timeout=idle_timeout); on asyncio.TimeoutError send {"type":"closed","reason":"idle timeout"} and stop; if msg["type"] == "websocket.disconnect" stop; if msg.get("bytes") is not None: await backend.write(bytes); elif msg.get("text") is not None: parse JSON (ignore invalid); {"type":"resize","cols","rows"} -> clamp (cols 10-500, rows 5-200) and await backend.resize(cols, rows); {"type":"ping"} -> ignore.
8. finally: await backend.close() (swallow errors); if the websocket is still open send {"type":"closed","reason":"session ended"} (ignore errors) and close(code=1000).

REST route DELETE /devices/{device_id}/hostkey with dependencies=[Depends(require_auth)] (use the route decorator's dependencies argument): opens app.db.connect(request.app.state.db_path), forget_fingerprint; True -> Response(status_code=204); False -> HTTPException 404 detail "no stored host key".
