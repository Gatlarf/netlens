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

## app/api/terminal.py
15:MAX_SESSIONS = 5
20:def _clamp_cols(cols: int) -> int:
24:def _clamp_rows(rows: int) -> int:
28:async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
34:async def terminal_ws(
35:    websocket: WebSocket,
36:    device_id: int,
37:    proto: str = "ssh",
38:    port: Optional[int] = None,
256:async def delete_hostkey(device_id: int, request: Request) -> Response:

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

TASK:
Create tests/test_api_terminal.py with pytest and fastapi.testclient.TestClient (websocket_connect) for app/api/terminal.py. Setup: settings = app.config.load_settings({"NETLENS_TOKEN": "t"}); app = app.main.create_app(settings, db_path=tmp_path/"t.db"); replace app.state.terminal_backends = {"ssh": FakeFactory, "telnet": FakeFactory}. Seed BEFORE starting the client with app.db.connect + init_db: save_scan_results(conn, parse_nmap_xml(Path(__file__).parent.joinpath("fixtures","deep.xml").read_text(encoding="utf-8")), "deep") (from app.scanner.store and app.scanner.nmap_parser). Devices: id 1 = 192.168.1.1 (ssh 22 open), id 2 = 192.168.1.20 (ssh 22 open), id 3 = 192.168.1.30 (NO port 22 or 23 open), id 4 = 192.168.1.50 (only 8080). Also create a device with a public IP: app.db.get_or_create_device(conn, "aa:bb:cc:dd:ee:99", "8.8.8.8") plus an open tcp port 22 inserted with conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')", (id,)) then conn.commit(). Use `with TestClient(app) as client:`. Always pass headers={"Authorization": "Bearer t"} explicitly to client.websocket_connect(url, headers=...).
FakeBackend(TerminalBackend subclass from app.terminal.base): __init__(self, **kwargs) records kwargs in a module-level list `created`; has fingerprint = "SHA256:fake", new_key = True; connect(): raises the exception stored in a module-level variable `connect_error` when set; read(): returns the next item of an asyncio.Queue (None means EOF -> return b""), initially it queues b"welcome\r\n"; write(data): queues b"echo:" + data; resize(c, r): records in module-level list `resizes`; close(): marks closed. FakeFactory = FakeBackend (a callable accepting keyword args). Reset module state in an autouse fixture.
Tests: (1) unauthenticated websocket (headers={"Authorization": "Bearer wrong"}) is rejected: pytest.raises(WebSocketDisconnect) on websocket_connect or on first receive; (2) a wrong Origin header ("https://evil.example") with valid auth is rejected; a matching origin ("http://testserver") is accepted; (3) happy path ssh to device 1: send_json {"type":"auth","username":"bob","password":"pw","cols":100,"rows":30}; receive_json is {"type":"status","state":"connected",...} with fingerprint "SHA256:fake" and new_key true; receive_bytes == b"welcome\r\n"; send_bytes(b"ls\n"); receive_bytes == b"echo:ls\n"; the created backend kwargs contain host "192.168.1.1", port 22, username "bob", password "pw", cols 100, rows 30, known_fingerprint None; (4) after that session the fingerprint "SHA256:fake" is stored (app.terminal.hostkeys.get_fingerprint via a fresh connection) and a second connection to device 1 passes known_fingerprint "SHA256:fake" to the backend; (5) resize: send_json {"type":"resize","cols":120,"rows":40} then a write round trip; resizes contains (120, 40); out-of-range sizes are clamped (cols 9999 -> 500); (6) telnet proto on a device without port 23 -> error message code "port"; (7) device 3 (no ssh) -> {"type":"error","code":"port",...}; (8) unknown device 999 -> code "device"; (9) public-IP device -> code "policy"; (10) invalid proto "rdp" -> code "proto"; (11) auth message missing username for ssh -> code "auth_message"; (12) connect_error = AuthFailed("authentication failed") -> error code "auth" and the response text never contains the password; ConnectFailed("down") -> code "connect" message "down"; HostKeyMismatch("SHA256:a","SHA256:b") -> {"type":"hostkey_mismatch","expected":"SHA256:a","actual":"SHA256:b"}; (13) DELETE /api/devices/1/hostkey with auth returns 204 after a session stored a key and 404 afterwards, and 401 without credentials; (14) with NETLENS_TERMINAL=off (load_settings({"NETLENS_TOKEN":"t","NETLENS_TERMINAL":"off"})) GET/DELETE routes return 404 and the websocket cannot connect; (15) idle timeout: app.state.terminal_idle_timeout = 0.3, after connecting wait: receive_json() eventually yields {"type":"closed","reason":"idle timeout"}; (16) session limit: set app.state.terminal_sessions = 5 before connecting -> error code "limit". Keep helper functions small. HARD LIMIT: under 330 lines, each test written once.
