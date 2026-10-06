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

TASK:
Create tests/test_api_terminal_errors.py with pytest and fastapi.testclient.TestClient. Imports: from tests.fake_terminal import FakeBackend; from fastapi import WebSocketDisconnect; app.config.load_settings; app.main.create_app; app.db: connect, init_db, get_or_create_device; app.scanner.store.save_scan_results; app.scanner.nmap_parser.parse_nmap_xml; app.terminal.base: AuthFailed, ConnectFailed, HostKeyMismatch.
Harness (write exactly this, adapt syntax): FIXTURE = Path(__file__).parent / "fixtures" / "deep.xml". def make_app(tmp_path, env=None): settings = load_settings({"NETLENS_TOKEN": "t", **(env or {})}); db_path = tmp_path / "t.db"; conn = connect(db_path); init_db(conn); save_scan_results(conn, parse_nmap_xml(FIXTURE.read_text(encoding="utf-8")), "deep"); pub = get_or_create_device(conn, "aa:bb:cc:dd:ee:99", "8.8.8.8"); conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')", (pub,)); conn.commit(); conn.close(); app = create_app(settings, db_path=db_path); app.state.terminal_backends = {"ssh": FakeBackend, "telnet": FakeBackend}; return app. An autouse fixture calls FakeBackend.reset(). Device ids: 1 = 192.168.1.1 (ssh 22 open), 2 = 192.168.1.20 (22 open), 3 = 192.168.1.30 (no 22/23), 4 = 192.168.1.50 (only 8080), 5 = 8.8.8.8 (22 open). AUTH = {"Authorization": "Bearer t"}; AUTH_MSG = {"type":"auth","username":"bob","password":"pw","cols":80,"rows":24}. WebSocket URL: /api/terminal/<id>/ws?proto=ssh (or proto=telnet). Helper def first_message(client, url, headers=AUTH, send=AUTH_MSG): with client.websocket_connect(url, headers=headers) as ws: if send is not None: ws.send_json(send); return ws.receive_json(). Usage always inside `with TestClient(app) as client:`.
Tests: wrong bearer -> pytest.raises(WebSocketDisconnect) around `with client.websocket_connect(url, headers={"Authorization": "Bearer wrong"}) as ws: ws.receive_text()`; no credentials at all -> same; Origin "https://evil.example" with valid auth -> WebSocketDisconnect; Origin "http://testserver" with valid auth -> works (first_message returns a status or error dict, not a disconnect) ; unknown device 999 -> {"type":"error","code":"device"...}; device 5 (public IP) -> code "policy"; device 3 ssh -> code "port"; device 1 telnet (no port 23) -> code "port"; proto=rdp -> code "proto"; auth message without username -> code "auth_message"; auth message that is not JSON object type "auth" ({"type":"x"}) -> code "auth_message"; FakeBackend.connect_error = AuthFailed("authentication failed") -> error dict with code "auth" and message "authentication failed", and json.dumps of the message does not contain "pw"; ConnectFailed("down") -> code "connect", message "down"; HostKeyMismatch("SHA256:a","SHA256:b") -> {"type":"hostkey_mismatch","expected":"SHA256:a","actual":"SHA256:b"}; NETLENS_TERMINAL "off" via make_app(tmp_path, {"NETLENS_TERMINAL":"off"}): websocket connect raises (WebSocketDisconnect or an exception from Starlette for a missing route; use pytest.raises(Exception)) and DELETE /api/devices/1/hostkey returns 404. HARD LIMIT: under 170 lines, each test written once.
