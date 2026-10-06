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

## app/terminal/ssh.py
6:class SSHBackend(TerminalBackend):
7:    def __init__(
35:    def _create_client_factory(self):
51:    async def connect(self) -> None:
95:    async def read(self) -> bytes:
101:    async def write(self, data: bytes) -> None:
107:    async def resize(self, cols: int, rows: int) -> None:
112:    async def close(self) -> None:

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
Create tests/test_terminal_ssh.py with pytest (asyncio_mode=auto) for app.terminal.ssh.SSHBackend and app.terminal.base exceptions (AuthFailed, ConnectFailed, HostKeyMismatch). Start a local asyncssh server in a fixture (async fixture using pytest_asyncio.fixture, yield (port, host_key_fingerprint), close it afterwards): class DemoServer(asyncssh.SSHServer) with begin_auth(self, username) -> True, password_auth_supported(self) -> True, validate_password(self, username, password) -> username == "bob" and password == "secret"; async def handle(process): process.stdout.write("welcome\r\n"); then loop reading lines from process.stdin (data = await process.stdin.read(1024); stop on EOF) and echo back "echo:" + data; process.exit(0) at EOF. server = await asyncssh.create_server(DemoServer, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle, encoding=None) with key = asyncssh.generate_private_key("ssh-ed25519") (note: with encoding=None the process streams use bytes, so write b"welcome\r\n"); port = server.sockets[0].getsockname()[1]; fingerprint = key.get_fingerprint("sha256"). Tests: connect with the right credentials -> backend.fingerprint equals the server's fingerprint and new_key is True; read until b"welcome" is received; write(b"hi\n") then read until b"echo:hi" appears; resize(100, 40) does not raise; close() twice is fine and afterwards read returns b"" or the session is closed; wrong password -> AuthFailed; connecting with known_fingerprint equal to the real one works with new_key False; known_fingerprint "SHA256:bogus" -> HostKeyMismatch with .expected "SHA256:bogus" and .actual equal to the real fingerprint; connecting to a closed port -> ConnectFailed; connect_timeout (use a 0.2 s timeout against a listening socket that never answers, e.g. asyncio.start_server whose handler sleeps) -> ConnectFailed; a garbage private_key string with username bob -> ConnectFailed; error messages never contain the password. Use a helper to read until a marker with a 5 second asyncio.wait_for. At least 10 tests.
