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
Create app/terminal/ssh.py using asyncssh (installed, version 2.x). Imports: asyncssh; from app.terminal.base import TerminalBackend, AuthFailed, ConnectFailed, HostKeyMismatch.
class SSHBackend(TerminalBackend): __init__(self, host: str, port: int = 22, username: str = "", password: str | None = None, private_key: str | None = None, passphrase: str | None = None, cols: int = 80, rows: int = 24, known_fingerprint: str | None = None, connect_timeout: float = 10.0).
- connect(): define a small asyncssh.SSHClient subclass whose validate_host_public_key(self, host, addr, port, key) -> bool computes fp = key.get_fingerprint("sha256") (a string like "SHA256:abc..."), stores it on the backend (self.fingerprint) and returns True when known_fingerprint is None (trust on first use; set self.new_key = True) or when it equals known_fingerprint; otherwise returns False. Connect with asyncssh.connect(host, port, client_factory=<that class>, username=username, password=password, client_keys=[asyncssh.import_private_key(private_key, passphrase)] if private_key else None, known_hosts=() , agent_path=None, config=None, login_timeout=connect_timeout), wrapped in asyncio.wait_for(..., connect_timeout). (known_hosts=() together with validate_host_public_key makes asyncssh delegate the host-key decision to the callback; verify by running the tests.) Do not read ~/.ssh or any agent. If the host key was rejected (known_fingerprint set and fingerprint differs) raise HostKeyMismatch(known_fingerprint, self.fingerprint). asyncssh.PermissionDenied -> AuthFailed("authentication failed"); other asyncssh.Error, OSError, asyncio.TimeoutError -> ConnectFailed with a short message (never include the password or key). Invalid private key -> ConnectFailed("invalid private key").
- After connecting open an interactive session with a PTY: self._process = await conn.create_process(term_type="xterm-256color", term_size=(cols, rows), encoding=None) (bytes mode).
- read(): data = await self._process.stdout.read(4096); return data or b"" (EOF -> b""). Also merge stderr is unnecessary with a PTY.
- write(data): self._process.stdin.write(data) then await drain.
- resize(cols, rows): self._process.change_terminal_size(cols, rows).
- close(): idempotent: close the process stdin / the connection (conn.close(); await conn.wait_closed() with a short timeout).
Never log credentials.
