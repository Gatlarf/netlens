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
Create app/terminal/telnet.py (asyncio, stdlib). Imports: from app.terminal.base import TerminalBackend, ConnectFailed.
Constants: IAC=255, DONT=254, DO=253, WONT=252, WILL=251, SB=250, SE=240, ECHO=1, SGA=3, NAWS=31.
- def process_telnet_bytes(buf: bytes) -> tuple[bytes, bytes, bytes]: parse raw bytes received from a telnet server. Returns (data, replies, leftover). data = the application bytes with all IAC sequences removed (IAC IAC becomes a single 0xFF data byte). replies = the bytes to send back: for WILL ECHO and WILL SGA reply IAC DO <opt>; for any other WILL reply IAC DONT <opt>; for DO NAWS reply IAC WILL NAWS; for any other DO reply IAC WONT <opt>; WONT/DONT need no reply; subnegotiations IAC SB ... IAC SE are skipped; two-byte commands (IAC NOP etc.) are skipped. leftover = an incomplete trailing sequence (e.g. a lone IAC at the end, IAC DO without the option byte, an unterminated SB) which the caller prepends to the next chunk.
- def naws_bytes(cols: int, rows: int) -> bytes: IAC SB NAWS cols_hi cols_lo rows_hi rows_lo IAC SE (any 0xFF byte in the payload doubled).
- def escape_iac(data: bytes) -> bytes: double every 0xFF.
- class TelnetBackend(TerminalBackend): __init__(self, host: str, port: int = 23, cols: int = 80, rows: int = 24, connect_timeout: float = 10.0). async connect(): asyncio.open_connection with asyncio.wait_for(timeout); OSError/TimeoutError -> ConnectFailed(str message without exposing internals more than the strerror). async read() -> bytes: reads up to 4096 bytes, prepends leftover, runs process_telnet_bytes, writes replies to the server, loops until it has application data (so it never returns b"" for control-only chunks); returns b"" at EOF. async write(data) sends escape_iac(data). async resize(cols, rows): remembers the size and, if the server agreed to NAWS (we sent WILL NAWS), sends naws_bytes. async close(): close the writer, idempotent. When we send WILL NAWS also send the initial size right after.
