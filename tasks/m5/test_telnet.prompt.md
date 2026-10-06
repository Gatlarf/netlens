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

## app/terminal/telnet.py
11:IAC = 255
12:DONT = 254
13:DO = 253
14:WONT = 252
15:WILL = 251
16:SB = 250
17:SE = 240
18:ECHO = 1
19:SGA = 3
20:NAWS = 31
23:def escape_iac(data: bytes) -> bytes:
28:def naws_bytes(cols: int, rows: int) -> bytes:
40:def process_telnet_bytes(buf: bytes) -> tuple[bytes, bytes, bytes]:
134:class TelnetBackend(TerminalBackend):
135:    def __init__(
154:    async def connect(self) -> None:
165:    async def read(self) -> bytes:
198:    async def write(self, data: bytes) -> None:
204:    async def resize(self, cols: int, rows: int) -> None:
211:    async def close(self) -> None:

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
Create tests/test_terminal_telnet.py with pytest (asyncio_mode=auto) for app.terminal.telnet (process_telnet_bytes, naws_bytes, escape_iac, TelnetBackend) and app.terminal.base (ConnectFailed). process_telnet_bytes cases: plain text passes through with no replies; IAC IAC becomes b"\xff"; IAC WILL ECHO -> reply IAC DO ECHO and no data; IAC WILL 24 -> reply IAC DONT 24; IAC DO NAWS -> IAC WILL NAWS; IAC DO 24 -> IAC WONT 24; IAC WONT/DONT -> no reply; IAC SB 31 0 80 0 24 IAC SE skipped; text around control sequences preserved in order; trailing lone IAC and "IAC DO" are returned as leftover with data before them preserved; empty input. naws_bytes(80,24) == bytes([255,250,31,0,80,0,24,255,240]); naws_bytes(255,24) doubles the 0xFF payload byte; escape_iac(b"a\xffb") == b"a\xff\xffb". TelnetBackend: start a local asyncio.start_server on 127.0.0.1 port 0 whose handler writes b"login: " then reads one line and echoes it back with "got: " prefix and closes; connect a TelnetBackend("127.0.0.1", port), await connect(), read() returns b"login: ", write(b"bob\r\n"), read until data contains b"got: bob", then a later read returns b"" at EOF; close() twice is fine; a server that sends IAC WILL ECHO + b"hi" first yields read() == b"hi" and the server receives IAC DO ECHO; connecting to a closed port raises ConnectFailed. At least 14 tests.
