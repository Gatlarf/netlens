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

## app/scanner/netinfo.py
10:def parse_ip_addr(text: str) -> list[str]:
16:    networks: set[str] = set()
62:def parse_default_gateway(text: str) -> Optional[str]:
100:async def run_ip(args: list[str], ip_path: str = "ip", timeout: float = 5.0) -> str:
130:async def detect_ranges(ip_path: str = "ip") -> list[str]:
136:async def detect_gateway(ip_path: str = "ip") -> Optional[str]:

TASK:
Create tests/test_netinfo.py with pytest (asyncio_mode=auto) for app.scanner.netinfo (parse_ip_addr, parse_default_gateway, run_ip, detect_ranges, detect_gateway). Cases: parse_ip_addr on a multi-line sample with lo (127.0.0.1/8), eth0 (192.168.0.5/24), docker0 (172.17.0.1/16), wlan0 (10.1.2.3/22), a public iface (203.0.113.9/24) and "veth123@if4" (172.18.0.1/16) returns ["10.1.0.0/22", "192.168.0.0/24"] (sorted as strings is fine; assert as a set plus length 2); empty text returns []; garbage lines are ignored; a /16 private network (192.168.0.5/16) is excluded because the prefix is too short. parse_default_gateway: normal line returns "192.168.0.1"; multiple lines returns the first; empty -> None; "default dev ppp0" (no via) -> None; invalid ip -> None. run_ip/detect_*: create fake executables in tmp_path (python script with a "#!" line using sys.executable, chmod 0o755) that print sample output; assert detect_ranges and detect_gateway results through ip_path=; a missing executable path returns "" / [] / None; a script exiting 1 returns "". At least 14 tests.
