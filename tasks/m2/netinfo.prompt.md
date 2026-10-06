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

TASK:
Create app/scanner/netinfo.py (stdlib, asyncio). app.config.is_scannable_range(cidr: str) -> bool exists (True only for private/link-local IPv4 networks with prefix >= 20).
- def parse_ip_addr(text: str) -> list[str]: parse the output of `ip -o -f inet addr show` (lines like "2: eth0    inet 192.168.0.5/24 brd 192.168.0.255 scope global eth0" or "3: wlan0    inet 10.1.2.3/22 ..."). For each line take the interface name (second whitespace field, strip a trailing ':' and any '@...' suffix) and the CIDR after "inet". Skip interfaces named "lo" or starting with "docker", "veth", "br-", "virbr", "tun", "tap", "wg". Convert to the network with ipaddress.ip_network(cidr, strict=False), keep only those passing is_scannable_range, return sorted unique str list.
- def parse_default_gateway(text: str) -> str | None: parse `ip -4 route show default` output ("default via 192.168.0.1 dev eth0 proto dhcp ...") and return the gateway IP of the first default route, or None. Validate with ipaddress.ip_address.
- async def run_ip(args: list[str], ip_path: str = "ip", timeout: float = 5.0) -> str: run asyncio.create_subprocess_exec(ip_path, *args), return stdout text; return "" on FileNotFoundError, timeout, or non-zero exit.
- async def detect_ranges(ip_path: str = "ip") -> list[str]: parse_ip_addr(await run_ip(["-o","-f","inet","addr","show"], ip_path)).
- async def detect_gateway(ip_path: str = "ip") -> str | None: parse_default_gateway(await run_ip(["-4","route","show","default"], ip_path)).
