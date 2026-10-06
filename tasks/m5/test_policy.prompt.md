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

## app/terminal/policy.py
7:def target_allowed(ip: str, ranges: Iterable[str]) -> bool:
44:def pick_port(
45:    proto: str,
46:    requested: int | None,
47:    open_ports: list[tuple[str, int]],

TASK:
Create tests/test_terminal_policy.py with pytest for app.terminal.policy (target_allowed, pick_port). target_allowed: "192.168.1.5" with ranges [] -> True; "10.0.0.7" with [] True; "172.16.0.1" True; "169.254.1.1" True; "8.8.8.8" False; "127.0.0.1" False even when ranges ["127.0.0.0/8"]; "0.0.0.0" False; "224.0.0.1" False; "192.168.1.5" with ranges ["192.168.1.0/24"] True; "192.168.2.5" with ranges ["192.168.1.0/24"] False; "10.0.0.7" with ranges ["10.0.0.0/20", "192.168.1.0/24"] True; "garbage" False; "" False; ranges given as a tuple works. pick_port: ("ssh", None, [("tcp",22)]) -> 22; ("telnet", None, [("tcp",23)]) -> 23; ("ssh", 2222, [("tcp",2222)]) -> 2222; ("ssh", None, []) raises ValueError; ("ssh", 22, [("udp",22)]) raises ValueError (udp ignored); ("ssh", 70000, [("tcp",70000)]) ValueError; ("ssh", 0, ...) ValueError; ("rdp", None, ...) ValueError. At least 16 cases (parametrize).
HARD LIMIT: keep the file under 150 lines; each test written once.
