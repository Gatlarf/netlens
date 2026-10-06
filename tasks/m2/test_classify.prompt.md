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

## app/scanner/classify.py
7:DEVICE_TYPES: tuple[str, ...] = (
23:VM_MAC_PREFIXES: tuple[str, ...] = (
33:VM_VENDOR_KEYWORDS: tuple[str, ...] = (
42:OS_TYPE_MAP: dict[str, str] = {
59:VENDOR_NAS_KEYWORDS: tuple[str, ...] = (
65:VENDOR_CAMERA_KEYWORDS: tuple[str, ...] = (
73:VENDOR_PRINTER_KEYWORDS: tuple[str, ...] = (
85:PRINTER_PORTS: frozenset[int] = frozenset({631, 9100, 515})
87:VENDOR_ROUTER_KEYWORDS: tuple[str, ...] = (
105:VENDOR_PHONE_KEYWORDS: tuple[str, ...] = (
117:CAMERA_PORTS: frozenset[int] = frozenset({554, 8554})
118:NAS_PORTS: frozenset[int] = frozenset({5000, 5001, 2049, 548})
119:ROUTER_PORTS: frozenset[int] = frozenset({53, 67})
122:WINDOWS_SERVER_PORTS: frozenset[int] = frozenset({3389, 445, 1433, 80, 443})
123:LINUX_SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 3306, 5432, 8080, 8006})
126:SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 8080, 3306})
129:def classify_device(
131:    vendor: str | None = None,
132:    os_name: str | None = None,
133:    os_type: str | None = None,
134:    open_ports: Iterable[int] = (),
135:    services: Iterable[str] = (),
136:    hostnames: Iterable[str] = (),
137:    mac: str | None = None,

TASK:
Create tests/test_classify.py with pytest for app.scanner.classify.classify_device (keyword-only args vendor, os_name, os_type, open_ports, services, hostnames, mac) and DEVICE_TYPES. Cases (expected type): mac "52:54:00:aa:bb:cc" -> vm; vendor "VMware, Inc." -> vm; os_type "router" -> router; os_type "WAP" -> ap; os_type "printer" -> printer; os_type "webcam" -> camera; os_type "phone" -> phone; os_type "storage-misc" -> nas; os_type "specialized" -> iot; vendor "Synology Incorporated" -> nas; vendor "Hikvision" -> camera; vendor "HP" with open_ports [9100] -> printer; vendor "Espressif Inc." -> iot; vendor "Ubiquiti" with hostnames ["unifi-ap-lobby"] -> ap; vendor "Ubiquiti" with hostnames ["sw-core"] -> switch; vendor "Belkin International" with open_ports [22,53,80,443] -> router; vendor "Apple" with open_ports [] -> phone; open_ports [631] only -> printer; open_ports [554] -> camera; open_ports [5000] -> nas; os_name "Linux 5.4" with open_ports [22] -> server; os_name "Linux 5.4" with open_ports [] -> pc; os_name "Windows 10" with open_ports [] -> pc; os_name "Windows Server 2019" with open_ports [445] -> server; open_ports [8080] only -> server; nothing at all -> unknown. A VM mac wins over os_type "router". Result is always in DEVICE_TYPES. None inputs do not raise. At least 20 tests, parametrized.
