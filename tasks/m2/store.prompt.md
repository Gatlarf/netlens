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

## app/scanner/nmap_parser.py
6:@dataclass
7:class ScanPort:
8:    proto: str
9:    port: int
10:    state: str
11:    service: Optional[str]
12:    product: Optional[str]
13:    version: Optional[str]
14:    extrainfo: Optional[str]
17:@dataclass
18:class ScanHost:
19:    ip: str
20:    mac: Optional[str]
21:    vendor: Optional[str]
22:    hostnames: list[tuple[str, str]]
23:    ports: list[ScanPort]
24:    os_name: Optional[str]
25:    os_accuracy: Optional[int]
26:    os_type: Optional[str]
27:    ttl: Optional[int]
28:    via: str
31:def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
40:    hosts: list[ScanHost] = []

## app/scanner/classify.py
8:DEVICE_TYPES: tuple[str, ...] = (
24:VM_MAC_PREFIXES: tuple[str, ...] = (
34:VM_VENDOR_KEYWORDS: tuple[str, ...] = (
43:OS_TYPE_MAP: dict[str, str] = {
60:VENDOR_NAS_KEYWORDS: tuple[str, ...] = (
66:VENDOR_CAMERA_KEYWORDS: tuple[str, ...] = (
74:VENDOR_PRINTER_KEYWORDS: tuple[str, ...] = (
86:PRINTER_PORTS: frozenset[int] = frozenset({631, 9100, 515})
88:VENDOR_IOT_KEYWORDS: tuple[str, ...] = (
95:VENDOR_ROUTER_KEYWORDS: tuple[str, ...] = (
113:VENDOR_PHONE_KEYWORDS: tuple[str, ...] = (
125:CAMERA_PORTS: frozenset[int] = frozenset({554, 8554})
126:NAS_PORTS: frozenset[int] = frozenset({5000, 5001, 2049, 548})
127:ROUTER_PORTS: frozenset[int] = frozenset({53, 67})
130:WINDOWS_SERVER_PORTS: frozenset[int] = frozenset({3389, 445, 1433, 80, 443})
131:LINUX_SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 3306, 5432, 8080, 8006})
134:SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 8080, 3306})
137:def classify_device(
139:    vendor: str | None = None,
140:    os_name: str | None = None,
141:    os_type: str | None = None,
142:    open_ports: Iterable[int] = (),
143:    services: Iterable[str] = (),
144:    hostnames: Iterable[str] = (),
145:    mac: str | None = None,

## app/db.py
11:SCHEMA_VERSION = 1
14:def utcnow() -> str:
19:def connect(path: str | os.PathLike) -> sqlite3.Connection:
43:def init_db(conn: sqlite3.Connection) -> None:
210:def _normalize_mac(mac: str | None) -> str | None:
223:def get_or_create_device(
224:    conn: sqlite3.Connection,
225:    mac: str | None,
226:    ip: str,
227:    now: str | None = None,
236:    device_id: int | None = None
298:def add_event(
299:    conn: sqlite3.Connection,
300:    kind: str,
301:    detail: str | None = None,
302:    device_id: int | None = None,
303:    now: str | None = None,
321:def list_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:

TASK:
Rewrite app/scanner/store.py (COMPLETE file) keeping the existing public function and its behaviour, and adding event logging, classification and extra names.

Existing behaviour to keep: save_scan_results(conn, hosts: list[ScanHost], kind: str, now: str | None = None, extra_names: dict[str, list[tuple[str, str]]] | None = None) -> {"new": int, "updated": int, "device_ids": list[int]}; kind must be "quick" or "deep" else ValueError; each host handled with app.db.get_or_create_device(conn, host.mac, host.ip, now); vendor updated only when not None; os_name/os_confidence updated only when host.os_name is not None; hostname = first PTR name else first name else unchanged; device_names upserted with source = type.lower(); ports upserted, and for kind "deep" ports not in the result are deleted; one commit at the end; new-vs-updated decided with prev_max = SELECT COALESCE(MAX(id),0) FROM devices read before get_or_create_device (device is new if returned id > prev_max).

Additions:
1. extra_names: mapping ip -> list of (name, source). Before processing, for each host whose ip is in extra_names, append those (name, source) pairs to its hostnames (as (name, source)) when not already present (copy the host with dataclasses.replace; do not mutate the input).
2. Snapshot BEFORE calling get_or_create_device (it updates the row): look up the existing device with the same identity rule: if host.mac is not None -> SELECT id, primary_ip, online, os_name FROM devices WHERE mac = lower-colon mac; else WHERE mac IS NULL AND primary_ip = host.ip. Also read the set of (proto, port) already in ports for it.
3. Events via app.db.add_event(conn, kind, detail, device_id=..., now=now) (note add_event commits; that is acceptable). Kinds: "device_new" (detail f"{ip} {vendor or ''}".strip()) for a new device; for existing devices: "device_online" if old online == 0; "ip_changed" if old primary_ip != host.ip (detail f"{old} -> {new}"); "os_changed" if old os_name and host.os_name are both not None and differ (detail f"{old} -> {new}"); "port_opened" for every (proto, port) not previously stored (detail f"{proto}/{port} {service or ''}".strip()). No port_opened events for new devices.
4. Classification: after ports and names are saved, compute the open ports (all rows of the ports table for the device whose state starts with "open"), their services, all names of the device from device_names, and set devices.device_type = app.scanner.classify.classify_device(vendor=<devices.vendor>, os_name=<devices.os_name>, os_type=host.os_type, open_ports=<ints>, services=<strs>, hostnames=<strs>, mac=<devices.mac>). (classify_device is keyword-only and returns a string.) device_type is never touched when type_override is set (type_override is a separate column and must not be modified).
Use parameterised SQL only.
