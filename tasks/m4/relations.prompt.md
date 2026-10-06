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
Create app/scanner/relations.py (pure, stdlib only).
@dataclass(frozen=True) class Edge: src_id: int; dst_id: int; kind: str; source: str; confidence: float.
def infer_relations(devices: list[dict], hops: dict[str, list[str]] | None = None, gateway_ip: str | None = None) -> list[Edge]
- devices: dicts with keys id, primary_ip, type (device type string), hostname (str|None), vendor (str|None), ports (list of ints, open ports), online (0/1). hops: mapping device IP -> list of intermediate router IPs (nearest first) from traceroute.
- Build ip_to_id from devices with a primary_ip.
- gateway edges: gw_id = ip_to_id.get(gateway_ip) if gateway_ip else None; source "default-route", confidence 1.0. If gw_id is None and gateway_ip is None: when exactly one device has type "router", use it with source "heuristic" and confidence 0.5; otherwise no gateway edges. For every other device that has NO usable hops (empty or missing in `hops`, or whose hop IPs are all unknown) add Edge(device.id, gw_id, "gateway", ...). Never an edge from the gateway to itself.
- route edges (kind "route", source "traceroute", confidence 0.9): for a device with hops, take the hop IPs that exist in ip_to_id (in order, nearest first, drop duplicates and the device itself) -> known = [r1, r2, ...]; add Edge(device.id, r1_id, "route") for the nearest known router... i.e. the device attaches to the LAST known hop (the router closest to the device), and each consecutive pair of known hops is chained: Edge(r_k_id, r_{k-1}_id) from farther-from-scanner... define precisely: known hops ordered nearest-to-scanner first = [r1, r2, ..., rn]; add Edge(device, rn); for i from n down to 2 add Edge(r_i, r_{i-1}); and Edge(r1, gw_id) if gw_id is known and r1 != gw. Skip duplicates and self edges.
- host-of edges (kind "host-of", source "heuristic", confidence 0.5): VM devices are those with type == "vm". Hypervisor candidates are devices (not VMs) that have port 8006 in ports, OR whose hostname or vendor (lowercase) contains any of: proxmox, esxi, vmware, hyper-v, hypervisor, libvirt, kvm, xen. If there is exactly one candidate add Edge(vm.id, candidate.id, "host-of") for every VM; with zero or several candidates add none.
- Return the unique edges (unique per (src_id, dst_id, kind)) sorted by (kind, src_id, dst_id).
