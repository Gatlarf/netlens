INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite; connections come from app.db.connect(path) and use row_factory=sqlite3.Row)
CREATE TABLE checks (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ts TEXT NOT NULL,
            up INTEGER NOT NULL,
            rtt_ms REAL
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
        , notify_offline INTEGER NOT NULL DEFAULT 1)
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
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
CREATE TABLE proxmox_guests (
            vmid INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            node TEXT NOT NULL,
            status TEXT NOT NULL,
            macs TEXT NOT NULL DEFAULT '[]',
            ips TEXT NOT NULL DEFAULT '[]',
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            host_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            updated TEXT NOT NULL
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
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )

## app/db.py helpers
- utcnow() -> str            # 'YYYY-MM-DDTHH:MM:SSZ' (UTC, seconds precision, trailing Z)
- connect(path) -> sqlite3.Connection
- init_db(conn) -> None      # idempotent schema creation/migration
- get_or_create_device(conn, mac: str | None, ip: str, now: str | None = None) -> int   # returns device id
- add_event(conn, kind: str, detail: str | None = None, device_id: int | None = None, now: str | None = None) -> int   # commits, returns event id
- get_setting(conn, key: str) -> str | None
- set_setting(conn, key: str, value: str) -> None   # commits
- delete_setting(conn, key: str) -> None            # commits
All timestamps in the database are strings in the utcnow() format, so they compare correctly as strings.

TASK: write tests/test_proxmox_units.py (pytest, full file, under 150 lines, each test written once).

Modules under test:
- app/integrations/proxmox_config.py: ProxmoxConfig dataclass (enabled=False, url="", verify_tls=True, username="", password="", token_id="", token_secret=""), load_config(conn), save_config(conn, cfg), uses_token(cfg), is_configured(cfg), normalize_url(url), public_dict(cfg). normalize_url("192.168.0.180") == "https://192.168.0.180:8006"; normalize_url(" https://pve.lan:8006/ ") == "https://pve.lan:8006"; normalize_url("http://pve.lan") == "http://pve.lan:8006"; normalize_url("") == ""; normalize_url("ftp://x") raises ValueError. public_dict has no "password" and no "token_secret" keys but has password_set, token_secret_set, auth_method ("token", "password" or "none"), configured. is_configured needs a valid non-empty url plus token_id+token_secret or username+password.
- app/integrations/proxmox_match.py: norm_mac(mac), match_inventory(inventory, devices) -> {"hosts": {node: device_id|None}, "guests": [guest + device_id + host_device_id]}.
  inventory = {"nodes": [{"name": "pve1", "ip": "192.168.0.180"}], "guests": [{"vmid": 100, "name": "web", "kind": "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": ["192.168.0.50"]}]}; devices = [{"id": 1, "mac": "00:11:22:33:44:55", "ips": ["192.168.0.180"]}, {"id": 2, "mac": "BC:24:11:AA:BB:CC", "ips": ["192.168.0.50"]}].

Fixture `conn`: from app.db import connect, init_db; c = connect(":memory:"); init_db(c); yield c.

Cases (exactly these):
1. config load/save round trip on an empty db (defaults first, then saved values); garbage JSON stored with set_setting(conn, "proxmox", "oops") -> defaults.
2. normalize_url cases listed above.
3. is_configured / uses_token / public_dict as described (secrets never appear in public_dict: assert "s3cret" not in str(public_dict(cfg))).
4. norm_mac: "BC-24-11-AA-BB-CC" -> "bc:24:11:aa:bb:cc"; None -> None; "" -> None.
5. match by MAC: with the example data, hosts == {"pve1": 1}; the guest gets device_id 2 and host_device_id 1; the input dicts are not mutated (the original guest has no "device_id" key).
6. match by IP fallback: guest with macs [] and ips ["192.168.0.50"] still matches device 2 (device mac None is fine).
7. no match: guest with unknown mac and ip -> device_id None but host_device_id still 1; a node without matching device -> hosts {"pve1": None} and host_device_id None.
8. a device claimed by two guests goes to the lowest vmid (two guests, vmid 100 and 101, same mac); the host device is never matched to a guest (a guest whose ip equals the node ip stays unmatched).
9. MAC match wins over IP: guest A (vmid 100) has ips of device 2 but the mac of device 3; guest B (vmid 101) has ips of device 3 only. Expect A -> 3 (mac), B -> 2? No: B has no mac match and its ip belongs to device 3 which is claimed, so B stays None. Assert exactly that.
