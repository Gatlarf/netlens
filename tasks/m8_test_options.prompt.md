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

TASK: write tests/test_scan_options.py (pytest, full file, under 170 lines, each test written once).

Module under test: app/scanner/options.py exposing ScanOptions (dataclass; defaults timing=3, quick_mode="ports", quick_top_ports=100, quick_ports="", deep_top_ports=1000, deep_ports="", deep_version="full", deep_os=True, deep_traceroute=True, skip_dns=False, host_timeout=0), PRESETS ({"default": {}, "fast": {...}, "fastest": {...}}), normalize_ports(spec), options_from_dict(data, base=None), options_to_dict(opts), options_from_json(text), preset_dict(name), option_args(kind, opts), command_preview(kind, opts).

Cases (exactly these):
1. option_args with default ScanOptions(): quick == ["-T3", "--top-ports", "100"]; deep == ["-T3", "-sV", "-O", "--osscan-guess", "--traceroute", "--top-ports", "1000"]; an unknown kind raises ValueError.
2. option_args quick variations: timing 4 + quick_top_ports 50 -> ["-T4","--top-ports","50"]; quick_ports "22, 80,443" -> ["-T3","-p","22,80,443"] (the custom spec wins over top ports; use options_from_dict so it is normalized); quick_mode "discovery" -> ["-T3","-sn"]; skip_dns and host_timeout 90 -> ends with ["-n","--host-timeout","90s"].
3. option_args deep variations: deep_version "light" -> contains "-sV" followed by "--version-light"; deep_version "off", deep_os False, deep_traceroute False, deep_top_ports 100, timing 4 -> exactly ["-T4","--top-ports","100"]; deep_ports "1-1024,8080" -> ["-p","1-1024,8080"] replaces --top-ports.
4. normalize_ports valid: "80" -> "80"; " 22 , 80-90 ,443 " -> "22,80-90,443"; "" -> "". Invalid (parametrize, each raises ValueError whose message contains the given text): "22,,80" -> "empty item"; "abc" -> "not a valid port"; "0" -> "out of range"; "70000" -> "out of range"; "90-80" -> "start is after"; "22;rm -rf /" -> "not a valid port"; "1-2-3" -> "not a valid port"; a list of 200 distinct ports like ",".join(str(p) for p in range(1000, 1200)) -> "too long".
5. options_from_dict: applies values on top of defaults without mutating the base; with a base object keeps base values for keys not given; unknown key "turbo" -> ValueError containing "unknown setting"; invalid values (parametrize with (dict, expected message part)): {"timing": 1} -> "timing", {"timing": "4"} -> "timing", {"timing": True} -> "timing", {"quick_mode": "x"} -> "quick_mode", {"deep_os": 1} -> "deep_os", {"quick_top_ports": 0} -> "quick_top_ports", {"deep_top_ports": 10001} -> "deep_top_ports", {"deep_version": "fast"} -> "deep_version", {"host_timeout": 5} -> "host_timeout", {"quick_ports": "99999"} -> "quick_ports"; host_timeout 0 and 10 and 86400 are accepted.
6. options_to_dict round trip: options_from_dict(options_to_dict(opts)) == opts for a non-default object; options_from_json: None, "", "{broken", "[]", '{"timing": 99}' all return ScanOptions() defaults; valid '{"timing": 4}' returns timing 4.
7. presets: preset_dict("default") equals options_to_dict(ScanOptions()); preset_dict("fast")["timing"] == 4 and ["deep_version"] == "light" and ["deep_top_ports"] == 200 and other values default; preset_dict("fastest")["skip_dns"] is True and ["deep_os"] is False and ["host_timeout"] == 120; every preset passes options_from_dict; preset_dict("nope") raises KeyError.
8. command_preview: for defaults the quick preview == "nmap -T3 --top-ports 100 -oX - <ranges>".
