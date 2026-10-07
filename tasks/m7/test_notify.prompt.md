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

TASK: write tests/test_notify.py (pytest, full file, under 200 lines, each test written once).

Modules under test (already written, use exactly these names):
- app/notify/config.py: NotifyConfig dataclass (enabled=False, smtp_host="", smtp_port=587, security="starttls", username="", password="", from_addr="", to_addrs=[], notify_new=True, notify_offline=True, last_event_id=None); load_config(conn); save_config(conn, cfg); is_configured(cfg) (needs smtp_host, from_addr, non-empty to_addrs); public_dict(cfg) (all fields except password and last_event_id, plus "password_set" and "configured"); parse_addresses(value) -> list[str] (splits on comma/semicolon/whitespace, drops empties and case-insensitive duplicates, raises ValueError("invalid email address: X") for entries without a valid user@host.tld shape).
- app/notify/mail.py: MailError; send_mail(cfg, subject, body, *, smtp_factory=None, timeout=20.0) -> None. smtp_factory(host, port, timeout) returns an object with methods ehlo(), starttls(context=None), login(user, password), send_message(msg), quit(). Security "starttls" calls ehlo, starttls, ehlo, then login (only if username), send_message, quit. Security "none" skips starttls. Security "ssl" also uses the factory. Raises MailError("SMTP host, sender and recipients must be set") when host, from_addr or recipients are missing. smtplib.SMTPAuthenticationError -> MailError containing "authentication failed"; ConnectionRefusedError raised by the factory -> MailError containing "refused"; socket.gaierror -> "resolve".
- app/notify/digest.py: current_max_event_id(conn) -> int; collect_events(conn, after_id, cfg) -> (events, max_id) where an event is kept only if kind == "device_new" and cfg.notify_new, or kind == "device_offline" and cfg.notify_offline and the device's notify_offline column is 1; events are dicts with keys id, ts, kind, device_id, name, ip, mac, vendor; build_message(events) -> (subject, body) with subject like "[Netlens] 2 new devices, 1 device offline" and "1 new device" / "1 device offline" singular forms; body contains the device names and ips.

Fixtures: `conn` = connect(":memory:") + init_db(c) (from app.db import connect, init_db, get_or_create_device, add_event). Create devices with get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10") (returns id, use different MACs/ips). add_event(conn, "device_new", "192.168.1.10 Acme", device_id=id, now="2026-03-10T12:00:00Z") inserts an event and returns its id. A fake SMTP class FakeSMTP recording calls in a list `calls` (tuples like ("ehlo",), ("starttls",), ("login", user, pw), ("send_message", msg), ("quit",)) is created inside the test file; the factory is `lambda host, port, timeout: fake`.

Cases (exactly these):
1. config: load_config on an empty db returns defaults; save_config then load_config round-trips (enabled=True, host, to_addrs list, last_event_id=7); garbage JSON in settings key "notifications" (set_setting(conn, "notifications", "{not json")) gives defaults; security "weird" in stored JSON falls back to "starttls".
2. is_configured false for defaults, true for a complete config; public_dict has no "password" key, has password_set True when a password is set and False otherwise, and "configured".
3. parse_addresses: "a@x.com, b@y.org; a@X.com  c@z.io" -> ["a@x.com","b@y.org","c@z.io"]; "not-an-address" raises ValueError; None -> [].
4. send_mail starttls sequence: calls == ehlo, starttls, ehlo, login, send_message, quit in this order; the message in send_message has Subject and To headers matching the config (To joined by ", ") and its body text contains the body.
5. send_mail with security "none" and empty username: no starttls, no login call.
6. send_mail errors: missing host -> MailError; factory raising smtplib.SMTPAuthenticationError(535, b"bad") -> MailError with "authentication failed"; factory raising ConnectionRefusedError -> "refused".
7. collect_events: create device A (notify_offline default 1) and device B (set notify_offline = 0 via SQL UPDATE); events: device_new for A, device_offline for A, device_offline for B, device_online for A; collect_events(conn, 0, cfg) with defaults returns kinds ["device_new","device_offline"] only for A and max_id equal to the id of the last event; with cfg.notify_new=False only the offline event of A; with cfg.notify_offline=False only the new event; after_id = last id returns ([], last id).
8. build_message: one new + two offline events from collect_events-shaped dicts you write by hand gives subject "[Netlens] 1 new device, 2 devices offline" and a body containing both section headings "New devices:" and "Went offline:".
