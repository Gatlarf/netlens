Create app/db.py using only the stdlib sqlite3.

- SCHEMA_VERSION = 1.
- def connect(path: str | os.PathLike) -> sqlite3.Connection: row_factory = sqlite3.Row, PRAGMA foreign_keys=ON, journal_mode=WAL (ignore failure for ":memory:"), creates parent dir for file paths.
- def init_db(conn) -> None: idempotent. Creates a table schema_version(version INTEGER) with one row, and these tables (all TEXT timestamps are ISO-8601 UTC strings):
  devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, primary_ip TEXT, hostname TEXT, vendor TEXT, os_name TEXT, os_confidence INTEGER, device_type TEXT, type_override TEXT, custom_name TEXT, notes TEXT, tags TEXT, online INTEGER NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, pos_x REAL, pos_y REAL, raw_xml TEXT)
  device_ips(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(device_id, ip))
  device_names(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, name TEXT NOT NULL, source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(device_id, name, source))
  ports(id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, proto TEXT NOT NULL, port INTEGER NOT NULL, state TEXT NOT NULL, service TEXT, product TEXT, version TEXT, updated TEXT NOT NULL, UNIQUE(device_id, proto, port))
  scans(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, hosts_found INTEGER NOT NULL DEFAULT 0, error TEXT)
  events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, kind TEXT NOT NULL, detail TEXT)
  relations(id INTEGER PRIMARY KEY, src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, kind TEXT NOT NULL, source TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0, manual INTEGER NOT NULL DEFAULT 0, UNIQUE(src_id, dst_id, kind))
  settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)
  host_keys(device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL)
  plus indexes on device_ips(ip), events(ts), ports(device_id).
- def utcnow() -> str: current UTC time as ISO-8601 with seconds precision and trailing "Z".
- def get_or_create_device(conn, mac: str | None, ip: str, now: str | None = None) -> int: MAC is normalised to lowercase colon-separated form (accept "AA-BB-CC-DD-EE-FF" too). If mac is given: find device by mac, else create. If mac is None: find a device with mac IS NULL and primary_ip == ip, else create. On find: update last_seen and primary_ip, set online=1. Always upsert a device_ips row for (device, ip) updating last_seen. Returns the device id. Commit before returning.
- def add_event(conn, kind: str, detail: str | None = None, device_id: int | None = None, now: str | None = None) -> int: insert event, commit, return id.
- def list_devices(conn) -> list[dict]: all devices ordered by INET-like numeric IP order is NOT required; order by primary_ip string then id; return plain dicts.
