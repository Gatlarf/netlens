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

## app/scanner/names.py
14:def parse_ssdp_response(text: str) -> dict[str, str]:
22:    result: dict[str, str] = {}
45:def parse_upnp_description(xml_text: str) -> dict[str, str]:
59:    result: dict[str, str] = {}
85:async def ssdp_search(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
93:    result: dict[str, list[tuple[str, str]]] = {}
161:async def mdns_browse(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
167:    result: dict[str, list[tuple[str, str]]] = {}
229:async def collect_names(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
251:    merged: dict[str, list[tuple[str, str]]] = {}

TASK:
Create tests/test_names.py with pytest (asyncio_mode=auto) for app.scanner.names (parse_ssdp_response, parse_upnp_description, collect_names). Tests: parse_ssdp_response on "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux/4.9 UPnP/1.0 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n" returns location, server, st, usn lowercase keys with correct values; header names in mixed case work; garbage and empty text return {}; parse_upnp_description on a realistic UPnP XML with xmlns="urn:schemas-upnp-org:device-1-0" containing friendlyName "Living Room TV", manufacturer "Samsung", modelName "UE55", modelNumber "1.0" returns the four keys; XML with only friendlyName returns just that key; invalid XML returns {}. collect_names: monkeypatch app.scanner.names.ssdp_search and app.scanner.names.mdns_browse with async fakes returning {"192.168.1.5": [("tv", "ssdp")]} and {"192.168.1.5": [("tv.local", "mdns")], "192.168.1.9": [("nas", "mdns")]}; collect_names returns both IPs with merged, de-duplicated lists; if one fake raises RuntimeError the other's result is still returned; if both raise the result is {}. At least 10 tests.
