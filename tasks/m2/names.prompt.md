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
Create app/scanner/names.py (stdlib + the optional package zeroconf). Purpose: collect extra device names from the LAN without root.
- def parse_ssdp_response(text: str) -> dict[str, str]: parse an SSDP/HTTP-style response (header lines "NAME: value", case-insensitive names). Return a dict with lowercase keys, e.g. {"location": ..., "server": ..., "usn": ..., "st": ...}. Ignore the status line and malformed lines.
- def parse_upnp_description(xml_text: str) -> dict[str, str]: parse a UPnP device description XML with xml.etree.ElementTree (namespace-agnostic: match on local tag names). Return the values of friendlyName, manufacturer, modelName, modelNumber that exist (keys: "friendly_name","manufacturer","model_name","model_number"). Invalid XML returns {}.
- async def ssdp_search(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]: send an M-SEARCH (ST: ssdp:all, MX: 2) over UDP multicast 239.255.255.250:1900 using a non-blocking asyncio datagram or loop.sock_* with a timeout, collect responses for `timeout` seconds, and map sender IP -> [(name, "ssdp")] where name is the SERVER header's product token if no description is fetched. Fetching descriptions is optional; do not do HTTP requests. Never raise: return {} on any OSError.
- async def mdns_browse(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]: use zeroconf.asyncio.AsyncZeroconf and AsyncServiceBrowser on the service types ["_workstation._tcp.local.", "_http._tcp.local.", "_ssh._tcp.local.", "_airplay._tcp.local.", "_ipp._tcp.local.", "_smb._tcp.local."], wait `timeout`, resolve each service's server name and addresses (parsed_addresses()), and map ip -> [(server name without trailing '.local.' and without a trailing dot, "mdns")]. Import zeroconf inside the function and return {} if it is missing or anything fails.
- async def collect_names(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]: run ssdp_search and mdns_browse concurrently (asyncio.gather with return_exceptions=True), merge the dicts (dedupe), never raise.
