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
Create app/scanner/classify.py (pure, stdlib).
DEVICE_TYPES = ("router","switch","ap","server","pc","phone","printer","iot","camera","nas","vm","unknown").
def classify_device(*, vendor: str | None = None, os_name: str | None = None, os_type: str | None = None, open_ports=(), services=(), hostnames=(), mac: str | None = None) -> str
Return one DEVICE_TYPES member. Matching is case-insensitive. Evaluate rules in this order, first match wins:
1. VM: mac starts with one of 52:54:00, 00:50:56, 00:0c:29, 08:00:27, bc:24:11, 00:15:5d, or vendor contains vmware/qemu/virtualbox/microsoft hyper-v/proxmox.
2. os_type mapping (nmap osclass type): "router"->router, "switch"->switch, "WAP"->ap, "printer"->printer, "webcam"->camera, "phone"->phone, "storage-misc"->nas, "media device","game console","specialized","power-device","PDA","terminal"->iot. (os_type "general purpose" and everything else falls through.)
3. Vendor keywords: synology, qnap, western digital->nas; hikvision, dahua, axis communications, reolink, amcrest->camera; hp, hewlett, canon, epson, brother, xerox, lexmark, kyocera, ricoh together with any of ports 631, 9100, 515->printer; espressif, tuya, sonoff, shelly, tp-link smart (vendor contains "tp-link" AND no port 22/445 open and ports 80 or none)->iot is NOT wanted, skip that last one; ubiquiti, mikrotik, tp-link, netgear, cisco, aruba, ruckus, zyxel, d-link, avm, fritz, belkin, asus, linksys, huawei: router if any hostname contains "router"/"gw"/"gateway" or ports include 53, else ap if hostname contains "ap" as a token or "wifi"/"wlan"/"unifi", else switch if hostname contains "sw"/"switch", else router; apple, samsung, xiaomi, oneplus, google, huawei device, oppo, motorola when no ports are open->phone.
4. Port rules: 631 or 9100 or 515 open->printer; 554 or 8554 open->camera; any of 5000,5001,2049,548 or hostname contains "nas"->nas; 53 and 67 both->router.
5. os_name contains "windows" -> server if any of 3389,445,1433,80,443 and name contains "server", else pc; os_name contains "android" or "ios" or "iphone"->phone; os_name contains "linux" or "bsd"-> server if ports include any of 22,80,443,3306,5432,8080,8006 else pc; os_name contains "mac os" or "macos"->pc.
6. ports include 22 or 80 or 443 or 8080 or 3306->server.
7. otherwise "unknown".
Keep the rule tables as module level constants. Handle None and empty inputs without raising. open_ports is an iterable of ints; services and hostnames iterables of str.
