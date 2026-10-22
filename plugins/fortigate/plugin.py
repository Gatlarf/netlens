"""Fortinet FortiGate plugin (kind "topology"): the firewall as the gateway node, the devices behind it as clients, and its health.

Talks to the FortiOS REST API (/api/v2/...) with a bearer token. Only GET requests:

    monitor/system/status           host name, model, serial number, firmware version
    cmdb/system/interface           the firewall's own MAC addresses and addresses, the SNMP index (a stable port number)
    monitor/system/interface        link state, speed and packet counters of every interface
    monitor/system/dhcp             leases: address, MAC address, host name, interface
    monitor/user/device/query       the device inventory FortiOS builds itself: vendor, operating system, kind of device
    monitor/network/arp             ARP table
    cmdb/system/ha, monitor/system/ha-peer     high-availability mode and the members
    monitor/vpn/ipsec               IPsec tunnels
    monitor/license/status          licences and support contracts with their end dates

The field names differ a little between FortiOS versions, so every reader accepts the names it knows and leaves out what it cannot find.
`diagnose` lists the fields a firewall really answers with, so a tester can send them without addresses. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_CLIENTS = 4000


class FortiError(Exception):
    pass


class AuthRefused(FortiError):
    auth_failed = True


class Missing(FortiError):
    """This FortiOS version or profile has no such endpoint."""


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0].split(" ")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


def _first(row, *keys):
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _truthy(value):
    return value is True or str(value).lower() in ("true", "1", "yes", "up")


class Firewall:
    def __init__(self, url, token, vdom="", role="", verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FortiError(f"{url!r} is not an address like https://192.168.1.99")
        self.base, self.id, self.host, self.timeout = f"{parts.scheme}://{parts.netloc}/api/v2", parts.netloc, parts.hostname, float(timeout)
        self.token = token.strip()
        self.vdom = vdom.strip() if vdom else ""
        self.role = (role or "auto").strip().lower()
        if self.role not in ("auto", "gateway", "node"):
            raise FortiError(f"{self.id}: the role must be auto, gateway or node")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def raw(self, path):
        query = ("&" if "?" in path else "?") + "vdom=" + urllib.parse.quote(self.vdom) if self.vdom else ""
        request = urllib.request.Request(f"{self.base}/{path}{query}", headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise AuthRefused(f"{self.id} refused the token (wrong, expired, or this machine is not in the API user's trusted hosts)")
            if exc.code == 403:
                raise AuthRefused(f"{self.id} says this token may not read {path.split('?')[0]} (give the API user's profile read access to it)")
            if exc.code in (404, 405, 424):
                raise Missing(f"{self.id} has no {path.split('?')[0]}")
            raise FortiError(f"{self.id} answered HTTP {exc.code} for {path.split('?')[0]}")
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise FortiError(f"{self.id}: the certificate is not trusted ({exc.reason.verify_message}); install your own certificate or untick Verify TLS certificate")
            raise FortiError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise FortiError(f"{self.id} did not answer properly (is this a FortiGate with the REST API on?): {exc}")

    def get(self, path, optional=False):
        try:
            data = self.raw(path)
        except Missing:
            if optional:
                return None
            raise
        return data

    def results(self, path, optional=True):
        data = self.get(path, optional)
        return data.get("results") if isinstance(data, dict) else None

    def rows(self, path):
        res = self.results(path)
        if isinstance(res, dict):                       # some endpoints answer a table keyed by name
            return [dict(v, name=v.get("name", k)) if isinstance(v, dict) else {"name": k} for k, v in res.items()]
        return [r for r in res if isinstance(r, dict)] if isinstance(res, list) else []


def parse_firewalls(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "token"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one FortiGate")
    out = []
    for i, r in enumerate(items, 1):
        url = str(r.get("host") or "").strip()
        if not url:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("token") or "").strip():
            raise ValueError(f"{url}: enter the API token")
        out.append(Firewall(url, str(r["token"]), str(r.get("vdom") or ""), r.get("role"), config.get("verify_tls", True), config.get("timeout") or 20))
    return out


# ----------------------------------------------------------------------------- what the firewall tells
TYPE_WORDS = (("printer", "printer"), ("camera", "camera"), ("phone", "phone"), ("tablet", "tablet"), ("tv", "tv"), ("television", "tv"), ("game", "console"), ("console", "console"),
              ("nas", "nas"), ("router", "router"), ("switch", "switch"), ("access point", "ap"), ("server", "server"), ("speaker", "speaker"), ("iot", "iot"))
OS_TYPES = (("ios", "phone"), ("android", "phone"), ("windows", "pc"), ("mac", "pc"), ("linux", "pc"), ("chrome", "pc"), ("ubuntu", "pc"))


def _kind(row):
    text = " ".join(str(_first(row, k) or "") for k in ("hardware_type", "hardware_family", "device_type", "type")).lower()
    for word, kind in TYPE_WORDS:
        if re.search(r"\b" + word, text):
            return kind
    os_name = str(_first(row, "os_name", "os") or "").lower()
    for word, kind in OS_TYPES:
        if os_name.startswith(word):
            return kind
    return None


def _epoch_date(value):
    """'2027-01-31' from an epoch (seconds), an ISO date or a date-time; None for 0 and for text that is no date."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d") if value > 86400 else None
    text = str(value or "").strip()
    if re.match(r"^\d{9,11}$", text):
        return _epoch_date(int(text))
    m = re.match(r"^(\d{4})[-/](\d{2})[-/](\d{2})", text)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else None


def find_licences(node, path=()):
    """Every entry with an end date in the licence status, however deeply it is nested: [(name, 'YYYY-MM-DD')]."""
    found = []
    if isinstance(node, dict):
        for key in ("expires", "expiry", "expire", "expiration", "expire_time", "expiry_date"):
            date = _epoch_date(node.get(key)) if key in node else None
            if date and path:
                found.append((" ".join(p.replace("_", " ") for p in path[-2:]), date))
                break
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                found.extend(find_licences(value, path + (str(key),)))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            found.extend(find_licences(value, path))
    return found


def ha_info(fw, serial):
    config = fw.results("cmdb/system/ha") or {}
    mode = str(config.get("mode") or "").lower() if isinstance(config, dict) else ""
    if not mode or mode == "standalone":
        return None
    peers = fw.rows("monitor/system/ha-peer")

    def role(entry):
        for key in ("primary", "master", "is_master", "is_primary"):
            if key in entry:
                return "primary" if _truthy(entry[key]) else "secondary"
        text = str(entry.get("role") or entry.get("status") or "").lower()
        return "primary" if text in ("primary", "master") else "secondary" if text in ("secondary", "slave", "backup") else None

    mine = next((p for p in peers if serial and str(p.get("serial_no") or p.get("serial") or "") == serial), None)
    others = [p for p in peers if p is not mine]
    state = role(mine) if mine else None
    peer_state = role(others[0]) if others else None
    if state is None and peer_state:
        state = "secondary" if peer_state == "primary" else "primary"
    sync = None
    checks = fw.results("monitor/system/ha-checksums")
    if isinstance(checks, list) and checks:
        sums = [tuple(sorted((k, v) for k, v in c.items() if k in ("checksum", "checksums", "global"))) for c in checks if isinstance(c, dict)]
        sync = len(set(sums)) == 1 if sums else None
    return {"mode": {"a-p": "active-passive", "a-a": "active-active"}.get(mode, mode), "state": state, "peer_state": peer_state, "in_sync": sync}


def read(fw):
    status = fw.get("monitor/system/status")
    info = status.get("results") if isinstance(status, dict) and isinstance(status.get("results"), dict) else {}
    serial = str((status or {}).get("serial") or info.get("serial") or "")[:60]
    version = str((status or {}).get("version") or "")[:60]
    cmdb = fw.rows("cmdb/system/interface")
    live = {str(r.get("name")): r for r in fw.rows("monitor/system/interface?include_vlan=false")}
    own = {m for m in (_mac(_first(i, "macaddr", "mac")) for i in cmdb) if m} | {m for m in (_mac(r.get("mac")) for r in live.values()) if m}
    with_mac = [i for i in cmdb if _mac(_first(i, "macaddr", "mac"))]
    mine = next((i for i in with_mac if _ipv4(i.get("ip")) == _ipv4(fw.host)), None) or next((i for i in with_mac if i.get("role") == "lan"), None) or (with_mac[0] if with_mac else None)
    mac = _mac(_first(mine or {}, "macaddr", "mac"))
    node = {"ip": _ipv4(fw.host) or _ipv4((mine or {}).get("ip")), "name": str(info.get("hostname") or fw.id)[:100],
            "model": (" ".join(x for x in (info.get("model_name"), info.get("model_number")) if x) or None), "role": "gateway" if fw.role != "node" else "node"}
    if mac:
        node["mac"] = mac
    ports, used = [], set()
    for i, c in enumerate(sorted(cmdb, key=lambda r: str(r.get("name"))), 1):
        name = str(c.get("name") or "")
        if str(c.get("type") or "physical") not in ("physical", "aggregate", "hard-switch", "vlan") or not name:
            continue
        number = c.get("snmp-index") if isinstance(c.get("snmp-index"), int) and 0 < c.get("snmp-index") <= 1024 else i
        if number in used:
            continue
        used.add(number)
        row = live.get(name, {})
        up = _truthy(row.get("link")) if "link" in row else False
        speed = row.get("speed")
        port = {"port": number, "name": name[:40], "up": up, "enabled": str(c.get("status") or "up") != "down",
                "speed_mbps": float(speed) if isinstance(speed, (int, float)) and speed > 0 else None}
        for key in ("tx_packets", "rx_packets", "tx_errors", "rx_errors"):
            if isinstance(row.get(key), int):
                port[key] = row[key]
        ports.append(port)
    node["ports"] = ports[:128]

    clients = {}

    def entry(m, **fields):
        c = clients.setdefault(m, {"mac": m, "medium": "unknown"})
        for k, v in fields.items():
            if v not in (None, "") and c.get(k) is None:
                c[k] = v
        return c

    for lease in fw.rows("monitor/system/dhcp"):
        m = _mac(lease.get("mac"))
        if m:
            entry(m, ip=_ipv4(lease.get("ip")), name=str(lease.get("hostname") or "")[:100] or None, port=str(lease.get("interface") or "")[:60] or None)
    for d in fw.rows("monitor/user/device/query"):
        m = _mac(d.get("mac"))
        if not m or d.get("is_online") is False:
            continue
        os_name = " ".join(str(x) for x in (d.get("os_name"), d.get("os_version")) if x) or None
        entry(m, ip=_ipv4(_first(d, "ipv4_address", "ip")), name=str(_first(d, "hostname", "host") or "")[:100] or None, vendor=str(d.get("hardware_vendor") or "")[:100] or None,
              os=os_name and os_name[:100], model=str(d.get("hardware_version") or "")[:100] or None, device_type=_kind(d), port=str(_first(d, "interface", "detected_interface") or "")[:60] or None)
    for a in fw.rows("monitor/network/arp"):
        m = _mac(a.get("mac"))
        if m:
            entry(m, ip=_ipv4(a.get("ip")), port=str(a.get("interface") or "")[:60] or None)
    found = [{k: v for k, v in c.items() if v is not None} for m, c in clients.items() if m not in own and c.get("ip")]

    tunnels = []
    for t in fw.rows("monitor/vpn/ipsec"):
        name = str(t.get("name") or t.get("p2name") or "")[:80]
        proxies = [p for p in t.get("proxyid") or [] if isinstance(p, dict)]
        if name:
            tunnels.append({"name": name, "remote": str(t.get("rgwy") or "")[:80] or None,
                            "up": any(str(p.get("status")).lower() == "up" for p in proxies) if proxies else str(t.get("status") or "").lower() == "up"})
    licences = sorted({(n[:80], d) for n, d in find_licences(fw.results("monitor/license/status") or {})}, key=lambda x: x[1])
    firewall = {"version": version or None, "serial": serial or None, "model": node["model"], "ha": ha_info(fw, serial), "tunnels": tunnels,
                "licences": [{"name": n, "expires": d} for n, d in licences[:50]]}
    node["firewall"] = {k: v for k, v in firewall.items() if v}
    return node, found[:MAX_CLIENTS], {"version": version, "tunnels": len(tunnels)}


def connect(config):
    reads, problems = [], []
    for fw in parse_firewalls(config):
        try:
            reads.append((fw,) + read(fw))
        except AuthRefused:
            raise
        except FortiError as exc:
            problems.append(str(exc))
    if not reads:
        raise FortiError("; ".join(problems) or "no FortiGate answered")
    return reads, problems


def assemble(reads):
    nodes, clients, seen = [], [], set()
    gateway_mac = None
    for fw, node, found, _ in reads:
        entry = dict(node)
        if entry["role"] == "gateway" and gateway_mac is not None:
            entry["role"] = "node"
        if entry["role"] == "gateway":
            gateway_mac = entry.get("mac") or "02:00:" + ":".join(f"{int(p):02x}" for p in entry["ip"].split("."))
        elif gateway_mac:
            entry["parent_mac"] = gateway_mac
        nodes.append(entry)
    node_key = {id(n): n.get("mac") or "02:00:" + ":".join(f"{int(p):02x}" for p in n["ip"].split(".")) for n in nodes}
    for (fw, node, found, _), entry in zip(reads, nodes):
        for c in found:
            if c["mac"] in seen:
                continue
            seen.add(c["mac"])
            clients.append({**c, "node_mac": node_key[id(entry)]})
    return nodes, clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, problems = connect(config)
    total = sum(len(r[2]) for r in reads)
    versions = sorted({r[3]["version"] for r in reads if r[3]["version"]})
    message = f"Connected to {len(reads)} FortiGate(s) ({', '.join(versions) or 'version unknown'}): {total} device(s) behind it, {sum(r[3]['tunnels'] for r in reads)} VPN tunnel(s)"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    nodes, clients = assemble(reads)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    text = re.sub(r"https?://[^\s/]+", "<firewall>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<firewall>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{2,5})?\b", "<firewall>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the firewalls answer, as counts and field names (no addresses, names, serial numbers or tokens)."""
    try:
        firewalls = parse_firewalls(config)
    except (ValueError, FortiError) as exc:
        return {"error": str(exc)}
    report = {"firewalls": []}
    for fw in firewalls:
        entry = {"steps": {}}
        report["firewalls"].append(entry)
        for step, path in (("status", "monitor/system/status"), ("interfaces_cmdb", "cmdb/system/interface"), ("interfaces_live", "monitor/system/interface?include_vlan=false"),
                           ("dhcp", "monitor/system/dhcp"), ("devices", "monitor/user/device/query"), ("arp", "monitor/network/arp"), ("ha_config", "cmdb/system/ha"),
                           ("ha_peers", "monitor/system/ha-peer"), ("ipsec", "monitor/vpn/ipsec"), ("licences", "monitor/license/status")):
            try:
                data = fw.raw(path)
                res = data.get("results") if isinstance(data, dict) else data
                if isinstance(res, list):
                    entry["steps"][step] = {"ok": True, "count": len(res), "fields": sorted({k for r in res[:50] if isinstance(r, dict) for k in r})[:50]}
                elif isinstance(res, dict):
                    entry["steps"][step] = {"ok": True, "fields": sorted(res)[:50], "licence_entries_found": len(find_licences(res)) if step == "licences" else None}
                else:
                    entry["steps"][step] = {"ok": True, "type": type(res).__name__}
                if step == "status" and isinstance(data, dict):
                    entry["steps"][step]["version"] = str(data.get("version") or "")
                    entry["steps"][step]["top_level_fields"] = sorted(data)[:20]
            except Missing:
                entry["steps"][step] = {"ok": False, "error": "not on this firewall or profile"}
            except AuthRefused:
                raise
            except FortiError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
