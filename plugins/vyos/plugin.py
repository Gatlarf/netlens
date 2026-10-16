"""VyOS plugin (kind "topology"): the router as a node, the devices around it as clients.

Talks to VyOS's HTTPS API (POST with form fields `data` = JSON and `key`). Only read operations are ever sent:

    GET  /info                          version and host name (no key needed)
    POST /show {"op":"show","path":["interfaces"]}              interfaces with address and MAC (text table)
    POST /show {"op":"show","path":["arp"]}                      the neighbour table: address, interface, MAC, state (text table)
    POST /show {"op":"show","path":["dhcp","server","leases"]}   DHCP leases (text table), when the DHCP server is configured
    POST /retrieve {"op":"exists","path":["nat","source"]}       whether a source NAT rule exists (marks the gateway)

VyOS answers `show` with text, so the tables are parsed by looking for IPv4 and MAC addresses in each line instead of fixed columns; that keeps working
when a column is added in a newer release. Neighbours in state FAILED or INCOMPLETE and the router's own MAC addresses are skipped. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAC = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
DEAD_STATES = ("FAILED", "INCOMPLETE")
MAX_CLIENTS = 4000


class VyosError(Exception):
    pass


class AuthRefused(VyosError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower()
    return value if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


class Router:
    def __init__(self, url, key, role="", verify_tls=False, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise VyosError(f"{url!r} is not an address like https://192.168.1.1")
        self.base, self.id, self.host, self.key, self.timeout = f"{parts.scheme}://{parts.netloc}", parts.netloc, parts.hostname, key, float(timeout)
        self.role = (role or "auto").strip().lower()
        if self.role not in ("auto", "gateway", "node"):
            raise VyosError(f"{self.id}: the role must be auto, gateway or node")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def _open(self, request):
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8", "replace"))
            except ValueError:
                body = {}
            error = str(body.get("error", "")).lower() if isinstance(body, dict) else ""
            if exc.code in (401, 403) or ("key" in error and "required" in error):
                raise AuthRefused(f"{self.id} refused the API key")
            if isinstance(body, dict) and "success" in body:
                return body
            raise VyosError(f"{self.id} answered HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise VyosError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise VyosError(f"{self.id} did not answer properly (is this VyOS's HTTPS API?): {exc}")

    def info(self):
        answer = self._open(urllib.request.Request(f"{self.base}/info", headers={"Accept": "application/json"}, method="GET"))
        return answer.get("data") or {} if isinstance(answer, dict) else {}

    def call(self, endpoint, payload, optional=False):
        boundary = uuid.uuid4().hex
        fields = {"data": json.dumps(payload), "key": self.key}
        body = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in fields.items()) + f"--{boundary}--\r\n"
        request = urllib.request.Request(f"{self.base}/{endpoint}", data=body.encode(), method="POST",
                                         headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Accept": "application/json"})
        answer = self._open(request)
        if not isinstance(answer, dict) or not answer.get("success"):
            error = str((answer or {}).get("error") or "unknown error").strip()
            if "api key" in error.lower():
                raise AuthRefused(f"{self.id} refused the API key")
            if optional:
                return None
            raise VyosError(f"{self.id}: {payload.get('path')} failed: {error[:200]}")
        return answer.get("data")

    def show(self, *path, optional=False):
        data = self.call("show", {"op": "show", "path": list(path)}, optional)
        return data if isinstance(data, str) else ""


def parse_routers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one VyOS router")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("api_key") or "").strip():
            raise ValueError(f"{host}: enter the API key")
        out.append(Router(host, str(r["api_key"]).strip(), r.get("role"), config.get("verify_tls", False), config.get("timeout") or 30))
    return out


def parse_interfaces(text):
    """[(name, ipv4, mac)] from the `show interfaces` table (a continuation line has no name)."""
    rows = []
    for line in text.splitlines():
        mac, ip = MAC.search(line), IPV4.search(line)
        parts = line.split()
        if mac and parts and not line.startswith(" "):
            rows.append((parts[0], _ipv4(ip.group(1)) if ip else None, _mac(mac.group(1))))
    return rows


def parse_neighbors(text):
    """[(ipv4, interface, mac, state)] from `show arp`."""
    rows = []
    for line in text.splitlines():
        mac, ip = MAC.search(line), IPV4.search(line)
        if ip and mac:
            parts = line.split()
            rows.append((_ipv4(ip.group(1)), parts[1] if len(parts) > 1 else "", _mac(mac.group(1)), parts[-1].upper()))
    return rows


def parse_leases(text):
    """[(ipv4, mac, hostname)] from `show dhcp server leases`; the host name is the last column when it looks like one."""
    rows = []
    for line in text.splitlines():
        mac, ip = MAC.search(line), IPV4.search(line)
        if ip and mac:
            last = line.split()[-1]
            name = last if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", last) and not IPV4.fullmatch(last) and not MAC.fullmatch(last) and last.lower() not in ("active", "free", "expired", "default") and not re.fullmatch(r"[\d:.\-/]+", last) else None
            rows.append((_ipv4(ip.group(1)), _mac(mac.group(1)), name))
    return rows


def read(router):
    info = router.info()
    interfaces = parse_interfaces(router.show("interfaces"))
    own = {m for _, _, m in interfaces if m}
    primary = next((r for r in interfaces if r[0] and not r[0].startswith("127.") and r[2]), None) or next((r for r in interfaces if r[2]), None)
    nat = router.call("retrieve", {"op": "exists", "path": ["nat", "source"]}, optional=True) is True
    role = router.role if router.role != "auto" else ("gateway" if nat else "node")
    node = {"mac": primary[2] if primary else None, "macs": sorted(own - {primary[2]}) if primary else None, "ip": (primary[1] if primary else None) or _ipv4(router.host),
            "name": str(info.get("hostname") or router.id)[:100], "model": ("VyOS " + str(info.get("version") or "")).strip()[:100], "role": role}
    clients = {}
    for ip, iface, mac, state in parse_neighbors(router.show("arp")):
        if mac and ip and state not in DEAD_STATES and mac not in own:
            clients[mac] = {"mac": mac, "ip": ip, "medium": "unknown"}
    for ip, mac, name in parse_leases(router.show("dhcp", "server", "leases", optional=True)):
        if mac and mac not in own:
            entry = clients.setdefault(mac, {"mac": mac, "ip": ip, "medium": "unknown"})
            entry["ip"] = entry.get("ip") or ip
            if name:
                entry["name"] = name[:100]
    return {k: v for k, v in node.items() if v is not None}, list(clients.values())[:MAX_CLIENTS], {"version": str(info.get("version") or ""), "nat": nat}


def connect(config):
    reads, problems = [], []
    for router in parse_routers(config):
        try:
            reads.append(read(router))
        except AuthRefused:
            raise
        except VyosError as exc:
            problems.append(str(exc))
    if not reads:
        raise VyosError("; ".join(problems) or "no VyOS router answered")
    return reads, problems


def assemble(reads):
    nodes, clients, seen = [], [], set()
    for node, found, _ in reads:
        if not node.get("mac") or any(node["mac"] == n["mac"] for n in nodes):
            continue
        entry = dict(node)
        if entry["role"] == "gateway" and any(n["role"] == "gateway" for n in nodes):
            entry["role"] = "node"
        nodes.append(entry)
    node_macs = {m for n in nodes for m in [n["mac"], *n.get("macs", [])]}
    gateway = next((n["mac"] for n in nodes if n["role"] == "gateway"), None)
    for n in nodes:
        if gateway and n["mac"] != gateway and n["role"] != "gateway":
            n["parent_mac"] = gateway
    for node, found, _ in reads:
        if not node.get("mac"):
            continue
        for c in found:
            if c["mac"] not in seen and c["mac"] not in node_macs:
                seen.add(c["mac"])
                clients.append({**c, "node_mac": node["mac"]})
    return nodes, clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, problems = connect(config)
    versions = sorted({r[2]["version"] for r in reads if r[2]["version"]})
    message = f"Connected to {len(reads)} VyOS router(s) ({', '.join(versions) or 'version unknown'}): {sum(len(r[1]) for r in reads)} client(s) in the ARP table and DHCP leases"
    if len([1 for r in reads if r[0]["role"] == "gateway"]) > 1:
        message += ". More than one router counts as gateway: the first is used"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    nodes, clients = assemble(reads)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<router>", str(exc))[:300]


def diagnose(config):
    """What the routers answer, as counts (no MAC or IP addresses, names or keys)."""
    try:
        routers = parse_routers(config)
    except (ValueError, VyosError) as exc:
        return {"error": str(exc)}
    report = {"routers": []}
    for router in routers:
        entry = {"steps": {}}
        report["routers"].append(entry)
        try:
            info = router.info()
            entry["steps"]["info"] = {"ok": True, "fields": sorted(info), "version": str(info.get("version") or "")}
            for step, path in (("interfaces", ("interfaces",)), ("arp", ("arp",)), ("dhcp_leases", ("dhcp", "server", "leases"))):
                text = router.show(*path)
                lines = [l for l in text.splitlines() if l.strip()]
                parsed = parse_interfaces(text) if step == "interfaces" else parse_neighbors(text) if step == "arp" else parse_leases(text)
                entry["steps"][step] = {"ok": True, "lines": len(lines), "parsed_rows": len(parsed), "header_columns": len(lines[0].split()) if lines else 0}
            entry["steps"]["nat"] = {"ok": True, "source_nat": router.call("retrieve", {"op": "exists", "path": ["nat", "source"]}, optional=True) is True}
        except AuthRefused:
            raise
        except VyosError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc)}
    return report
