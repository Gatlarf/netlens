"""Proxmox VE plugin: lists the VMs and containers and the host each one runs on (read-only)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import re
import socket
import ssl
import time
from typing import Any, Callable
import urllib.error
from urllib.parse import urlparse
import urllib.parse
import urllib.request


# ----------------------------------------------------------------------------- diagnostic helpers
KEEP_WORDS = {"type", "status", "state", "online", "template", "kind", "version", "release", "role", "model"}
MAC_RE = re.compile(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SAMPLES = 3


def describe(value: Any, key: str = "") -> Any:
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        macs = [k for k in value if isinstance(k, str) and MAC_RE.match(k)]
        out = {k: describe(v, k) for k, v in value.items() if k not in macs}
        if macs:  # rows keyed by MAC address: the addresses are not written down, one example row is described
            out[f"<mac> x {len(macs)}"] = describe(value[macs[0]])
        return out
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and not isinstance(value, (dict, list)):
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if MAC_RE.match(value):
            return "<mac " + ("dashes" if "-" in value else "colons") + (", UPPER" if value.upper() == value and re.search("[A-F]", value) else "") + ">"
        if IPV4_RE.match(value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def mask(text: str) -> str:
    """A configuration string with its structure kept and MAC / IPv4 addresses hidden (for example `virtio=<mac>,bridge=vmbr0`)."""
    text = re.sub(r"(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", "<mac>", text)
    return re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(/\d+)?\b", "<ipv4>", text)


def problem(exc: Exception) -> str:
    return type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]


def make_step(report: dict) -> Callable[[str, Callable[[], Any]], Any]:
    """step(name, call): run one read, record its shape or its failure, return the raw value (or None)."""

    def step(name: str, call: Callable[[], Any], shape: Callable[[Any], Any] = describe) -> Any:
        try:
            raw = call()
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": problem(exc)}
            return None
        report["steps"][name] = {"ok": True, "shape": shape(raw)}
        return raw

    return step


# ----------------------------------------------------------------------------- configuration
@dataclass
class ProxmoxConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = True
    username: str = ""
    password: str = ""
    token_id: str = ""
    token_secret: str = ""


def uses_token(cfg: ProxmoxConfig) -> bool:
    return bool(cfg.token_id) and bool(cfg.token_secret)


def has_credentials(cfg: ProxmoxConfig) -> bool:
    return uses_token(cfg) or (bool(cfg.username) and bool(cfg.password))


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("invalid Proxmox URL")
    if not parsed.hostname:
        raise ValueError("invalid Proxmox URL")
    if parsed.port is None:
        url = url + ":8006"
    return url


# ----------------------------------------------------------------------------- client
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
# Interfaces that only exist inside a guest (container networks, bridges, tunnels): their addresses
# are not on the LAN and must not be used to identify the guest.
INTERNAL_NIC_RE = re.compile(r"^(lo|docker\d*|br-.*|veth.*|virbr.*|cni.*|flannel.*|cali.*|tun\d*|tap\d*|wg\d*|tailscale.*)$")


class ProxmoxError(Exception):
    """Human-readable failure talking to Proxmox."""


def _ipv4(value: str | None) -> str | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.split("/")[0].strip())
    except ValueError:
        return None
    if addr.version != 4 or addr.is_loopback or addr.is_link_local:
        return None
    return str(addr)


def parse_net(value: str) -> tuple[str | None, str | None]:
    """Parse a guest `netN` config value into (mac, static ipv4).

    qemu:  "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0"
    lxc:   "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.0.5/24,type=veth"
    """
    mac = ip = None
    for part in str(value).split(","):
        key, _, val = part.partition("=")
        key, val = key.strip(), val.strip()
        if key == "ip":
            ip = _ipv4(val)
        elif MAC_RE.match(val) and mac is None:
            mac = val.lower()
    return mac, ip


Transport = Callable[[str, str, dict, bytes | None], tuple[int, bytes]]


class ProxmoxClient:
    def __init__(self, cfg: ProxmoxConfig, *, transport: Transport | None = None, timeout: float = 10.0):
        self.cfg = cfg
        self.base = normalize_url(cfg.url) + "/api2/json"
        self.timeout = timeout
        self._transport = transport or self._urllib_transport
        self._ticket: str | None = None
        self._csrf = ""

    # -- transport ---------------------------------------------------------
    def _urllib_transport(self, method: str, url: str, headers: dict, data: bytes | None) -> tuple[int, bytes]:
        ctx = ssl.create_default_context()
        if not self.cfg.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise ProxmoxError(
                    "the TLS certificate could not be verified; Proxmox uses a self-signed "
                    "certificate by default, so turn off 'Verify TLS certificate' to continue"
                ) from exc
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise ProxmoxError(f"connection to {self.cfg.url} timed out") from exc
            raise ProxmoxError(f"cannot connect to {self.cfg.url}: {reason}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise ProxmoxError(f"connection to {self.cfg.url} timed out") from exc
        except OSError as exc:
            raise ProxmoxError(f"cannot connect to {self.cfg.url}: {exc}") from exc

    # -- auth + requests ---------------------------------------------------
    def _auth_headers(self) -> dict:
        if uses_token(self.cfg):
            return {"Authorization": f"PVEAPIToken={self.cfg.token_id}={self.cfg.token_secret}"}
        if self._ticket is None:
            body = urllib.parse.urlencode({"username": self.cfg.username, "password": self.cfg.password}).encode()
            status, raw = self._transport(
                "POST", self.base + "/access/ticket", {"Content-Type": "application/x-www-form-urlencoded"}, body
            )
            if status in (401, 403):
                raise ProxmoxError("authentication failed (check username and password)")
            data = self._decode(status, raw)
            if not isinstance(data, dict) or not data.get("ticket"):
                raise ProxmoxError("authentication failed (no ticket returned)")
            self._ticket = data["ticket"]
            self._csrf = data.get("CSRFPreventionToken") or ""
        return {"Cookie": f"PVEAuthCookie={self._ticket}", "CSRFPreventionToken": self._csrf}

    @staticmethod
    def _decode(status: int, raw: bytes) -> Any:
        if status >= 400:
            raise ProxmoxError(f"Proxmox returned HTTP {status}")
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))["data"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ProxmoxError("unexpected response from Proxmox (is this a Proxmox VE address?)") from exc

    def get(self, path: str) -> Any:
        status, raw = self._transport("GET", self.base + path, {**self._auth_headers(), "Accept": "application/json"}, None)
        if status == 401:
            raise ProxmoxError("authentication failed (check the credentials or API token)")
        if status == 403:
            raise ProxmoxError("permission denied (the account needs at least the PVEAuditor role)")
        return self._decode(status, raw)

    def post(self, path: str, fields: dict) -> Any:
        headers = {**self._auth_headers(), "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        status, raw = self._transport("POST", self.base + path, headers, urllib.parse.urlencode(fields).encode())
        if status == 401:
            raise ProxmoxError("authentication failed (check the credentials or API token)")
        if status == 403:
            raise ProxmoxError("permission denied (the token needs the VM.PowerMgmt privilege, for example the PVEVMAdmin role on the guest, and 'Privilege Separation' off or the role given to the token too)")
        return self._decode(status, raw)

    def _try(self, path: str) -> Any:
        """GET that returns None instead of raising for per-guest details that may be unavailable."""
        try:
            return self.get(path)
        except ProxmoxError:
            return None

    # -- high level --------------------------------------------------------
    def version(self) -> str:
        data = self.get("/version")
        return str(data.get("version", "unknown")) if isinstance(data, dict) else "unknown"

    def nodes(self) -> list[dict]:
        out: list[dict] = []
        status = self._try("/cluster/status")
        for entry in status or []:
            if entry.get("type") == "node" and entry.get("name"):
                out.append({"name": entry["name"], "ip": _ipv4(entry.get("ip")), "online": bool(entry.get("online", 1))})
        if out:
            return out
        for entry in self.get("/nodes"):  # not clustered / no cluster permission: look up each node's address
            name = entry.get("node")
            if not name:
                continue
            ip = None
            nets = self._try(f"/nodes/{name}/network") or []
            for nic in sorted(nets, key=lambda n: n.get("iface") != "vmbr0"):
                ip = _ipv4(nic.get("address"))
                if ip:
                    break
            out.append({"name": name, "ip": ip, "online": entry.get("status", "online") == "online"})
        return out

    def _guest_details(self, node: str, kind: str, vmid: int, running: bool) -> tuple[list[str], list[str]]:
        macs: list[str] = []
        ips: list[str] = []

        def add(lst: list[str], value: str | None) -> None:
            if value and value not in lst:
                lst.append(value)

        config = self._try(f"/nodes/{node}/{kind}/{vmid}/config") or {}
        for key, value in config.items():
            if re.fullmatch(r"net\d+", key):
                mac, ip = parse_net(value)
                add(macs, mac)
                add(ips, ip)
            elif re.fullmatch(r"ipconfig\d+", key):  # qemu cloud-init
                add(ips, parse_net(value)[1])

        if running:  # live addresses
            if kind == "lxc":
                for nic in self._try(f"/nodes/{node}/lxc/{vmid}/interfaces") or []:
                    if not INTERNAL_NIC_RE.match(str(nic.get("name", ""))):
                        add(ips, _ipv4(nic.get("inet")))
            else:
                agent = self._try(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
                nics = agent.get("result") if isinstance(agent, dict) else agent
                for nic in nics or []:
                    if INTERNAL_NIC_RE.match(str(nic.get("name", ""))):
                        continue
                    hw = nic.get("hardware-address")
                    if hw and MAC_RE.match(hw) and not hw.startswith("00:00:00:00:00:00"):
                        add(macs, hw.lower())
                    for a in nic.get("ip-addresses", []):
                        if a.get("ip-address-type") == "ipv4":
                            add(ips, _ipv4(a.get("ip-address")))
        return macs, ips

    def inventory(self) -> dict:
        nodes = self.nodes()
        guests = []
        for g in self.get("/cluster/resources?type=vm"):
            if g.get("template") or g.get("type") not in ("qemu", "lxc") or g.get("vmid") is None:
                continue
            running = g.get("status") == "running"
            macs, ips = self._guest_details(g["node"], g["type"], int(g["vmid"]), running)
            config = self._try(f"/nodes/{g['node']}/{g['type']}/{int(g['vmid'])}/config") or {}
            guests.append({
                "cpus": g.get("maxcpu"),
                "memory_mb": int(g["maxmem"] / 1048576) if isinstance(g.get("maxmem"), (int, float)) and g["maxmem"] else None,
                "disk_gb": int(g["maxdisk"] / 1073741824) if isinstance(g.get("maxdisk"), (int, float)) and g["maxdisk"] else None,
                "uptime": g.get("uptime") if running else None,
                "tags": str(g.get("tags") or config.get("tags") or "").replace(";", ", "),
                "os": str(config.get("ostype") or ""),
                "autostart": bool(int(config.get("onboot", 0))) if str(config.get("onboot", "")).isdigit() else None,
                "vmid": int(g["vmid"]),
                "name": g.get("name") or f"{g['type']}-{g['vmid']}",
                "kind": g["type"],
                "node": g["node"],
                "status": g.get("status", "unknown"),
                "macs": macs,
                "ips": ips,
            })
        guests.sort(key=lambda g: g["vmid"])
        return {"nodes": nodes, "guests": guests}


# ----------------------------------------------------------------------------- plugin entry points
CLIENT_FACTORY = ProxmoxClient  # replaced by tests


def _servers(config: dict) -> list[dict]:
    """One flat config per Proxmox: the rows of the server list, or the single url and credentials of an older Netlens."""
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    keep = ("token_id", "token_secret", "username", "password")
    out = [{"url": r.get("host"), "verify_tls": config.get("verify_tls", True), **{k: r.get(k) or "" for k in keep}}
           for r in rows if isinstance(r, dict) and any(r.get(k) for k in ("host", *keep))]
    if not out:
        raise ValueError("enter the address and credentials of at least one Proxmox server")
    return out


def _each(config: dict, work):
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - keeps its type; only the message gets the server's name
            if len(servers) > 1 and exc.args:
                exc.args = (f"{one.get('url')}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


def _client(config: dict):
    cfg = ProxmoxConfig(
        url=config.get("url", ""),
        verify_tls=bool(config.get("verify_tls", True)),
        username=config.get("username", ""),
        password=config.get("password", ""),
        token_id=config.get("token_id", ""),
        token_secret=config.get("token_secret", ""),
    )
    if not has_credentials(cfg):
        raise ValueError("enter either an API token (ID and secret) or a username and password")
    return CLIENT_FACTORY(cfg)


def _details(g: dict) -> dict:
    """Resources, uptime, tags and so on, as the guest details of the plugin contract (empty values left out)."""
    started = None
    if isinstance(g.get("uptime"), (int, float)) and g["uptime"] > 0:
        started = datetime.fromtimestamp(time.time() - g["uptime"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    details = {"cpus": g.get("cpus"), "memory_mb": g.get("memory_mb"), "disk_gb": g.get("disk_gb"), "started": started,
               "tags": g.get("tags"), "os": g.get("os"), "autostart": g.get("autostart")}
    return {k: v for k, v in details.items() if v not in (None, "")}


def _test_one(config: dict) -> str:
    client = _client(config)
    version = client.version()
    inventory = client.inventory()
    return f"Connected: Proxmox VE {version}, {len(inventory['nodes'])} node(s), {len(inventory['guests'])} guest(s)"


def test(config: dict) -> dict:
    messages = _each(config, _test_one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} Proxmox servers answered. " + " | ".join(messages)}


def fetch(config: dict) -> dict:
    results = _each(config, _fetch_one)
    if len(results) == 1:
        return results[0]
    hosts, guests, taken = [], [], set()
    for out in results:
        hosts += out["hosts"]
        for g in out["guests"]:
            if g["id"] in taken:                      # the same VM number on two clusters: keep both apart
                g = {**g, "id": f"{g['host_id']}/{g['id']}"}
            taken.add(g["id"])
            guests.append(g)
    return {"hosts": hosts, "guests": guests}


def _fetch_one(config: dict) -> dict:
    inventory = _client(config).inventory()
    return {
        "hosts": [
            {"id": n["name"], "name": n["name"], "ip": n.get("ip"), "online": bool(n.get("online", True))}
            for n in inventory["nodes"]
        ],
        "guests": [
            {
                "id": str(g["vmid"]),
                "name": g["name"],
                "kind": g["kind"],
                "host_id": g["node"],
                "status": g["status"],
                "macs": g["macs"],
                "ips": g["ips"],
                "details": _details(g),
            }
            for g in inventory["guests"]
        ],
    }


def diagnose(config: dict) -> dict:
    """What this Proxmox answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""

    client = _client(_servers(config)[0])      # the first server is described
    report: dict = {"steps": {}}
    step = make_step(report)
    step("version", lambda: client.get("/version"))
    step("cluster_status", lambda: client.get("/cluster/status"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    step("nodes", lambda: client.get("/nodes"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    resources = step("resources", lambda: client.get("/cluster/resources?type=vm"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    for kind in ("qemu", "lxc"):
        guest = next((g for g in resources or [] if isinstance(g, dict) and g.get("type") == kind and not g.get("template") and g.get("vmid") is not None), None)
        if guest:
            # the network lines of a guest keep their structure (`virtio=<mac>,bridge=vmbr0`); every other value is only described
            def read_config(guest=guest, kind=kind):
                cfg = client.get(f"/nodes/{guest['node']}/{kind}/{guest['vmid']}/config")
                return {k: (mask(v) if isinstance(v, str) and re.fullmatch(r"(net|ipconfig)\d+", k) else describe(v, k)) for k, v in cfg.items()}

            step(f"{kind}_config", read_config, lambda v: v)
    try:
        inventory = client.inventory()
        report["result"] = {
            "nodes": len(inventory["nodes"]), "nodes_with_ip": sum(1 for n in inventory["nodes"] if n.get("ip")),
            "guests": len(inventory["guests"]), "by_kind": {k: sum(1 for g in inventory["guests"] if g["kind"] == k) for k in ("qemu", "lxc")},
            "guests_with_mac": sum(1 for g in inventory["guests"] if g["macs"]), "guests_with_ip": sum(1 for g in inventory["guests"] if g["ips"]),
        }
    except Exception as exc:  # noqa: BLE001
        report["error"] = problem(exc)
    return report


def power(config: dict, payload: dict) -> dict:
    """Reset, reboot, shut down or start one guest. payload: {"guest_id": "101", "host": "pve1", "action": "reset"}. Does not wait for the task to end."""
    action = payload.get("action")
    if action not in ("reset", "reboot", "shutdown", "start"):
        raise ValueError(f"unknown action {action!r}")
    vmid = str(payload.get("guest_id") or "").split("/")[-1]
    node = payload.get("host") or ""
    if not vmid.isdigit():
        raise ValueError("this guest has no Proxmox number")
    problems = []
    for one in _servers(config):
        client = _client(one)
        try:
            found = [g for g in client.get("/cluster/resources?type=vm") if str(g.get("vmid")) == vmid and g.get("type") in ("qemu", "lxc") and (not node or g.get("node") == node)]
        except ProxmoxError as exc:
            problems.append(str(exc))
            continue
        if not found:
            continue
        guest = found[0]
        if action == "start" and guest.get("status") == "running":
            return {"message": f"{guest.get('name') or vmid} is already running"}
        verb = "reboot" if action == "reset" and guest["type"] == "lxc" else action      # a container has no reset button
        fields = {"timeout": "60", "forceStop": "1"} if verb == "shutdown" else {}
        client.post(f"/nodes/{guest['node']}/{guest['type']}/{int(guest['vmid'])}/status/{verb}", fields)
        return {"message": f"{verb} sent to {guest.get('name') or vmid} on {guest['node']}"}
    raise ProxmoxError(problems[0] if problems else f"guest {vmid} was not found on any configured Proxmox server")
