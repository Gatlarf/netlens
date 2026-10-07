"""Minimal read-only Proxmox VE API client (standard library only; blocking)."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from app.integrations.proxmox_config import ProxmoxConfig, normalize_url, uses_token

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
        return {"Cookie": f"PVEAuthCookie={self._ticket}"}

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
            guests.append({
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
