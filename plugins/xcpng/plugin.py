"""XCP-ng / XenServer / Xen Orchestra plugin: hosts, VMs and storage of Xen pools (read-only; power actions only when asked).

Two ways in, chosen by itself for every address:
- a **Xen Orchestra** (XO, the management server of Vates VMS): the REST API under /rest/v0, one login for every pool XO manages;
- a **pool master** (XCP-ng or XenServer): the XAPI over JSON-RPC at /jsonrpc, no XO needed.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.parse
from typing import Any, Callable


# ----------------------------------------------------------------------------- diagnostic helpers
KEEP_WORDS = {"type", "status", "state", "power_state", "online", "template", "kind", "version", "release", "role", "model", "SR_type",
              "content_type", "virtualizationMode", "domain_type", "productBrand", "product_brand", "product_version", "mode", "status"}
MAC_RE = re.compile(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SAMPLES = 3


def describe(value: Any, key: str = "") -> Any:
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        macs = [k for k in value if isinstance(k, str) and MAC_RE.match(k)]
        out = {k: describe(v, k) for k, v in value.items() if k not in macs}
        if macs:
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
            return "<mac>"
        if IPV4_RE.match(value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def _problem(exc: Exception, server: Any = None) -> str:
    """An error text without addresses: URLs, host:port, the host names of the configured servers and IPv4 addresses are removed.
    `server` is a host text, a list of them, or an object with `host` / `id`."""
    names: list[str] = []
    for item in server if isinstance(server, (list, tuple)) else [server]:
        names += [str(getattr(item, a, "") or "") for a in ("host", "id")] if item is not None and not isinstance(item, str) else [str(item or "")]
    text = re.sub(r"https?://\S+", "<url>", str(exc))
    for name in sorted({n for n in names if n}, key=len, reverse=True):
        bare = re.sub(r"^https?://", "", name).split("/")[0]
        for part in sorted({bare, bare.rsplit(":", 1)[0] if bare.count(":") == 1 else bare}, key=len, reverse=True):
            if part:
                text = text.replace(part, "<server>")
    text = re.sub(r"<server>:\d+", "<server>", text)
    text = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<ipv4>", text)
    return type(exc).__name__ + ": " + text[:300]


def make_step(report: dict, hosts: list[str]) -> Callable[..., Any]:
    def step(name: str, call: Callable[[], Any], shape: Callable[[Any], Any] = describe) -> Any:
        try:
            raw = call()
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc, hosts)}
            return None
        report["steps"][name] = {"ok": True, "shape": shape(raw)}
        return raw

    return step


# ----------------------------------------------------------------------------- errors and transport
class XenError(Exception):
    """Human-readable failure talking to XO or XAPI."""


class XenAuthError(XenError):
    auth_failed = True      # Netlens stops calling the plugin until the settings are saved again


Transport = Callable[[str, str, dict, bytes | None], tuple[int, bytes]]


def normalize_base(host: str, allow_http: bool = False) -> str:
    """https://host[:port] without a path. A bare address means HTTPS on the default port. Plain http would send the password or token
    unencrypted, so it is refused unless the plugin setting 'Allow plain http' is on (for a lab)."""
    host = (host or "").strip().rstrip("/")
    if not host:
        raise ValueError("enter the address of the Xen Orchestra, or of the pool master")
    if "://" not in host:
        host = "https://" + host
    parsed = urllib.parse.urlparse(host)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("the address must look like https://192.168.0.10")
    if parsed.scheme == "http" and not allow_http:
        raise ValueError("an address that starts with http:// would send the login unencrypted; use https://, or switch on 'Allow plain http' for a lab")
    return f"{parsed.scheme}://{parsed.netloc}"


def make_transport(verify_tls: bool, timeout: float, label: str, fingerprint: str = "") -> Transport:
    """One request per call. With a fingerprint, exactly that certificate is trusted (also a self-signed one) and nothing is sent to another."""
    pin = re.sub(r"[^0-9a-f]", "", (fingerprint or "").lower())
    if fingerprint and len(pin) != 64:
        raise ValueError("the certificate fingerprint must be 64 hexadecimal digits (SHA-256)")
    ctx = ssl.create_default_context()
    if pin or not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def send(method: str, url: str, headers: dict, data: bytes | None) -> tuple[int, bytes]:
        parts = urllib.parse.urlsplit(url)
        secure = parts.scheme == "https"
        conn = (http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout, context=ctx) if secure
                else http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout))
        try:
            conn.connect()
            if pin and secure and hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != pin:
                raise XenError(f"the certificate of {label} does not match the fingerprint; nothing was sent")
            conn.request(method, parts.path + (f"?{parts.query}" if parts.query else ""), body=data, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(50_000_000)
        except ssl.SSLCertVerificationError as exc:
            raise XenError("the TLS certificate could not be verified; XCP-ng and Xen Orchestra use a self-signed certificate by default: "
                           "fill in its fingerprint, or turn off 'Verify TLS certificate'") from exc
        except ssl.SSLError as exc:
            raise XenError(f"cannot make a secure connection to {label}: {exc.reason or exc}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise XenError(f"connection to {label} timed out") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise XenError(f"cannot connect to {label}: {exc}") from exc
        finally:
            conn.close()

    return send


def _ipv4(value: Any) -> str | None:
    try:
        addr = ipaddress.ip_address(str(value).split("/")[0].strip())
    except ValueError:
        return None
    if addr.version != 4 or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return None
    return str(addr)


def _mac(value: Any) -> str | None:
    value = str(value or "").strip().lower()
    return value if MAC_RE.match(value) and value != "00:00:00:00:00:00" else None


def _gb(size: Any) -> int | None:
    return int(size / 1073741824) if isinstance(size, (int, float)) and size > 0 else None


def _int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _epoch(stamp: Any) -> int | None:
    """XAPI times look like 20261028T17:23:38Z (UTC); the beginning of 1970 means 'never'."""
    from datetime import datetime, timezone
    try:
        value = datetime.strptime(str(stamp), "%Y%m%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(value.timestamp()) if value.year > 1970 else None


STATUS = {"running": "running", "halted": "stopped", "suspended": "paused", "paused": "paused"}


def _status(value: Any) -> str:
    return STATUS.get(str(value or "").lower(), "unknown")


def _single_host_of(pool: Any, hosts: list[dict]) -> str | None:
    """A VM that is not running has no host. In a pool with one host it can only belong to that one."""
    mine = [h["id"] for h in hosts if h.get("pool") == pool]
    return mine[0] if len(mine) == 1 else None


def _storage(pools: list[dict], hosts: list[dict], srs: list[dict]) -> dict:
    """The storage repositories of the pools in the shape of the storage contract (one system per pool, one pool per repository)."""
    systems, store = [], []
    for p in pools:
        master = next((h for h in hosts if h["id"] == p.get("master")), None) or next((h for h in hosts if h.get("pool") == p["id"]), {})
        systems.append({"id": p["id"], "name": p["name"], "ip": master.get("ip"), "vendor": master.get("brand") or "Xen",
                        "model": "Xen pool", "version": master.get("version"), "online": True, "health": "ok"})
    known = {p["id"] for p in pools}
    for sr in srs:
        if sr.get("pool") not in known or not sr.get("size") or sr["size"] <= 0:
            continue
        used = max(0, sr.get("used") or 0)
        store.append({"id": sr["id"], "system_id": sr["pool"], "name": sr["name"], "total": sr["size"], "used": used,
                      "avail": max(0, sr["size"] - used), "health": "ok", "raid": ("shared " if sr.get("shared") else "") + str(sr.get("type") or "")})
    return {"systems": systems, "pools": store} if store else {}


# ----------------------------------------------------------------------------- Xen Orchestra (REST)
class XoClient:
    """Xen Orchestra, REST API v0. Login: an authentication token (cookie) or a user name and password (Basic)."""

    mode = "xo"

    def __init__(self, base: str, row: dict, transport: Transport):
        self.base, self._send = base + "/rest/v0", transport
        token, user, password = (row.get("token") or "").strip(), row.get("username") or "", row.get("password") or ""
        if token:
            self.headers = {"Cookie": f"authenticationToken={token}"}
        elif user and password:
            self.headers = {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}
        else:
            raise ValueError("Xen Orchestra needs an authentication token, or a user name and password")

    def get(self, path: str, fields: str = "", **query: Any) -> Any:
        params = {"limit": "100000", **{k: str(v) for k, v in query.items()}}
        if fields:
            params["fields"] = fields
        url = f"{self.base}/{path}?{urllib.parse.urlencode(params)}"
        status, raw = self._send("GET", url, {**self.headers, "Accept": "application/json"}, None)
        if status in (401, 403):
            raise XenAuthError("Xen Orchestra refused the login or the account may not read this" if status == 401 else "this Xen Orchestra account may not read that (it needs a read-only role on the pools)")
        if status >= 400:
            raise XenError(f"Xen Orchestra returned HTTP {status} for {path}")
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise XenError("unexpected answer from Xen Orchestra (is this its address?)") from exc

    def post(self, path: str) -> None:
        status, raw = self._send("POST", f"{self.base}/{path}", {**self.headers, "Accept": "application/json", "Content-Type": "application/json"}, b"{}")
        if status in (401, 403):
            raise XenError("this Xen Orchestra account may not do that (power actions need an operator or admin role)")
        if status >= 400:
            raise XenError(f"Xen Orchestra returned HTTP {status}")

    def version(self) -> str:
        self.get("ping")
        return "Xen Orchestra"

    def inventory(self) -> dict:
        pools_raw = self.get("pools", "id,name_label,master")
        hosts_raw = self.get("hosts", "id,name_label,address,power_state,productBrand,version,$pool,startTime,rebootRequired")
        pifs = {p.get("$host"): p for p in self.get("pifs", "mac,management,ip,$host") if p.get("management")}
        hosts = [{"id": h["id"], "name": h.get("name_label") or h["id"], "ip": _ipv4(h.get("address")) or _ipv4((pifs.get(h["id"]) or {}).get("ip")),
                  "mac": _mac((pifs.get(h["id"]) or {}).get("mac")), "online": str(h.get("power_state")) == "Running",
                  "version": h.get("version"), "brand": h.get("productBrand"), "pool": h.get("$pool")} for h in hosts_raw]
        macs: dict[str, list[str]] = {}
        for v in self.get("vifs", "MAC,$VM"):
            mac = _mac(v.get("MAC"))
            if mac and mac not in macs.setdefault(v.get("$VM"), []):
                macs[v.get("$VM")].append(mac)
        disks: dict[str, int] = {}
        vdi_size = {d["id"]: d.get("size") for d in self.get("vdis", "id,size")}
        for b in self.get("vbds", "VM,VDI,is_cd_drive"):
            if not b.get("is_cd_drive") and vdi_size.get(b.get("VDI")):
                disks[b.get("VM")] = disks.get(b.get("VM"), 0) + vdi_size[b["VDI"]]
        guests = []
        for v in self.get("vms", "id,name_label,power_state,addresses,mainIpAddress,$container,$pool,CPUs,memory,os_version,tags,startTime,auto_poweron,virtualizationMode"):
            ips = []
            for value in [v.get("mainIpAddress"), *(v.get("addresses") or {}).values()]:
                ip = _ipv4(value)
                if ip and ip not in ips:
                    ips.append(ip)
            host = v.get("$container") if any(h["id"] == v.get("$container") for h in hosts) else None
            os_name = (v.get("os_version") or {}).get("name") if isinstance(v.get("os_version"), dict) else None
            guests.append({"id": v["id"], "name": v.get("name_label") or v["id"], "kind": v.get("virtualizationMode") or "vm", "pool": v.get("$pool"),
                           "host": host, "status": _status(v.get("power_state")), "macs": macs.get(v["id"], []), "ips": ips,
                           "cpus": (v.get("CPUs") or {}).get("number"), "memory": (v.get("memory") or {}).get("size"), "disk": disks.get(v["id"]),
                           "os": os_name, "tags": ", ".join(str(t) for t in v.get("tags") or []), "autostart": v.get("auto_poweron"), "started": v.get("startTime")})
        srs = [{"id": s["id"], "name": s.get("name_label") or s["id"], "pool": s.get("$pool"), "size": s.get("size"), "used": s.get("physical_usage") or s.get("usage"),
                "shared": bool(s.get("shared")), "type": s.get("SR_type"), "content": s.get("content_type")}
               for s in self.get("srs", "id,name_label,$pool,size,usage,physical_usage,shared,SR_type,content_type") if s.get("content_type") in ("user", None, "")]
        pools = [{"id": p["id"], "name": p.get("name_label") or p["id"], "master": p.get("master")} for p in pools_raw]
        return {"pools": pools, "hosts": hosts, "guests": guests, "srs": srs}

    def power(self, guest_id: str, action: str) -> str:
        verb = {"reset": "hard_reboot", "reboot": "clean_reboot", "shutdown": "clean_shutdown", "start": "start"}[action]
        self.post(f"vms/{urllib.parse.quote(guest_id)}/actions/{verb}")
        return verb

    def guest(self, guest_id: str) -> dict | None:
        try:
            return self.get(f"vms/{urllib.parse.quote(guest_id)}", "id,name_label,power_state")
        except XenError:
            return None


# ----------------------------------------------------------------------------- XAPI (JSON-RPC)
NULL_REF = "OpaqueRef:NULL"


class XapiClient:
    """A pool master (XCP-ng or XenServer): XAPI over JSON-RPC at /jsonrpc. The session is closed again after every sync."""

    mode = "xapi"

    def __init__(self, base: str, row: dict, transport: Transport):
        self.url, self._send, self.session = base + "/jsonrpc", transport, None
        self.user, self.password = row.get("username") or "", row.get("password") or ""
        if not (self.user and self.password):
            raise ValueError("a pool master needs a user name and password (a read-only user, or root)")
        self._id = 0

    def _rpc(self, method: str, params: list) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}).encode()
        status, raw = self._send("POST", self.url, {"Content-Type": "application/json", "Accept": "application/json"}, body)
        if status == 404:
            raise XenError("this address is neither a Xen Orchestra nor a XenServer / XCP-ng pool master (no /rest/v0 and no /jsonrpc)")
        if status >= 400:
            raise XenError(f"XAPI returned HTTP {status}")
        try:
            answer = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise XenError("unexpected answer from XAPI (is this the pool master?)") from exc
        error = answer.get("error") if isinstance(answer, dict) else None
        if error:
            message = str(error.get("message") if isinstance(error, dict) else error)
            if "AUTHENTICATION" in message:
                raise XenAuthError("XAPI refused the user name or password")
            if "HOST_IS_SLAVE" in message:
                raise XenError("this host is not the pool master; use the address of the master")
            if "VM_LACKS_FEATURE" in message:
                raise XenError("this VM has no Xen guest tools, so it cannot be asked to reboot or shut down cleanly; install the tools, or use reset")
            if "PERMISSION_DENIED" in message or "RBAC" in message:
                raise XenError("this XAPI account may not do that (it needs at least the read-only role, and the VM operator role for power actions)")
            raise XenError("XAPI error: " + message[:200])
        return answer.get("result") if isinstance(answer, dict) else None

    def login(self) -> None:
        if self.session is None:
            self.session = self._rpc("session.login_with_password", [self.user, self.password, "1.0", "netlens"])

    def close(self) -> None:
        if self.session:
            try:
                self._rpc("session.logout", [self.session])
            except XenError:
                pass
            self.session = None

    def call(self, method: str, *args: Any) -> Any:
        self.login()
        return self._rpc(method, [self.session, *args])

    def version(self) -> str:
        hosts = self.call("host.get_all_records") or {}
        first = next(iter(hosts.values()), {})
        soft = first.get("software_version") or {}
        return f"{soft.get('product_brand') or 'Xen'} {soft.get('product_version') or ''}".strip()

    def inventory(self) -> dict:
        try:
            return self._inventory()
        finally:
            self.close()

    def _inventory(self) -> dict:
        pool_raw = self.call("pool.get_all_records") or {}
        pools = []
        for ref, p in pool_raw.items():
            pools.append({"id": p["uuid"], "name": p.get("name_label") or p["uuid"], "master": None, "master_ref": p.get("master")})
        pool_id = pools[0]["id"] if pools else None
        host_raw = self.call("host.get_all_records") or {}
        metrics = self.call("host_metrics.get_all_records") or {}
        pifs = [p for p in (self.call("PIF.get_all_records") or {}).values() if p.get("management")]
        hosts, host_uuid = [], {}
        for ref, h in host_raw.items():
            host_uuid[ref] = h["uuid"]
            soft = h.get("software_version") or {}
            pif = next((p for p in pifs if p.get("host") == ref), {})
            live = (metrics.get(h.get("metrics")) or {}).get("live", True)
            hosts.append({"id": h["uuid"], "name": h.get("name_label") or h["uuid"], "ip": _ipv4(h.get("address")) or _ipv4(pif.get("IP")), "mac": _mac(pif.get("MAC")),
                          "online": bool(live), "version": soft.get("product_version"), "brand": soft.get("product_brand"), "pool": pool_id})
        for p in pools:
            p["master"] = host_uuid.get(p.pop("master_ref"))
            if p["name"] == p["id"]:     # an unnamed pool (the XCP-ng default) is called after its master, as Xen Orchestra does
                p["name"] = next((h["name"] for h in hosts if h["id"] == p["master"]), p["name"])
        vif_macs: dict[str, list[str]] = {}
        for v in (self.call("VIF.get_all_records") or {}).values():
            mac = _mac(v.get("MAC"))
            if mac and mac not in vif_macs.setdefault(v.get("VM"), []):
                vif_macs[v.get("VM")].append(mac)
        guest_metrics = self.call("VM_guest_metrics.get_all_records") or {}
        vm_metrics = self.call("VM_metrics.get_all_records") or {}
        vdi = {r: d.get("virtual_size") for r, d in (self.call("VDI.get_all_records") or {}).items()}
        disks: dict[str, int] = {}
        for b in (self.call("VBD.get_all_records") or {}).values():
            size = _int(vdi.get(b.get("VDI")))
            if b.get("type") == "Disk" and size and size > 0:
                disks[b.get("VM")] = disks.get(b.get("VM"), 0) + size
        guests = []
        for ref, v in (self.call("VM.get_all_records") or {}).items():
            if v.get("is_a_template") or v.get("is_a_snapshot") or v.get("is_control_domain"):
                continue
            gm = guest_metrics.get(v.get("guest_metrics")) or {}
            ips = []
            for value in (gm.get("networks") or {}).values():
                ip = _ipv4(value)
                if ip and ip not in ips:
                    ips.append(ip)
            power = _status(v.get("power_state"))
            host = host_uuid.get(v.get("resident_on")) if v.get("resident_on") != NULL_REF else None
            if host is None and v.get("affinity") != NULL_REF:
                host = host_uuid.get(v.get("affinity"))
            if host is None and power != "running":
                host = _single_host_of(pool_id, hosts)
            guests.append({"id": v["uuid"], "name": v.get("name_label") or v["uuid"], "kind": v.get("domain_type") or "vm", "pool": pool_id, "host": host,
                           "status": power, "macs": vif_macs.get(ref, []), "ips": ips, "cpus": _int(v.get("VCPUs_max")), "memory": _int(v.get("memory_static_max")),
                           "disk": disks.get(ref), "os": (gm.get("os_version") or {}).get("name"), "tags": ", ".join(str(t) for t in v.get("tags") or []),
                           "autostart": str((v.get("other_config") or {}).get("auto_poweron", "")).lower() == "true" or None,
                           "started": _epoch((vm_metrics.get(v.get("metrics")) or {}).get("start_time")) if power == "running" else None})
        srs = []
        for ref, s in (self.call("SR.get_all_records") or {}).items():
            if s.get("content_type") not in ("user", ""):
                continue
            size = _int(s.get("physical_size"))
            srs.append({"id": s["uuid"], "name": s.get("name_label") or s["uuid"], "pool": pool_id, "size": size,
                        "used": _int(s.get("physical_utilisation")), "shared": bool(s.get("shared")), "type": s.get("type"), "content": s.get("content_type")})
        return {"pools": pools, "hosts": hosts, "guests": guests, "srs": srs}

    def power(self, guest_id: str, action: str) -> str:
        verb = {"reset": "hard_reboot", "reboot": "clean_reboot", "shutdown": "clean_shutdown", "start": "start"}[action]
        try:
            ref = self.call("VM.get_by_uuid", guest_id)
            if verb == "start":
                self.call("VM.start", ref, False, False)
            else:
                self.call(f"VM.{verb}", ref)
        finally:
            self.close()
        return verb

    def guest(self, guest_id: str) -> dict | None:
        try:
            ref = self.call("VM.get_by_uuid", guest_id)
            return {"id": guest_id, "name_label": self.call("VM.get_name_label", ref), "power_state": self.call("VM.get_power_state", ref)}
        except XenError:
            return None
        finally:
            self.close()


# ----------------------------------------------------------------------------- plugin entry points
TIMEOUT = 20.0
TRANSPORT_FACTORY = make_transport      # replaced by tests


def _servers(config: dict) -> list[dict]:
    rows = [r for r in config.get("servers") or [] if isinstance(r, dict) and r.get("host")]
    if not rows:
        raise ValueError("enter the address of at least one Xen Orchestra or pool master")
    return rows


def _hosts(config: dict) -> list[str]:
    return [str(r.get("host") or "") for r in config.get("servers") or [] if isinstance(r, dict)]


def _client(config: dict, row: dict):
    base = normalize_base(row.get("host", ""), bool(config.get("allow_http")))
    send = TRANSPORT_FACTORY(bool(config.get("verify_tls", True)), TIMEOUT, base, row.get("fingerprint") or "")
    status, raw = send("GET", base + "/rest/v0/ping", {"Accept": "application/json"}, None)
    is_xo = status == 200 and b"pong" in raw
    return (XoClient if is_xo else XapiClient)(base, row, send)


def _each(config: dict, work: Callable[[Any], Any]) -> list:
    rows, out = _servers(config), []
    for row in rows:
        client = _client(config, row)
        try:
            out.append(work(client))
        except Exception as exc:  # noqa: BLE001 - keeps its type (auth_failed); only the message names the server
            if len(rows) > 1 and exc.args:
                exc.args = (f"{row.get('host')}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return out


def test(config: dict) -> dict:
    def one(client) -> str:
        what = client.version()
        inv = client.inventory()
        via = "Xen Orchestra" if client.mode == "xo" else "pool master"
        return f"Connected to {what} ({via}): {len(inv['hosts'])} host(s), {len(inv['guests'])} VM(s)"

    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} servers answered. " + " | ".join(messages)}


def _details(g: dict) -> dict:
    started = None
    if isinstance(g.get("started"), (int, float)) and g["started"] > 0:
        from datetime import datetime, timezone
        started = datetime.fromtimestamp(g["started"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    memory = g.get("memory")
    details = {"cpus": g.get("cpus"), "memory_mb": int(memory / 1048576) if isinstance(memory, (int, float)) and memory > 0 else None,
               "disk_gb": _gb(g.get("disk")), "started": started, "tags": g.get("tags"), "os": g.get("os"), "autostart": g.get("autostart")}
    return {k: v for k, v in details.items() if v not in (None, "")}


def _output(inv: dict) -> dict:
    out = {
        "hosts": [{"id": h["id"], "name": h["name"], "ip": h.get("ip"), "mac": h.get("mac"), "online": h["online"]} for h in inv["hosts"]],
        "guests": [{"id": g["id"], "name": g["name"], "kind": g["kind"], "host_id": g.get("host"), "status": g["status"],
                    "macs": g["macs"], "ips": g["ips"], "details": _details(g)} for g in inv["guests"]],
    }
    storage = _storage(inv["pools"], inv["hosts"], inv["srs"])
    if storage:
        out["storage"] = storage
    return out


def fetch(config: dict) -> dict:
    parts = [_output(inv) for inv in _each(config, lambda c: c.inventory())]
    merged: dict = {"hosts": [], "guests": []}
    seen_hosts, seen_guests, seen_storage = set(), set(), {"systems": set(), "pools": set()}
    for part in parts:             # two servers may show the same pool (XO and the master): keep each id once
        for h in part["hosts"]:
            if h["id"] not in seen_hosts:
                seen_hosts.add(h["id"])
                merged["hosts"].append(h)
        for g in part["guests"]:
            if g["id"] not in seen_guests:
                seen_guests.add(g["id"])
                merged["guests"].append(g)
        for key in ("systems", "pools"):
            for item in (part.get("storage") or {}).get(key, []):
                if item["id"] not in seen_storage[key]:
                    seen_storage[key].add(item["id"])
                    merged.setdefault("storage", {}).setdefault(key, []).append(item)
    return merged


def diagnose(config: dict) -> dict:
    """What this server answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""
    hosts = _hosts(config)
    row = _servers(config)[0]
    report: dict = {"steps": {}}
    step = make_step(report, hosts)
    client = step("detect", lambda: _client(config, row), lambda c: {"mode": c.mode})
    if client is None:
        return report
    if client.mode == "xo":
        for name, path, fields in (("pools", "pools", ""), ("hosts", "hosts", ""), ("vms", "vms", ""), ("srs", "srs", ""), ("vifs", "vifs", "")):
            step(name, lambda path=path, fields=fields: client.get(path, fields or "*"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    else:
        for name in ("pool", "host", "SR", "VM", "VM_guest_metrics", "VIF", "PIF"):
            step(name, lambda name=name: client.call(f"{name}.get_all_records"),
                 lambda v: {"count": len(v), "first": [describe(x) for x in list(v.values())[:SAMPLES]]})
        client.close()
    try:
        inv = client.inventory()
        report["result"] = {"pools": len(inv["pools"]), "hosts": len(inv["hosts"]), "hosts_with_ip": sum(1 for h in inv["hosts"] if h.get("ip")),
                            "guests": len(inv["guests"]), "guests_running": sum(1 for g in inv["guests"] if g["status"] == "running"),
                            "guests_with_mac": sum(1 for g in inv["guests"] if g["macs"]), "guests_with_ip": sum(1 for g in inv["guests"] if g["ips"]),
                            "guests_without_host": sum(1 for g in inv["guests"] if not g.get("host")), "storage_repositories": len(inv["srs"])}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, hosts)
    return report


def power(config: dict, payload: dict) -> dict:
    """Reset (hard reboot), reboot, shut down or start one VM. payload: {"guest_id": "<uuid>", "action": "reset"}. Does not wait for the task to end."""
    action = payload.get("action")
    if action not in ("reset", "reboot", "shutdown", "start"):
        raise ValueError(f"unknown action {action!r}")
    guest_id = str(payload.get("guest_id") or "")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", guest_id):
        raise ValueError("this guest has no Xen identifier")
    problems = []
    for row in _servers(config):
        client = _client(config, row)
        try:
            found = client.guest(guest_id)
            if not found:
                continue
            state = _status(found.get("power_state"))
            if action == "start" and state == "running":
                return {"message": f"{found.get('name_label') or guest_id} is already running"}
            verb = client.power(guest_id, action)
            return {"message": f"{verb} sent to {found.get('name_label') or guest_id}"}
        except XenError as exc:
            problems.append(str(exc))
    raise XenError(problems[0] if problems else "the virtual machine was not found on any configured server")
