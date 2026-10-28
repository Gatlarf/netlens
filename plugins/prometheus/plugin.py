"""Prometheus plugin (kind "metrics"): the readings of hosts that a Prometheus-compatible store already holds, for hosts that cannot be probed.

Prometheus, VictoriaMetrics, Mimir and Thanos answer the same HTTP API. The plugin asks for the processor, memory, swap, disks, network traffic, load and uptime of the
hosts that `node_exporter` (Linux, BSD, macOS) and `windows_exporter` report, with fixed queries (nothing the administrator types ends up in a query except a job name,
which is checked character by character). Read-only: only GET requests to /api/v1. Netlens sends nothing to the hosts.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import time
import urllib.parse
from typing import Any, Callable


# ----------------------------------------------------------------------------- diagnostic helpers
KEEP_WORDS = {"status", "resultType", "version", "mode", "fstype", "device", "state", "errorType"}
MAC_RE = re.compile(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def describe(value: Any, key: str = "") -> Any:
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and not isinstance(value, (dict, list)):
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}>"
    if isinstance(value, str):
        if IPV4_RE.match(value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def _problem(exc: Exception, server: Any = None) -> str:
    """An error text without addresses: URLs, host:port, the configured host names and IPv4 addresses are removed."""
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
class PromError(Exception):
    """Human-readable failure talking to the metrics store."""


class PromAuthError(PromError):
    auth_failed = True      # Netlens stops calling the plugin until the settings are saved again


Transport = Callable[[str, str, dict, bytes | None], tuple[int, bytes]]
MAX_RESPONSE = 30_000_000


def normalize_base(host: str, allow_http: bool = False) -> str:
    """https://host[:port][/prefix] without a trailing slash. A bare address means HTTPS. Plain http would send a token or password unencrypted, so it is refused
    unless the plugin setting 'Allow plain http' is on (a lab, or a store on the same machine)."""
    host = (host or "").strip().rstrip("/")
    if not host:
        raise ValueError("enter the address of the Prometheus, for example https://prometheus.example.com:9090")
    if "://" not in host:
        host = "https://" + host
    parsed = urllib.parse.urlparse(host)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("the address must look like https://prometheus.example.com:9090")
    if parsed.query or parsed.fragment:
        raise ValueError("the address must not contain a query")
    if parsed.scheme == "http" and not allow_http:
        raise ValueError("an address that starts with http:// would send the login unencrypted; use https://, or switch on 'Allow plain http' for a lab")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


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
                raise PromError(f"the certificate of {label} does not match the fingerprint; nothing was sent")
            conn.request(method, parts.path + (f"?{parts.query}" if parts.query else ""), body=data, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(MAX_RESPONSE)
        except ssl.SSLCertVerificationError as exc:
            raise PromError("the TLS certificate could not be verified: fill in its fingerprint, or turn off 'Verify TLS certificate' for a self-signed one") from exc
        except ssl.SSLError as exc:
            raise PromError(f"cannot make a secure connection to {label}: {exc.reason or exc}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise PromError(f"connection to {label} timed out") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise PromError(f"cannot connect to {label}: {exc}") from exc
        finally:
            conn.close()

    return send


TRANSPORT_FACTORY = make_transport      # replaced by tests


# ----------------------------------------------------------------------------- the queries (fixed; the only variable part is a checked job name)
JOB_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SKIP_FS = "tmpfs|overlay|squashfs|ramfs|devtmpfs|iso9660|proc|sysfs|cgroup.*|fuse.*|nsfs|autofs|tracefs|debugfs|securityfs|pstore|efivarfs|configfs|mqueue|hugetlbfs|bpf"
SKIP_NIC = "lo|veth.*|docker.*|br-.*|virbr.*|tap.*|cali.*|flannel.*|cni.*"
SKIP_WIN_NIC = ".*(Loopback|isatap|Teredo|6to4|vEthernet).*"
MIN_DISK = 64 * 1024 * 1024
MAX_DISKS, MAX_NICS = 40, 20

# (metric, label key, PromQL). @J@ is replaced by `,job=~"a|b"` (or nothing) inside a selector that already has matchers, @K@ by `job=~"a|b"` (or nothing).
QUERIES: list[tuple[str, str, str]] = [
    # node_exporter (Linux, BSD, macOS)
    ("cpu_pct", "", '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"@J@}[2m])) * 100)'),
    ("load1", "", "node_load1{@K@}"),
    ("mem_pct", "", "100 * (1 - node_memory_MemAvailable_bytes{@K@} / node_memory_MemTotal_bytes{@K@})"),
    ("swap_pct", "", "100 * (1 - node_memory_SwapFree_bytes{@K@} / node_memory_SwapTotal_bytes{@K@}) and node_memory_SwapTotal_bytes{@K@} > 0"),
    ("disk_pct", "mountpoint", '100 * (1 - node_filesystem_avail_bytes{fstype!~"%s"@J@} / node_filesystem_size_bytes{fstype!~"%s"@J@}) and node_filesystem_size_bytes{fstype!~"%s"@J@} > %d' % (SKIP_FS, SKIP_FS, SKIP_FS, MIN_DISK)),
    ("disk_free_b", "mountpoint", 'node_filesystem_avail_bytes{fstype!~"%s"@J@} and node_filesystem_size_bytes{fstype!~"%s"@J@} > %d' % (SKIP_FS, SKIP_FS, MIN_DISK)),
    ("net_rx_bps", "device", 'rate(node_network_receive_bytes_total{device!~"%s"@J@}[2m]) * 8' % SKIP_NIC),
    ("net_tx_bps", "device", 'rate(node_network_transmit_bytes_total{device!~"%s"@J@}[2m]) * 8' % SKIP_NIC),
    ("uptime_s", "", "time() - node_boot_time_seconds{@K@}"),
    # windows_exporter
    ("cpu_pct", "", '100 - (avg by (instance) (rate(windows_cpu_time_total{mode="idle"@J@}[2m])) * 100)'),
    ("mem_pct", "", "100 * (1 - windows_os_physical_memory_free_bytes{@K@} / windows_cs_physical_memory_bytes{@K@})"),
    ("disk_pct", "volume", '100 * (1 - windows_logical_disk_free_bytes{volume!~"HarddiskVolume.*"@J@} / windows_logical_disk_size_bytes{volume!~"HarddiskVolume.*"@J@})'),
    ("disk_free_b", "volume", 'windows_logical_disk_free_bytes{volume!~"HarddiskVolume.*"@J@}'),
    ("net_rx_bps", "nic", 'rate(windows_net_bytes_received_total{nic!~"%s"@J@}[2m]) * 8' % SKIP_WIN_NIC),
    ("net_tx_bps", "nic", 'rate(windows_net_bytes_sent_total{nic!~"%s"@J@}[2m]) * 8' % SKIP_WIN_NIC),
    ("uptime_s", "", "time() - (windows_system_boot_time_timestamp_seconds{@K@} or windows_system_boot_time_timestamp{@K@})"),
]
NAME_QUERIES = [("nodename", 'node_uname_info{@K@}'), ("hostname", 'windows_cs_hostname{@K@}')]
LIMITS = {"disk_pct": MAX_DISKS, "disk_free_b": MAX_DISKS, "net_rx_bps": MAX_NICS, "net_tx_bps": MAX_NICS}


def _job_selector(job: str) -> tuple[str, str]:
    """('@K@' text, '@J@' text) for a comma-separated list of job names, or ('', '') for none. A name may hold only letters, digits and _ . : - so it can never alter the query."""
    names = [j.strip() for j in re.split(r"[,\s]+", job or "") if j.strip()]
    if not names:
        return "", ""
    for n in names:
        if not JOB_RE.match(n):
            raise ValueError(f"the job name {n!r} may hold only letters, digits and _ . : - (up to 64 characters)")
    matcher = 'job=~"%s"' % "|".join(n.replace(".", "[.]") for n in names)          # a dot as [.]: a backslash would be an invalid escape inside a PromQL string
    return matcher, "," + matcher


def build_query(template: str, job: str) -> str:
    k, j = _job_selector(job)
    return template.replace("@J@", j).replace("@K@", k)


# ----------------------------------------------------------------------------- the client
class Prom:
    def __init__(self, base: str, headers: dict, send: Transport) -> None:
        self.base, self.headers, self.send = base, headers, send

    def get(self, path: str, params: dict | None = None) -> Any:
        url = self.base + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        status, body = self.send("GET", url, self.headers, None)
        if status in (401, 403):
            raise PromAuthError("the metrics store refused the login (check the token, or the user name and password)")
        try:
            doc = json.loads(body)
        except ValueError:
            raise PromError(f"the metrics store answered HTTP {status} without JSON (is this a Prometheus address?)") from None
        if status != 200 or not isinstance(doc, dict) or doc.get("status") != "success":
            detail = str(doc.get("error", ""))[:160] if isinstance(doc, dict) else ""
            raise PromError(f"the metrics store answered HTTP {status}" + (f": {detail}" if detail else ""))
        return doc.get("data")

    def version(self) -> str:
        try:
            data = self.get("/api/v1/status/buildinfo")
            if isinstance(data, dict) and data.get("version"):
                return f"Prometheus {str(data['version'])[:20]}"
        except PromAuthError:
            raise
        except PromError:
            pass
        self.get("/api/v1/query", {"query": "vector(1)"})          # VictoriaMetrics and others may not have buildinfo
        return "a Prometheus-compatible store"

    def query(self, promql: str, window: tuple[float, float, int] | None = None) -> list[dict]:
        """The series of a query: instant (newest value) or, with window=(start, end, step), a range. Each: {"labels": {...}, "values": [(ts, value)]}."""
        if window:
            data = self.get("/api/v1/query_range", {"query": promql, "start": f"{window[0]:.0f}", "end": f"{window[1]:.0f}", "step": str(window[2])})
        else:
            data = self.get("/api/v1/query", {"query": promql})
        result = data.get("result") if isinstance(data, dict) else None
        out = []
        for item in result if isinstance(result, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("metric"), dict):
                continue
            raw = item.get("values") if window else [item.get("value")]
            values = []
            for pair in raw if isinstance(raw, list) else []:
                if isinstance(pair, list) and len(pair) == 2:
                    try:
                        ts, v = float(pair[0]), float(pair[1])
                    except (TypeError, ValueError):
                        continue
                    if math.isfinite(ts) and math.isfinite(v):
                        values.append((ts, v))
            if values:
                out.append({"labels": {str(k): str(v) for k, v in item["metric"].items()}, "values": values})
        return out


# ----------------------------------------------------------------------------- settings
def _flag(config: dict, key: str, default: bool) -> bool:
    value = config.get(key, default)
    return value if isinstance(value, bool) else default


def _servers(config: dict) -> list[dict]:
    rows = config.get("servers")
    if not isinstance(rows, list):
        rows = []
    rows = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()]
    if not rows:
        raise ValueError("enter the address of the Prometheus")
    return rows


def _hosts(config: dict) -> list[str]:
    return [str(r.get("host") or "") for r in _servers(config)]


def _headers(row: dict) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "Netlens-prometheus-plugin"}
    token = str(row.get("token") or "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    elif row.get("username"):
        headers["Authorization"] = "Basic " + base64.b64encode(f"{row.get('username')}:{row.get('password') or ''}".encode()).decode()
    return headers


def _client(config: dict, row: dict) -> Prom:
    base = normalize_base(str(row.get("host")), _flag(config, "allow_http", False))
    label = re.sub(r"^https?://", "", base)
    send = TRANSPORT_FACTORY(_flag(config, "verify_tls", True), 30.0, label, str(row.get("fingerprint") or ""))
    return Prom(base, _headers(row), send)


def _each(config: dict, fn: Callable[[Prom], Any]) -> list[Any]:
    out = []
    for row in _servers(config):
        out.append(fn(_client(config, row)))
    return out


def _number(config: dict, key: str, default: int, low: int, high: int) -> int:
    value = config.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(low, min(high, int(value)))


# ----------------------------------------------------------------------------- the readings
def _ip_of(instance: str) -> str | None:
    host = instance.rsplit(":", 1)[0] if instance.count(":") == 1 else instance.strip("[]")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not (addr.is_loopback or addr.is_link_local or addr.is_unspecified) else None


def collect(client: Prom, config: dict, now: float | None = None, prefix: str = "") -> list[dict]:
    """The hosts of the store with their readings, in the output format of kind "metrics"."""
    now = now if now is not None else time.time()
    job = str(config.get("job") or "")
    history = _number(config, "history_minutes", 20, 0, 120)
    step = _number(config, "step", 60, 15, 600)
    window = (now - history * 60, now, step) if history else None
    max_hosts = _number(config, "max_hosts", 500, 1, 2000)
    names: dict[str, str] = {}
    for label, template in NAME_QUERIES:
        for series in client.query(build_query(template, job)):
            inst, name = series["labels"].get("instance"), series["labels"].get(label)
            if inst and name:
                names.setdefault(inst, name.strip())
    hosts: dict[str, dict] = {}
    seen: dict[tuple, int] = {}
    for metric, label_key, template in QUERIES:
        for series in client.query(build_query(template, job), window):
            inst = series["labels"].get("instance")
            if not inst:
                continue
            if inst not in hosts:
                if len(hosts) >= max_hosts:
                    continue
                hosts[inst] = {"id": (prefix + inst)[:120], "name": names.get(inst) or inst.rsplit(":", 1)[0], "ip": _ip_of(inst), "readings": []}
            label = series["labels"].get(label_key, "") if label_key else ""
            if label_key and not label:
                continue
            count = seen.get((inst, metric), 0)
            if count >= LIMITS.get(metric, 1):
                continue
            if any(r["metric"] == metric and r["label"] == label for r in hosts[inst]["readings"]):
                continue                                       # a host that two exporter families both answer: the first wins
            seen[(inst, metric)] = count + 1
            values = series["values"]
            reading = {"metric": metric, "label": label[:40], "value": values[-1][1]}
            if window:
                reading["samples"] = [[int(ts), v] for ts, v in values][-240:]
            hosts[inst]["readings"].append(reading)
    return [h for h in hosts.values() if h["readings"]]


# ----------------------------------------------------------------------------- the plugin interface
def _check(config: dict) -> None:
    """Refuse a bad setting before anything is sent."""
    _servers(config)
    _job_selector(str(config.get("job") or ""))


def test(config: dict) -> dict:
    _check(config)

    def one(client: Prom) -> str:
        what = client.version()
        job = str(config.get("job") or "")
        counts = []
        for label, template in (("Linux", "count(node_uname_info{@K@})"), ("Windows", "count(windows_cs_hostname{@K@})")):
            series = client.query(build_query(template, job))
            if series:
                counts.append(f"{int(series[0]['values'][-1][1])} {label} host(s)")
        return f"Connected to {what}: " + (", ".join(counts) if counts else "no node_exporter or windows_exporter hosts found (is the job name right?)")

    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} servers answered. " + " | ".join(messages)}


def fetch(config: dict) -> dict:
    _check(config)
    rows = _servers(config)
    hosts: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        client = _client(config, row)
        prefix = f"{row.get('id')}/" if len(rows) > 1 and row.get("id") else ""
        for h in collect(client, config, prefix=prefix):
            if h["id"] not in seen:
                seen.add(h["id"])
                hosts.append(h)
    return {"hosts": hosts}


def diagnose(config: dict) -> dict:
    """What this store answers, described by field names and types (no names, addresses or labels), for the plugin's author."""
    _check(config)
    hosts = _hosts(config)
    row = _servers(config)[0]
    report: dict = {"steps": {}}
    step = make_step(report, hosts)
    client = step("connect", lambda: _client(config, row), lambda c: {"ok": True})
    if client is None:
        return report
    step("version", client.version, lambda v: {"text": v.split(" ")[0]})
    job = str(config.get("job") or "")
    for name, template in (("linux_hosts", "count(node_uname_info{@K@})"), ("windows_hosts", "count(windows_cs_hostname{@K@})"), ("up", "count(up{@K@})")):
        step(name, lambda template=template: client.query(build_query(template, job)), lambda v: {"series": len(v), "value": (v[0]["values"][-1][1] if v else None)})
    try:
        found = collect(client, config)
        per: dict[str, int] = {}
        for h in found:
            for r in h["readings"]:
                per[r["metric"]] = per.get(r["metric"], 0) + 1
        report["result"] = {"hosts": len(found), "hosts_with_ip": sum(1 for h in found if h["ip"]), "readings": sum(per.values()), "readings_per_metric": per,
                            "readings_with_history": sum(1 for h in found for r in h["readings"] if r.get("samples"))}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, hosts)
    return report
