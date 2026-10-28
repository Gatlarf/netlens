"""Xen Orchestra backup plugin: what Xen Orchestra backs up (read-only).

For every virtual machine the newest backup, the copies kept and whether the last run worked, the backup repositories with their free
space and the recent failed runs. Netlens ties each backup to its VM by the VM's UUID (the id the XCP-ng / XenServer plugin uses).
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
import time
from datetime import datetime, timezone
import urllib.parse
from typing import Any, Callable


# ----------------------------------------------------------------------------- diagnostic helpers
KEEP_WORDS = {"type", "status", "state", "online", "kind", "version", "mode", "vmProtection", "enabled", "timezone"}
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


def _int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def stamp(ms: Any) -> str | None:
    """XO times are milliseconds since 1970 (a few places use seconds); Netlens wants UTC text."""
    value = _int(ms)
    if not value or value <= 0:
        return None
    if value < 10_000_000_000:       # seconds
        value *= 1000
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plain(text: Any, limit: int = 250) -> str:
    """One line without addresses: failure texts of XO may name a server or a path."""
    text = re.sub(r"https?://\S+", "<url>", str(text or ""))
    text = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<ipv4>", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


# ----------------------------------------------------------------------------- schedules
def _field_count(field: str, low: int, high: int) -> int:
    """How many values of a cron field (a list, ranges, */n) fall into low..high."""
    values: set[int] = set()
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, _, raw = part.partition("/")
            step = max(1, _int(raw) or 1)
        if part in ("*", ""):
            a, b = low, high
        elif "-" in part:
            a, _, b_raw = part.partition("-")
            a, b = _int(a), _int(b_raw)
            if a is None or b is None:
                continue
        else:
            a = _int(part)
            if a is None:
                continue
            b = a if step == 1 else high
        values.update(range(a, b + 1, step))
    return len({v for v in values if low <= v <= high}) or 1


def cron_interval(cron: str) -> int | None:
    """The usual number of seconds between two runs of a five-field cron schedule (an estimate: 'every 5 minutes', 'daily', 'weekly')."""
    fields = str(cron or "").split()
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = fields
    if dow not in ("*", "?"):
        return int(7 * 86400 / _field_count(dow, 0, 6))
    if dom not in ("*", "?"):
        return int(30 * 86400 / _field_count(dom, 1, 31))
    if hour == "*" or "/" in hour and hour.startswith("*"):
        per_hour = _field_count(minute, 0, 59)
        runs_per_day = _field_count(hour, 0, 23) * per_hour
        return int(86400 / runs_per_day)
    return int(86400 / (_field_count(hour, 0, 23) * _field_count(minute, 0, 59)))


# ----------------------------------------------------------------------------- Xen Orchestra
def _now() -> float:
    return time.time()


RUN_STATES = {"success": "ok", "failure": "failed", "interrupted": "failed", "skipped": "unknown", "pending": "unknown"}
MAX_VMS = 500                # one request per VM for its backup overview


class Xo:
    """Xen Orchestra, REST API v0 (GET only). Login: an authentication token (cookie) or a user name and password (Basic)."""

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
        params = {k: str(v) for k, v in query.items()}
        if fields:
            params["fields"] = fields
        url = f"{self.base}/{path}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        status, raw = self._send("GET", url, {**self.headers, "Accept": "application/json"}, None)
        if status == 401:
            raise XenAuthError("Xen Orchestra refused the login (wrong token, user name or password)")
        if status == 403:
            raise XenError("this Xen Orchestra account may not read that (it needs the right to see backups: an admin, or a role with read access to the jobs and repositories)")
        if status >= 400:
            raise XenError(f"Xen Orchestra returned HTTP {status} for {path.split('/')[0]}")
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise XenError("unexpected answer from Xen Orchestra (is this its address?)") from exc


TRANSPORT_FACTORY = make_transport      # replaced by tests
TIMEOUT = 30.0


def _servers(config: dict) -> list[dict]:
    rows = [r for r in config.get("servers") or [] if isinstance(r, dict) and r.get("host")]
    if not rows:
        raise ValueError("enter the address of at least one Xen Orchestra")
    return rows


def _hosts(config: dict) -> list[str]:
    return [str(r.get("host") or "") for r in config.get("servers") or [] if isinstance(r, dict)]


def _connect(config: dict, row: dict) -> tuple[Xo, str]:
    base = normalize_base(row.get("host", ""), bool(config.get("allow_http")))
    send = TRANSPORT_FACTORY(bool(config.get("verify_tls", True)), TIMEOUT, base, row.get("fingerprint") or "")
    status, raw = send("GET", base + "/rest/v0/ping", {"Accept": "application/json"}, None)
    if not (status == 200 and b"pong" in raw):
        raise XenError("this address is not a Xen Orchestra (it has no /rest/v0); a pool master has no backups to read")
    return Xo(base, row, send), base


def _lan_ip(base: str) -> str | None:
    host = urllib.parse.urlsplit(base).hostname or ""
    return _ipv4(host)


def read(config: dict, row: dict, server_id: str) -> dict:
    xo, base = _connect(config, row)
    xo.get("ping")
    repos = xo.get("backup-repositories", "id,name,enabled,size,used,available,url")
    schedules: dict[str, list[dict]] = {}
    for s in xo.get("schedules", "id,jobId,cron,enabled"):
        if s.get("enabled", True):
            schedules.setdefault(s.get("jobId"), []).append(s)
    warnings: list[str] = []
    stores = []
    for r in repos:
        if r.get("enabled") is False:
            warnings.append(f"the repository {_plain(r.get('name'), 60)} is switched off in Xen Orchestra")
        total, used, avail = (_int(r.get(k)) for k in ("size", "used", "available"))
        stores.append({"id": f"{server_id}:{r['id']}", "server_id": server_id, "name": r.get("name") or r["id"], "total": total, "used": used, "avail": avail})
    store_ids = {r["id"]: f"{server_id}:{r['id']}" for r in repos}
    vms = xo.get("vms", "id,name_label", limit=100000)
    if len(vms) > MAX_VMS:
        warnings.append(f"Xen Orchestra has {len(vms)} VMs; only the first {MAX_VMS} are looked at")
    targets = []
    for vm in vms[:MAX_VMS]:
        try:
            info = (xo.get(f"vms/{urllib.parse.quote(vm['id'])}/dashboard") or {}).get("backupsInfo") or {}
        except XenAuthError:
            raise
        except XenError:
            continue                      # a VM that is gone meanwhile, or that this account may not see
        archives = [a for a in info.get("backupArchives") or [] if isinstance(a, dict)]
        runs = [r for r in info.get("lastRuns") or [] if isinstance(r, dict)]
        if not archives and not runs:
            continue
        newest = max(archives, key=lambda a: _int(a.get("timestamp")) or 0, default={})
        last_run = max(runs, key=lambda r: _int(r.get("timestamp")) or 0, default={})
        intervals = [i for j in {r.get("backupJobId") for r in runs} for s in schedules.get(j, []) if (i := cron_interval(s.get("cron")))]
        targets.append({"id": f"{server_id}:{vm['id']}", "server_id": server_id, "store_id": store_ids.get(newest.get("backupRepository")), "type": "vm",
                        "backup_id": vm["id"], "name": vm.get("name_label"), "count": len(archives), "last_backup": stamp(newest.get("timestamp")),
                        "last_state": RUN_STATES.get(str(last_run.get("status")), "unknown"), "last_size": _int(newest.get("size")),
                        "interval": min(intervals) if intervals else None})
    target_of = {t["backup_id"]: t["id"] for t in targets}
    problems = []
    cutoff = (_now() - 7 * 86400) * 1000
    logs = xo.get("backup-logs", "id,jobId,jobName,status,start,end,message,result,tasks,infos", limit=100000)
    for log in logs:
        if log.get("status") not in ("failure", "interrupted") or (_int(log.get("start")) or 0) < cutoff:
            continue
        failed = [t for t in log.get("tasks") or [] if isinstance(t, dict) and t.get("status") in ("failure", "interrupted")]
        for task in failed:
            data = task.get("data") or {}
            vm_id = data.get("id") if data.get("type") == "VM" else None
            problems.append({"id": f"{server_id}:{log['id']}:{vm_id or task.get('id')}", "server_id": server_id, "kind": "backup", "state": "failed",
                             "at": stamp(task.get("end") or log.get("end")), "target_id": target_of.get(vm_id),
                             "text": _plain(f"{log.get('jobName') or 'backup job'}: {data.get('name_label') or 'a VM'}: {(task.get('result') or {}).get('message') or 'failed'}")})
        if not failed:                    # the whole job failed before it reached a VM
            problems.append({"id": f"{server_id}:{log['id']}", "server_id": server_id, "kind": "backup", "state": "failed", "at": stamp(log.get("end") or log.get("start")),
                             "target_id": None, "text": _plain(f"{log.get('jobName') or 'backup job'}: {(log.get('result') or {}).get('message') or 'failed'}")})
    problems.sort(key=lambda p: p.get("at") or "", reverse=True)
    server = {"id": server_id, "name": "Xen Orchestra", "ip": _lan_ip(base), "version": None, "online": True, "warnings": warnings[:10]}
    return {"servers": [server], "stores": stores, "targets": targets, "problems": problems[:200]}


def _each(config: dict, work: Callable[[dict, str], Any]) -> list:
    rows, out = _servers(config), []
    for i, row in enumerate(rows):
        try:
            out.append(work(row, "xo" if len(rows) == 1 else f"xo{i + 1}"))
        except Exception as exc:  # noqa: BLE001 - keeps its type (auth_failed); only the message names the server
            if len(rows) > 1 and exc.args:
                exc.args = (f"{row.get('host')}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return out


def test(config: dict) -> dict:
    def one(row: dict, server_id: str) -> str:
        out = read(config, row, server_id)
        ok = sum(1 for t in out["targets"] if t["last_state"] == "ok")
        return f"Connected to Xen Orchestra: {len(out['stores'])} repositor(ies), {len(out['targets'])} backed-up VM(s), {ok} with a good last run"

    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} servers answered. " + " | ".join(messages)}


def fetch(config: dict) -> dict:
    merged: dict = {"servers": [], "stores": [], "targets": [], "problems": []}
    for part in _each(config, lambda row, server_id: read(config, row, server_id)):
        for key in merged:
            merged[key] += part[key]
    return merged


def diagnose(config: dict) -> dict:
    """What this Xen Orchestra answers, described by field names and types (no names, addresses or ids), for the plugin's author."""
    hosts = _hosts(config)
    row = _servers(config)[0]
    report: dict = {"steps": {}}
    step = make_step(report, hosts)
    xo = step("connect", lambda: _connect(config, row)[0], lambda _x: "ok")
    if xo is None:
        return report
    sample = lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]}   # noqa: E731
    step("backup-repositories", lambda: xo.get("backup-repositories", "*"), sample)
    step("backup-jobs", lambda: xo.get("backup-jobs", "*"), sample)
    step("schedules", lambda: xo.get("schedules", "*"), sample)
    step("backup-logs", lambda: xo.get("backup-logs", "*", limit=SAMPLES), sample)
    vms = step("vms", lambda: xo.get("vms", "id", limit=100000), lambda v: {"count": len(v)})
    for vm in (vms or [])[:SAMPLES]:
        step("vm dashboard backupsInfo", lambda vm=vm: (xo.get(f"vms/{urllib.parse.quote(vm['id'])}/dashboard") or {}).get("backupsInfo"))
        break
    try:
        out = read(config, row, "xo")
        report["result"] = {"repositories": len(out["stores"]), "backed_up_vms": len(out["targets"]), "with_archives": sum(1 for t in out["targets"] if t["count"]),
                            "last_run_ok": sum(1 for t in out["targets"] if t["last_state"] == "ok"), "last_run_failed": sum(1 for t in out["targets"] if t["last_state"] == "failed"),
                            "with_interval": sum(1 for t in out["targets"] if t["interval"]), "problems_7_days": len(out["problems"])}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, hosts)
    return report
