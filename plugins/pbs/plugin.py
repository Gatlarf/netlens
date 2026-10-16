"""Proxmox Backup Server plugin (kind "backup"): what is backed up, how old it is, and how full the datastores are.

Talks to the PBS REST API with an API token (GET only; `Authorization: PBSAPIToken=<user>@<realm>!<name>:<secret>`):

    GET /api2/json/version                                   version
    GET /api2/json/status/datastore-usage                    store, total, used, avail, estimated-full-date (a Unix time)
    GET /api2/json/admin/datastore/<store>/snapshots         backup-type (vm|ct|host), backup-id, backup-time, comment, size, protected, verification.state
    GET /api2/json/admin/gc | prune | verify | sync          jobs: store, last-run-state ("OK", "WARNINGS: 1", an error text), last-run-endtime
    GET /api2/json/nodes/localhost/tasks?typefilter=backup   backup tasks, newest first: worker_id "<store>:<type>/<id>", status ("OK", "WARNINGS: n", an error)
    GET /api2/json/nodes/localhost/tasks?errors=1&since=     tasks that did not end with OK

One target per backup group (a VM, container or host). The snapshots give the newest backup, its size, the number of copies and the usual interval (the
median of the gaps between the newest snapshots); the newest backup *task* of the group says whether the last backup worked (a failed backup leaves no
snapshot). With a certificate fingerprint the server's certificate is compared with it (so a self-signed one is trusted exactly); without one the normal
certificate check applies. Standard library only.
"""

import http.client
import ipaddress
import json
import re
import ssl
import statistics
import time
import urllib.parse
from datetime import datetime, timezone

MAX_SNAPSHOTS = 200000
TASK_LIMIT = 1000
PROBLEM_TASKS = {"backup": "backup", "prune": "prune", "prunejob": "prune", "garbage_collection": "gc", "verificationjob": "verify", "verify": "verify", "verify_group": "verify",
                 "verify_snapshot": "verify", "syncjob": "sync", "sync": "sync"}
TYPES = {"vm": "vm", "ct": "ct", "host": "host"}


class PbsError(Exception):
    pass


class AuthRefused(PbsError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def stamp(seconds):
    return datetime.fromtimestamp(int(seconds), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if seconds else None


def state_of(text):
    """'OK' -> ok, 'WARNINGS: 1' -> warning, anything else that is not empty -> failed (a job that never ran -> none)."""
    if text in (None, ""):
        return "none"
    text = str(text)
    return "ok" if text == "OK" else "warning" if text.startswith("WARNINGS") else "failed"


def _worse(a, b):
    order = {"none": 0, "ok": 1, "warning": 2, "failed": 3}
    return a if order[a] >= order[b] else b


class Server:
    def __init__(self, url, token_id, secret, fingerprint="", lan="", verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise PbsError(f"{url!r} is not an address like https://192.168.0.201:8007")
        if not re.fullmatch(r"[^@\s!]+@[^@\s!]+![^@\s!:]+", token_id.strip()):
            raise PbsError(f"{token_id.strip()!r} is not a token id like netlens@pbs!netlens")
        self.host, self.port = parts.hostname, parts.port or 8007
        self.id = f"{self.host}:{self.port}"
        self.auth = f"PBSAPIToken={token_id.strip()}:{secret.strip()}"
        self.timeout = float(timeout)
        self.fingerprint = re.sub(r"[^0-9a-f]", "", fingerprint.lower()) if fingerprint else ""
        if fingerprint and len(self.fingerprint) != 64:
            raise PbsError("the fingerprint must be 64 hexadecimal digits (SHA-256), as shown under Dashboard > Show Fingerprint")
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise PbsError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(self.host)
        self.context = ssl.create_default_context()
        if self.fingerprint or not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        target = f"/api2/json/{path}" + (f"?{query}" if query else "")
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        try:
            conn.connect()
            if self.fingerprint:
                der = conn.sock.getpeercert(binary_form=True)
                import hashlib

                if hashlib.sha256(der).hexdigest() != self.fingerprint:
                    raise PbsError(f"the certificate of {self.id} does not match the fingerprint; nothing was sent")
            conn.request("GET", target, headers={"Authorization": self.auth, "Accept": "application/json"})
            response = conn.getresponse()
            raw = response.read(50_000_000).decode("utf-8", "replace")
            status = response.status
        except ssl.SSLError as exc:
            raise PbsError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. For a self-signed certificate fill in the fingerprint")
        except (OSError, http.client.HTTPException) as exc:
            raise PbsError(f"cannot reach {self.id}: {exc}")
        finally:
            conn.close()
        if status in (401, 403):
            raise AuthRefused(f"{self.id} refused the API token (wrong token id or secret, or the token has no permission: give both the user and the token the Audit role on /)")
        if status != 200:
            raise PbsError(f"{self.id} answered HTTP {status} for {path}")
        try:
            return json.loads(raw)
        except ValueError:
            raise PbsError(f"{self.id} did not answer properly (is this Proxmox Backup Server?)")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "token_id", "secret"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Proxmox Backup Server")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("token_id") or "").strip() or not str(r.get("secret") or "").strip():
            raise ValueError(f"{host}: enter the token id and the secret")
        out.append(Server(host, str(r["token_id"]), str(r["secret"]), str(r.get("fingerprint") or ""), str(r.get("lan") or ""), config.get("verify_tls", True), config.get("timeout") or 30))
    return out


def _snapshot_groups(snapshots):
    """{(type, id): [snapshot, ...]} newest first."""
    groups = {}
    for s in snapshots:
        groups.setdefault((str(s.get("backup-type")), str(s.get("backup-id"))), []).append(s)
    for items in groups.values():
        items.sort(key=lambda s: s.get("backup-time") or 0, reverse=True)
    return groups


def interval_of(snapshots):
    """The usual time between two backups (median of the gaps between the newest ones), or None with fewer than three snapshots."""
    times = [s["backup-time"] for s in snapshots[:10] if s.get("backup-time")]
    gaps = [a - b for a, b in zip(times, times[1:]) if a > b]
    return int(statistics.median(gaps)) if len(gaps) >= 2 else None


def last_backup_states(tasks):
    """{'<store>:<type>/<id>': state} from backup tasks, newest first; a task that is still running is skipped."""
    out = {}
    for t in tasks:
        if t.get("worker_type") != "backup" or not t.get("worker_id") or t.get("endtime") is None:
            continue
        out.setdefault(str(t["worker_id"]), state_of(t.get("status")) if state_of(t.get("status")) != "none" else "unknown")
    return out


def build(usage, snapshots_by_store, jobs, tasks, problem_tasks, server_id, version, server):
    """(server dict, stores, targets, problems) for one Proxmox Backup Server."""
    stores, targets = [], []
    states = last_backup_states(tasks)
    for u in usage:
        name = u["store"]
        sid = f"{server_id}/{name}"
        entry = {"id": sid, "server_id": server_id, "name": name, "total": u.get("total"), "used": u.get("used"), "avail": u.get("avail"), "full": stamp(u.get("estimated-full-date"))}
        for kind, rows in jobs.items():
            mine = [r for r in rows if r.get("store") == name]
            state, at = "none", None
            for r in mine:
                state = _worse(state, state_of(r.get("last-run-state")))
                if r.get("last-run-endtime") and (at is None or r["last-run-endtime"] > at):
                    at = r["last-run-endtime"]
            entry[f"{kind}_state"], entry[f"{kind}_at"] = state, stamp(at)
        stores.append(entry)
        for (btype, bid), snaps in _snapshot_groups(snapshots_by_store.get(name, [])).items():
            newest = snaps[0]
            verification = (newest.get("verification") or {}).get("state")
            targets.append({
                "id": f"{sid}:{btype}/{bid}", "server_id": server_id, "store_id": sid, "type": TYPES.get(btype, "other"), "backup_id": bid,
                "name": next((s["comment"] for s in snaps if s.get("comment")), "")[:200] if any(s.get("comment") for s in snaps) else "",
                "count": len(snaps), "last_backup": stamp(newest.get("backup-time")), "last_size": newest.get("size"), "interval": interval_of(snaps),
                "last_state": states.get(f"{name}:{btype}/{bid}", "ok"), "protected": sum(1 for s in snaps if s.get("protected")),
                "verify_state": "ok" if verification == "ok" else "failed" if verification == "failed" else "none",
            })
    problems = []
    for t in problem_tasks:
        kind = PROBLEM_TASKS.get(t.get("worker_type"))
        state = state_of(t.get("status"))
        if kind is None or state in ("ok", "none") or t.get("endtime") is None:
            continue
        wid = str(t.get("worker_id") or "")
        match = re.match(r"^(?P<store>[^:]+):(?P<type>vm|ct|host)/(?P<id>[^/]+)$", wid)
        target = f"{server_id}/{match['store']}:{match['type']}/{match['id']}" if match else None
        what = {"backup": "Backup", "prune": "Prune", "gc": "Garbage collection", "verify": "Verification", "sync": "Sync"}[kind]
        text = f"{what} {'of ' + match['type'] + ' ' + match['id'] if match else 'job'} {'finished with warnings' if state == 'warning' else 'failed'}: {str(t.get('status'))[:200]}"
        problems.append({"id": t["upid"][:100], "server_id": server_id, "kind": kind, "state": state, "at": stamp(t["endtime"]), "text": text, "target_id": target})
    warnings = []
    return {"id": server_id, "name": server_id, "ip": server.ip, "version": version, "online": True, "warnings": warnings}, stores, targets, problems


def read(server, config):
    version = str((server.get("version").get("data") or {}).get("version") or "")
    usage = server.get("status/datastore-usage").get("data") or []
    snapshots = {}
    for u in usage:
        snapshots[u["store"]] = (server.get(f"admin/datastore/{urllib.parse.quote(u['store'], safe='')}/snapshots").get("data") or [])[:MAX_SNAPSHOTS]
    jobs = {}
    for kind, path in (("gc", "admin/gc"), ("prune", "admin/prune"), ("verify", "admin/verify"), ("sync", "admin/sync")):
        try:
            jobs[kind] = server.get(path).get("data") or []
        except PbsError:
            jobs[kind] = []                                 # no right to see this kind of job
    try:
        tasks = server.get("nodes/localhost/tasks", typefilter="backup", limit=TASK_LIMIT).get("data") or []
        since = int(time.time()) - int(config.get("problem_days") or 7) * 86400
        problem_tasks = server.get("nodes/localhost/tasks", errors=1, since=since, limit=200).get("data") or []
    except AuthRefused:
        tasks, problem_tasks = [], []                       # no Sys.Audit: the state of the last backup is then taken from the snapshots
    return version, usage, snapshots, jobs, tasks, problem_tasks


def connect(config):
    servers, stores, targets, problems, notes = [], [], [], [], []
    for server in parse_servers(config):
        try:
            version, usage, snaps, jobs, tasks, problem_tasks = read(server, config)
        except AuthRefused:
            raise
        except PbsError as exc:
            notes.append(str(exc))
            continue
        s, st, tg, pr = build(usage, snaps, jobs, tasks, problem_tasks, server.id, version, server)
        if not usage:
            s["warnings"].append("the token sees no datastore: give both the user and the token the Audit role on /")
        if not tasks and not problem_tasks:
            s["warnings"].append("no tasks visible (needs Sys.Audit): the state of the last backup is guessed from the snapshots")
        servers.append(s)
        stores += st
        targets += tg
        problems += pr
    if not servers:
        raise PbsError("; ".join(notes) or "no Proxmox Backup Server answered")
    return servers, stores, targets, problems, notes


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, stores, targets, problems, notes = connect(config)
    message = f"Connected to {len(servers)} Proxmox Backup Server ({', '.join(sorted({s['version'] for s in servers if s['version']})) or 'version unknown'}): {len(stores)} datastore(s), {len(targets)} backed up guest(s) or host(s)"
    failed = sum(1 for t in targets if t["last_state"] == "failed")
    if failed:
        message += f", {failed} with a failed last backup"
    if problems:
        message += f", {len(problems)} recent problem(s)"
    for s in servers:
        for w in s["warnings"]:
            message += f". Note: {w}"
    if notes:
        message += ". Not reachable: " + "; ".join(notes)
    return {"message": message}


def fetch(config):
    servers, stores, targets, problems, _ = connect(config)
    return {"servers": servers, "stores": stores, "targets": targets, "problems": problems}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>").replace(server.host, "<server>")
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the server answers, as counts and enumerations (no names, VM ids, addresses or paths)."""
    try:
        servers = parse_servers(config)
    except (ValueError, PbsError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            version, usage, snaps, jobs, tasks, problem_tasks = read(server, config)
            entry["steps"]["version"] = {"ok": True, "version": version}
            entry["steps"]["datastores"] = {"ok": True, "count": len(usage), "with_estimated_full_date": sum(1 for u in usage if u.get("estimated-full-date")), "fields": sorted({k for u in usage for k in u})[:30]}
            every = [s for rows in snaps.values() for s in rows]
            groups = {(s.get("backup-type"), s.get("backup-id")) for s in every}
            entry["steps"]["snapshots"] = {"ok": True, "count": len(every), "groups": len(groups), "types": {t: sum(1 for g in groups if g[0] == t) for t in sorted({str(g[0]) for g in groups})},
                                           "with_comment": sum(1 for s in every if s.get("comment")), "verified": sum(1 for s in every if (s.get("verification") or {}).get("state") == "ok"),
                                           "protected": sum(1 for s in every if s.get("protected")), "fields": sorted({k for s in every[:200] for k in s})[:30]}
            entry["steps"]["jobs"] = {"ok": True, **{k: {"count": len(v), "states": sorted({state_of(r.get("last-run-state")) for r in v})} for k, v in jobs.items()}}
            entry["steps"]["tasks"] = {"ok": True, "backup_tasks": len(tasks), "problem_tasks": len(problem_tasks), "types": sorted({str(t.get("worker_type")) for t in tasks + problem_tasks})[:20]}
        except AuthRefused:
            raise
        except PbsError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
