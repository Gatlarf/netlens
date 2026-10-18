"""Tenable Nessus plugin (kind "vulnerability"): the findings of the latest scans, per host.

Written from the Nessus REST API documentation (not tested against a real Nessus). Read-only (GET only), authenticated with an API key pair:
`X-ApiKeys: accessKey=<key>; secretKey=<secret>`.

    GET /server/properties                         the Nessus version
    GET /scans                                     the scans: id, name, status, last_modification_date
    GET /scans/<id>                                the hosts of the latest run (host_id, hostname) and when the scan ended
    GET /scans/<id>/hosts/<host_id>                info (host-ip, host-fqdn, mac-address) and the vulnerabilities (plugin_id, plugin_name, severity 0-4, count)
    GET /plugins/plugin/<plugin_id>                attributes: cve, cvss base scores, solution, cisa-known-exploited, exploit_available

Severity: 4 critical, 3 high, 2 medium, 1 low, 0 info. Only completed scans are read; per host and plugin the newest scan counts. The attributes of a plugin are asked for
once (the most serious first, up to the configured number). Standard library only.
"""

import hashlib
import http.client
import json
import re
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone

LEVELS = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
MAX_FINDINGS = 20000


class NessusError(Exception):
    pass


class AuthRefused(NessusError):
    auth_failed = True


def _stamp(seconds):
    try:
        return datetime.fromtimestamp(int(seconds), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if seconds else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class Server:
    def __init__(self, url, access_key, secret_key, fingerprint="", verify_tls=False, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise NessusError(f"{url!r} is not an address like https://192.168.0.50:8834")
        self.host, self.port = parts.hostname, parts.port or 8834
        self.id = f"{self.host}:{self.port}"
        self.auth = f"accessKey={access_key.strip()}; secretKey={secret_key.strip()}"
        self.timeout = float(timeout)
        self.fingerprint = re.sub(r"[^0-9a-f]", "", fingerprint.lower()) if fingerprint else ""
        if fingerprint and len(self.fingerprint) != 64:
            raise NessusError("the fingerprint must be 64 hexadecimal digits (SHA-256 of the certificate)")
        self.context = ssl.create_default_context()
        if self.fingerprint or not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        try:
            conn.connect()
            if self.fingerprint and hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != self.fingerprint:
                raise NessusError(f"the certificate of {self.id} does not match the fingerprint; nothing was sent")
            conn.request("GET", path, headers={"X-ApiKeys": self.auth, "Accept": "application/json"})
            response = conn.getresponse()
            raw = response.read(100_000_000).decode("utf-8", "replace")
            status = response.status
        except ssl.SSLError as exc:
            raise NessusError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. For a self-signed certificate fill in the fingerprint")
        except (OSError, http.client.HTTPException) as exc:
            raise NessusError(f"cannot reach {self.id}: {exc}")
        finally:
            conn.close()
        if status in (401, 403):
            raise AuthRefused(f"{self.id} refused the API keys (wrong keys, or the user may not read this)")
        if status != 200:
            raise NessusError(f"{self.id} answered HTTP {status} for {path.split('?')[0]}")
        try:
            return json.loads(raw)
        except ValueError:
            raise NessusError(f"{self.id} did not answer properly (is this Nessus?)")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "access_key", "secret_key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Nessus scanner")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("access_key") or "").strip() or not str(r.get("secret_key") or "").strip():
            raise ValueError(f"{host}: enter the access key and the secret key")
        out.append(Server(host, str(r["access_key"]), str(r["secret_key"]), str(r.get("fingerprint") or ""), bool(config.get("verify_tls", False)), config.get("timeout") or 30))
    return out


def attributes(plugin):
    """The attributes of /plugins/plugin/<id> as {name: [values]}."""
    out = {}
    for a in (plugin or {}).get("attributes") or []:
        if isinstance(a, dict) and a.get("attribute_name"):
            out.setdefault(str(a["attribute_name"]), []).append(str(a.get("attribute_value") or ""))
    return out


def details_of(plugin):
    """CVE numbers, the best score, the solution and whether it is known to be exploited, from a plugin's attributes."""
    at = attributes(plugin)
    cves = sorted({c.strip().upper() for v in at.get("cve", []) for c in v.split(",") if re.fullmatch(r"CVE-\d{4}-\d{4,9}", c.strip().upper())})
    score = None
    for name in ("cvss3_base_score", "cvss_base_score"):
        for v in at.get(name, []):
            try:
                score = float(v)
                break
            except ValueError:
                continue
        if score is not None:
            break
    exploited = bool(at.get("cisa-known-exploited"))
    return {"cve": cves[:20], "score": score, "solution": " ".join((at.get("solution") or [""])[0].split())[:500], "exploited": exploited}


def finding_id(ip, plugin_id):
    return hashlib.sha1(f"{ip}|{plugin_id}".encode()).hexdigest()[:20]


def read(server, config):
    """-> version, last scan stamp, rows [{ip, mac, name, plugin_id, title, severity, seen}] (newest per host and plugin)."""
    version = str((server.get("/server/properties") or {}).get("nessus_ui_version") or (server.get("/server/properties") or {}).get("server_version") or "")
    minimum = int(config.get("min_severity") or 1)
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(config.get("max_age_days") or 30))
    rows, newest_scan = {}, None
    for scan in (server.get("/scans") or {}).get("scans") or []:
        if scan.get("status") != "completed":
            continue
        detail = server.get(f"/scans/{int(scan['id'])}")
        ended = int((detail.get("info") or {}).get("scan_end") or scan.get("last_modification_date") or 0)
        when = _stamp(ended)
        if when is None or datetime.fromtimestamp(ended, tz=timezone.utc) < cutoff:
            continue
        newest_scan = max(newest_scan or when, when)
        for host in detail.get("hosts") or []:
            if not any(int(host.get(k) or 0) for k in ("critical", "high", "medium", "low")):
                continue
            hd = server.get(f"/scans/{int(scan['id'])}/hosts/{int(host['host_id'])}")
            info = hd.get("info") or {}
            ip = str(info.get("host-ip") or host.get("hostname") or "").strip()
            if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                continue
            mac = (str(info.get("mac-address") or "").split("\n")[0].strip().lower().replace("-", ":")) or None
            for v in hd.get("vulnerabilities") or []:
                sev = int(v.get("severity") or 0)
                if sev < minimum:
                    continue
                key = (ip, int(v["plugin_id"]))
                if key not in rows or when > rows[key]["seen"]:
                    rows[key] = {"ip": ip, "mac": mac if mac and re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None, "name": str(info.get("host-fqdn") or "")[:100],
                                 "plugin_id": int(v["plugin_id"]), "title": " ".join(str(v.get("plugin_name") or "Finding").split())[:200], "severity": LEVELS.get(sev, "info"),
                                 "seen": when, "scan": int(scan["id"]), "host_id": int(host["host_id"])}
    return version, newest_scan, list(rows.values())[:MAX_FINDINGS]


def enrich(server, rows, limit):
    """Look up the plugin attributes (once per plugin, the most serious first) and the port of the serious ones is not asked for: Nessus gives it per plugin output."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cache = {}
    for row in sorted(rows, key=lambda r: order[r["severity"]]):
        pid = row["plugin_id"]
        if pid in cache or len(cache) >= int(limit):
            continue
        try:
            cache[pid] = details_of(server.get(f"/plugins/plugin/{pid}"))
        except AuthRefused:
            raise
        except NessusError:
            cache[pid] = {"cve": [], "score": None, "solution": "", "exploited": False}
    return cache


def connect(config):
    servers, findings, notes = [], [], []
    for server in parse_servers(config):
        try:
            version, scanned, rows = read(server, config)
            cache = enrich(server, rows, config.get("detail_lookups") if config.get("detail_lookups") is not None else 300)
        except AuthRefused:
            raise
        except NessusError as exc:
            notes.append(str(exc))
            continue
        warnings = [] if scanned else ["no completed scan within the chosen time: run a scan in Nessus"]
        servers.append({"id": server.id, "name": "Nessus", "version": version, "online": True, "last_scan": scanned, "warnings": warnings})
        for r in rows:
            d = cache.get(r["plugin_id"]) or {"cve": [], "score": None, "solution": "", "exploited": False}
            findings.append({"id": f"{server.id}:{finding_id(r['ip'], r['plugin_id'])}"[:100], "server_id": server.id, "host_ip": r["ip"], "host_mac": r["mac"], "host_name": r["name"], "title": r["title"],
                             "cve": d["cve"], "severity": r["severity"], "score": d["score"], "last_seen": r["seen"], "exploited": d["exploited"], "solution": d["solution"]})
    if not servers:
        raise NessusError("; ".join(notes) or "no Nessus scanner answered")
    return servers, findings, notes


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, findings, notes = connect(config)
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    shown = ", ".join(f"{by[s]} {s}" for s in ("critical", "high", "medium", "low") if by.get(s)) or "no findings"
    message = f"Connected to {len(servers)} Nessus scanner ({', '.join(sorted({s['version'] for s in servers if s['version']})) or 'version unknown'}): {len(findings)} findings ({shown}) on {len({f['host_ip'] for f in findings})} host(s)"
    for s in servers:
        for w in s["warnings"]:
            message += f". Note: {w}"
    if notes:
        message += ". Not reachable: " + "; ".join(notes)
    return {"message": message}


def fetch(config):
    servers, findings, _ = connect(config)
    return {"servers": servers, "findings": findings}


def _problem(exc, server=None):
    text = str(exc)
    if server is not None:
        text = text.replace(server.id, "<server>").replace(server.host, "<server>")
    text = re.sub(r"https?://[^\s/]+", "<server>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Nessus answers, as counts and enumerations (no host names, addresses, titles or CVE numbers)."""
    try:
        servers = parse_servers(config)
    except (ValueError, NessusError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            props = server.get("/server/properties") or {}
            entry["steps"]["properties"] = {"ok": True, "fields": sorted(props)[:30]}
            scans = (server.get("/scans") or {}).get("scans") or []
            entry["steps"]["scans"] = {"ok": True, "count": len(scans), "statuses": sorted({str(s.get("status")) for s in scans})[:10], "fields": sorted({k for s in scans[:20] for k in s})[:30]}
            done = [s for s in scans if s.get("status") == "completed"]
            if done:
                detail = server.get(f"/scans/{int(done[0]['id'])}")
                hosts = detail.get("hosts") or []
                entry["steps"]["scan"] = {"ok": True, "hosts": len(hosts), "info_fields": sorted(detail.get("info") or {})[:40], "host_fields": sorted({k for h in hosts[:20] for k in h})[:30]}
                if hosts:
                    hd = server.get(f"/scans/{int(done[0]['id'])}/hosts/{int(hosts[0]['host_id'])}")
                    vulns = hd.get("vulnerabilities") or []
                    entry["steps"]["host"] = {"ok": True, "info_fields": sorted(hd.get("info") or {})[:40], "vulnerabilities": len(vulns), "vuln_fields": sorted({k for v in vulns[:20] for k in v})[:30],
                                              "severities": sorted({int(v.get("severity") or 0) for v in vulns})}
                    if vulns:
                        pl = server.get(f"/plugins/plugin/{int(vulns[0]['plugin_id'])}")
                        entry["steps"]["plugin"] = {"ok": True, "attribute_names": sorted(attributes(pl))[:60]}
        except AuthRefused:
            raise
        except NessusError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
