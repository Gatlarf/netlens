"""Rapid7 InsightVM plugin (kind "vulnerability"): the vulnerabilities of the assets, per host.

Written from the InsightVM / Nexpose API v3 documentation (not tested against a real console). Read-only (GET only), HTTP Basic authentication:

    GET /api/3/administration/info                           the version (optional)
    GET /api/3/assets?page=&size=                            the assets: id, ip, mac, hostName, history (when scanned), vulnerabilities {critical, severe, moderate, total}
    GET /api/3/assets/<id>/vulnerabilities?page=&size=       per asset: id (vulnerability), status, instances, results [{port, protocol}]
    GET /api/3/vulnerabilities/<vuln id>                     title, severity (Critical, Severe, Moderate), severityScore, cvss, cves, exploits, malwareKits
    GET /api/3/vulnerabilities/<vuln id>/solutions           ids of the solutions; GET /api/3/solutions/<id> has a summary

Severity: Critical, Severe (high) and Moderate (medium) are what the console has; Netlens only reports those. A vulnerability counts as "known to be exploited" when the console
knows exploits or malware kits for it. The asset ids are not kept: a finding id is made from the address, the vulnerability and the port. Standard library only.
"""

import binascii
import hashlib
import http.client
import json
import re
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone

PAGE = 500
MAX_FINDINGS = 20000
LEVELS = {"critical": "critical", "severe": "high", "moderate": "medium"}
RANK = {"critical": 3, "severe": 2, "moderate": 1}


class VmError(Exception):
    pass


class AuthRefused(VmError):
    auth_failed = True


class Console:
    def __init__(self, url, username, password, fingerprint="", verify_tls=False, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise VmError(f"{url!r} is not an address like https://192.168.0.60:3780")
        self.host, self.port = parts.hostname, parts.port or 3780
        self.id = f"{self.host}:{self.port}"
        self.auth = "Basic " + binascii.b2a_base64(f"{username.strip()}:{password}".encode(), newline=False).decode()
        self.timeout = float(timeout)
        self.fingerprint = re.sub(r"[^0-9a-f]", "", fingerprint.lower()) if fingerprint else ""
        if fingerprint and len(self.fingerprint) != 64:
            raise VmError("the fingerprint must be 64 hexadecimal digits (SHA-256 of the certificate)")
        self.context = ssl.create_default_context()
        if self.fingerprint or not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        try:
            conn.connect()
            if self.fingerprint and hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != self.fingerprint:
                raise VmError(f"the certificate of {self.id} does not match the fingerprint; nothing was sent")
            conn.request("GET", f"/api/3{path}" + (f"?{query}" if query else ""), headers={"Authorization": self.auth, "Accept": "application/json;charset=UTF-8"})
            response = conn.getresponse()
            raw = response.read(100_000_000).decode("utf-8", "replace")
            status = response.status
        except ssl.SSLError as exc:
            raise VmError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. For a self-signed certificate fill in the fingerprint")
        except (OSError, http.client.HTTPException) as exc:
            raise VmError(f"cannot reach {self.id}: {exc}")
        finally:
            conn.close()
        if status in (401, 403):
            raise AuthRefused(f"{self.id} refused the user name or password (or the user may not read assets)")
        if status != 200:
            raise VmError(f"{self.id} answered HTTP {status} for {path}")
        try:
            return json.loads(raw)
        except ValueError:
            raise VmError(f"{self.id} did not answer properly (is this InsightVM?)")

    def pages(self, path):
        page = 0
        while True:
            doc = self.get(path, page=page, size=PAGE)
            yield from doc.get("resources") or []
            total = int((doc.get("page") or {}).get("totalPages") or 1)
            page += 1
            if page >= total:
                return


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one InsightVM console")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("username") or "").strip() or not str(r.get("password") or ""):
            raise ValueError(f"{host}: enter the user name and the password")
        out.append(Console(host, str(r["username"]), str(r["password"]), str(r.get("fingerprint") or ""), bool(config.get("verify_tls", False)), config.get("timeout") or 30))
    return out


def _stamp(text):
    try:
        when = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def scanned_at(asset):
    """When the asset was last assessed: the newest entry of its history."""
    stamps = [s for s in (_stamp(h.get("date")) for h in asset.get("history") or [] if isinstance(h, dict)) if s]
    return max(stamps) if stamps else None


def vuln_details(doc, solution=""):
    cvss = doc.get("cvss") or {}
    v3, v2 = (cvss.get("v3") or {}).get("score"), (cvss.get("v2") or {}).get("score")
    score = v3 if v3 is not None else v2 if v2 is not None else doc.get("severityScore")
    cves = [c.strip().upper() for c in doc.get("cves") or [] if re.fullmatch(r"CVE-\d{4}-\d{4,9}", str(c).strip().upper())]
    return {"title": " ".join(str(doc.get("title") or doc.get("id") or "Vulnerability").split())[:200], "severity": str(doc.get("severity") or "").lower(), "score": float(score) if score is not None else None,
            "cve": sorted(set(cves))[:20], "exploited": bool(doc.get("exploits") or doc.get("malwareKits")), "solution": solution[:500]}


def read(console, config):
    """-> version, last scan, rows [{ip, mac, name, vuln, port, proto, seen, status}] and how often each vulnerability occurs."""
    try:
        info = console.get("/administration/info")
        version = str((info.get("version") if isinstance(info.get("version"), str) else (info.get("version") or {}).get("semantic")) or "")
    except AuthRefused:
        raise
    except VmError:
        version = ""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(config.get("max_age_days") or 30))
    minimum = RANK.get(str(config.get("min_severity") or "moderate").lower(), 1)
    rows, newest, count = [], None, {}
    for asset in console.pages("/assets"):
        ip = str(asset.get("ip") or "").strip()
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            continue
        seen = scanned_at(asset)
        if seen is not None and seen < cutoff:
            continue
        if seen is not None:
            newest = max(newest or seen, seen)                  # a clean asset counts: the network was scanned
        counts = asset.get("vulnerabilities") or {}
        if not any(int(counts.get(k) or 0) for k in ("critical", "severe", "moderate")):
            continue
        mac = str(asset.get("mac") or "").strip().lower().replace("-", ":")
        mac = mac if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) else None
        for v in console.pages(f"/assets/{int(asset['id'])}/vulnerabilities"):
            status = str(v.get("status") or "")
            if status.startswith("not-vulnerable") or status == "unknown":
                continue
            results = [r for r in v.get("results") or [] if isinstance(r, dict) and not str(r.get("status") or "").startswith("not-")] or [{}]
            for r in results[:5]:
                rows.append({"ip": ip, "mac": mac, "name": str(asset.get("hostName") or "")[:100], "vuln": str(v.get("id")), "port": r.get("port"), "proto": str(r.get("protocol") or "tcp").lower(),
                             "seen": seen.strftime("%Y-%m-%dT%H:%M:%SZ") if seen else None, "status": status})
            count[str(v.get("id"))] = count.get(str(v.get("id")), 0) + 1
    return version, (newest.strftime("%Y-%m-%dT%H:%M:%SZ") if newest else None), rows, minimum, count


def lookup(console, count, limit):
    """Title, severity, CVE numbers and so on, once per vulnerability, the most widespread first; the solution only for the first few."""
    cache = {}
    for i, (vid, _) in enumerate(sorted(count.items(), key=lambda kv: -kv[1])):
        if i >= int(limit):
            break
        try:
            doc = console.get(f"/vulnerabilities/{urllib.parse.quote(vid, safe='')}")
            solution = ""
            if i < 100:
                try:
                    ids = [s.get("id") if isinstance(s, dict) else s for s in (console.get(f"/vulnerabilities/{urllib.parse.quote(vid, safe='')}/solutions").get("resources") or [])][:1]
                    if ids and ids[0]:
                        sdoc = console.get(f"/solutions/{urllib.parse.quote(str(ids[0]), safe='')}")
                        solution = " ".join(str(((sdoc.get("summary") or {}).get("text")) or "").split())
                except VmError:
                    pass
            cache[vid] = vuln_details(doc, solution)
        except AuthRefused:
            raise
        except VmError:
            cache[vid] = None
    return cache


def connect(config):
    servers, findings, notes = [], [], []
    for console in parse_servers(config):
        try:
            version, scanned, rows, minimum, count = read(console, config)
            cache = lookup(console, count, config.get("detail_lookups") if config.get("detail_lookups") is not None else 300)
        except AuthRefused:
            raise
        except VmError as exc:
            notes.append(str(exc))
            continue
        servers.append({"id": console.id, "name": "InsightVM", "version": version, "online": True, "last_scan": scanned,
                        "warnings": [] if scanned else ["no asset was assessed within the chosen time: run a scan in InsightVM"]})
        for r in rows:
            d = cache.get(r["vuln"])
            if not d or RANK.get(d["severity"], 0) < minimum or d["severity"] not in LEVELS:
                continue
            key = hashlib.sha1(f"{r['ip']}|{r['vuln']}|{r['port']}|{r['proto']}".encode()).hexdigest()[:20]
            findings.append({"id": f"{console.id}:{key}"[:100], "server_id": console.id, "host_ip": r["ip"], "host_mac": r["mac"], "host_name": r["name"], "title": d["title"], "cve": d["cve"],
                             "severity": LEVELS[d["severity"]], "score": d["score"], "port": r["port"] if isinstance(r["port"], int) and 0 < r["port"] < 65536 else None,
                             "proto": r["proto"] if r["proto"] in ("tcp", "udp") else "tcp", "last_seen": r["seen"], "exploited": d["exploited"] or r["status"] == "vulnerable-exploited", "solution": d["solution"]})
    if not servers:
        raise VmError("; ".join(notes) or "no InsightVM console answered")
    return servers, findings[:MAX_FINDINGS], notes


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, findings, notes = connect(config)
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    shown = ", ".join(f"{by[s]} {s}" for s in ("critical", "high", "medium") if by.get(s)) or "no findings"
    message = f"Connected to {len(servers)} InsightVM console ({', '.join(sorted({s['version'] for s in servers if s['version']})) or 'version unknown'}): {len(findings)} findings ({shown}) on {len({f['host_ip'] for f in findings})} host(s)"
    for s in servers:
        for w in s["warnings"]:
            message += f". Note: {w}"
    if notes:
        message += ". Not reachable: " + "; ".join(notes)
    return {"message": message}


def fetch(config):
    servers, findings, _ = connect(config)
    return {"servers": servers, "findings": findings}


def _problem(exc, console=None):
    text = str(exc)
    if console is not None:
        text = text.replace(console.id, "<server>").replace(console.host, "<server>")
    text = re.sub(r"https?://[^\s/]+", "<server>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the console answers, as counts and enumerations (no host names, addresses, titles or CVE numbers)."""
    try:
        consoles = parse_servers(config)
    except (ValueError, VmError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for console in consoles:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            try:
                info = console.get("/administration/info")
                entry["steps"]["info"] = {"ok": True, "fields": sorted(info)[:30]}
            except AuthRefused:
                raise
            except VmError as exc:
                entry["steps"]["info"] = {"ok": False, "error": _problem(exc, console)}
            doc = console.get("/assets", page=0, size=20)
            assets = doc.get("resources") or []
            entry["steps"]["assets"] = {"ok": True, "sample": len(assets), "page_fields": sorted(doc.get("page") or {}), "fields": sorted({k for a in assets for k in a})[:40],
                                        "with_mac": sum(1 for a in assets if a.get("mac")), "with_history": sum(1 for a in assets if a.get("history"))}
            withv = next((a for a in assets if (a.get("vulnerabilities") or {}).get("total")), None)
            if withv:
                vdoc = console.get(f"/assets/{int(withv['id'])}/vulnerabilities", page=0, size=20)
                rows = vdoc.get("resources") or []
                entry["steps"]["asset_vulnerabilities"] = {"ok": True, "count": len(rows), "fields": sorted({k for r in rows for k in r})[:30], "statuses": sorted({str(r.get("status")) for r in rows})[:20],
                                                           "result_fields": sorted({k for r in rows for x in (r.get("results") or []) if isinstance(x, dict) for k in x})[:20]}
                if rows:
                    one = console.get(f"/vulnerabilities/{urllib.parse.quote(str(rows[0]['id']), safe='')}")
                    entry["steps"]["vulnerability"] = {"ok": True, "fields": sorted(one)[:50], "severity": str(one.get("severity")), "cvss_keys": sorted(one.get("cvss") or {})}
        except AuthRefused:
            raise
        except VmError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, console)}
    return report
