"""Greenbone / OpenVAS plugin (kind "vulnerability"): the findings of the scanner, per host.

Talks the Greenbone Management Protocol (GMP, XML over TLS, port 9390 of gvmd) with a user name and password. Read-only commands only:

    <get_version/>                                           the protocol version (works before login)
    <authenticate><credentials>...</credentials></authenticate>
    <get_tasks/>                                             the scan tasks and the time of their last report
    <get_results filter="..." details="1"/>                  the results (findings), paged

A result names the host (address, sometimes a host name), the port ("445/tcp"), the vulnerability test (an NVT with a name, CVE references, the score and a solution) and
the severity (0-10). Netlens turns the score into critical (9 and up), high (7), medium (4), low (above 0). The id of a finding is made from host, NVT and port, not from the result
id (that changes with every scan), so the same finding keeps its id over many scans and "new" means new. Standard library only.
"""

import hashlib
import re
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

PAGE = 500
MAX_FINDINGS = 20000
SEVERITY_LEVELS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


class GvmError(Exception):
    pass


class AuthRefused(GvmError):
    auth_failed = True


def level_of(score):
    for low, name in SEVERITY_LEVELS:
        if score >= low:
            return name
    return "info"


def _stamp(text):
    """'2026-10-18T14:00:00Z' or '2026-10-18T16:00:00+02:00' -> UTC stamp, or None."""
    if not text:
        return None
    try:
        when = datetime.fromisoformat(str(text).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Gmp:
    def __init__(self, host, username, password, fingerprint="", verify_tls=False, timeout=60):
        text = host.strip()
        text = re.sub(r"^[a-z]+://", "", text).rstrip("/")
        if not text:
            raise GvmError("enter the address of Greenbone, like 192.168.0.190:9390")
        name, _, port = text.partition(":") if text.count(":") == 1 else (text, "", "")
        self.host, self.port = name, int(port) if port.isdigit() else 9390
        self.id = f"{self.host}:{self.port}"
        self.username, self.password = username.strip(), password
        self.timeout = float(timeout)
        self.fingerprint = re.sub(r"[^0-9a-f]", "", fingerprint.lower()) if fingerprint else ""
        if fingerprint and len(self.fingerprint) != 64:
            raise GvmError("the fingerprint must be 64 hexadecimal digits (SHA-256 of the certificate)")
        self.context = ssl.create_default_context()
        if self.fingerprint or not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.sock = None
        self.authenticated = False

    # -- connection
    def open(self):
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host)
        except ssl.SSLError as exc:
            raise GvmError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. gvmd must listen with TLS (gvmd --listen --port 9390)")
        except OSError as exc:
            raise GvmError(f"cannot reach {self.id}: {exc}")
        if self.fingerprint:
            if hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest() != self.fingerprint:
                self.close()
                raise GvmError(f"the certificate of {self.id} does not match the fingerprint; nothing was sent")
        return self

    def close(self):
        try:
            if self.sock is not None:
                try:
                    self.sock.unwrap()                          # a proper TLS goodbye, so gvmd does not log a broken connection
                except (OSError, ValueError):
                    pass
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def command(self, xml):
        """Send one command and return the response element once it is complete."""
        if self.sock is None:
            self.open()
        parser = ET.XMLPullParser(events=("start", "end"))
        depth = 0
        try:
            self.sock.sendall(xml.encode("utf-8"))
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise GvmError(f"{self.id} closed the connection")
                parser.feed(chunk)
                for event, element in parser.read_events():
                    if event == "start":
                        depth += 1
                    else:
                        depth -= 1
                        if depth == 0:
                            return self._checked(element)
        except socket.timeout:
            raise GvmError(f"{self.id} did not answer in {self.timeout:g} seconds")
        except (OSError, ET.ParseError) as exc:
            raise GvmError(f"{self.id} did not answer properly: {exc}")

    def _checked(self, element):
        status = element.get("status", "")
        if status.startswith("2"):
            return element
        text = element.get("status_text", "")
        if element.tag == "authenticate_response" or status in ("400", "401") and "auth" in text.lower():
            raise AuthRefused(f"{self.id} refused the user name or password")
        if status == "403":
            raise GvmError(f"{self.id} says this user may not do that ({text}); give the user the Observer role")
        raise GvmError(f"{self.id} answered {status} {text}".strip())

    def login(self):
        from xml.sax.saxutils import escape

        self.command(f"<authenticate><credentials><username>{escape(self.username)}</username><password>{escape(self.password)}</password></credentials></authenticate>")
        self.authenticated = True


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Greenbone server")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("username") or "").strip() or not str(r.get("password") or ""):
            raise ValueError(f"{host}: enter the user name and the password")
        out.append(Gmp(host, str(r["username"]), str(r["password"]), str(r.get("fingerprint") or ""), bool(config.get("verify_tls", False)), config.get("timeout") or 60))
    return out


# ----------------------------------------------------------------------------- reading results
def _refs(nvt, kind):
    return [r.get("id", "").strip() for r in nvt.iter("ref") if r.get("type", "").lower() == kind and r.get("id")]


def parse_result(el):
    """One <result> -> a finding dict (without id/server), or None when it has no usable host."""
    host = el.find("host")
    ip = ((host.text or "").strip().split()[0] if host is not None and (host.text or "").strip() else "")
    hostname = (host.findtext("hostname") or "").strip() if host is not None else ""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return None
    nvt = el.find("nvt")
    oid = (nvt.get("oid") if nvt is not None else "") or el.findtext("name") or ""
    try:
        score = float(el.findtext("severity") or 0)
    except ValueError:
        score = 0.0
    port_text = (el.findtext("port") or "").strip()
    m = re.match(r"^(\d+)/(tcp|udp)$", port_text)
    cves = sorted({c.upper() for c in _refs(nvt, "cve")}) if nvt is not None else []
    solution = ""
    if nvt is not None:
        sol = nvt.find("solution")
        solution = " ".join((sol.text or "").split()) if sol is not None else ""
    title = (nvt.findtext("name") if nvt is not None else None) or el.findtext("name") or "Finding"
    return {"host_ip": ip, "host_name": hostname[:100], "oid": oid, "title": " ".join(title.split())[:200], "cve": [c for c in cves if re.fullmatch(r"CVE-\d{4}-\d{4,9}", c)][:20],
            "score": round(score, 1), "severity": level_of(score), "port": int(m.group(1)) if m else None, "proto": m.group(2) if m else "tcp",
            "seen": _stamp(el.findtext("creation_time")), "solution": solution[:500], "exploited": _exploited(nvt)}


def _exploited(nvt):
    """Whether the scanner marks the vulnerability as known to be exploited (a CISA KEV reference or tag)."""
    if nvt is None:
        return False
    if any(r.get("type", "").lower() in ("cisa", "cisa_kev", "kev") for r in nvt.iter("ref")):
        return True
    tags = (nvt.findtext("tags") or "").lower()
    return "known_exploited" in tags or "cisa_kev" in tags


def finding_id(parsed):
    return hashlib.sha1(f"{parsed['host_ip']}|{parsed['oid']}|{parsed['port']}|{parsed['proto']}".encode()).hexdigest()[:20]


def read_results(gmp, min_qod, min_severity, max_age_days):
    """All results above the thresholds, newest per (host, test, port), as a list of parsed findings."""
    above = max(0.0, float(min_severity) - 0.1)          # Greenbone's filter has ">" but no ">=": "severity>0.0" is "above zero"
    flt = f"apply_overrides=1 min_qod={int(min_qod)} severity>{above:.1f} sort-reverse=severity"
    newest, first = {}, 1
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(max_age_days))).strftime("%Y-%m-%dT%H:%M:%SZ")
    while True:
        response = gmp.command(f'<get_results filter="{flt} rows={PAGE} first={first}" details="1"/>')
        results = response.findall("result")
        for el in results:
            parsed = parse_result(el)
            if parsed is None or (parsed["seen"] and parsed["seen"] < cutoff):
                continue
            key = finding_id(parsed)
            if key not in newest or (parsed["seen"] or "") > (newest[key]["seen"] or ""):
                newest[key] = {**parsed, "id": key}
        if len(results) < PAGE or len(newest) >= MAX_FINDINGS:
            break
        first += PAGE
    return list(newest.values())[:MAX_FINDINGS]


def last_scan(gmp):
    stamps = []
    for task in gmp.command('<get_tasks filter="rows=-1"/>').findall("task"):
        report = task.find("last_report/report")
        if report is not None:
            stamps.append(_stamp(report.findtext("timestamp") or report.findtext("scan_end")))
    stamps = [s for s in stamps if s]
    return max(stamps) if stamps else None


def read(gmp, config):
    version = (gmp.command("<get_version/>").findtext("version") or "").strip()
    gmp.login()
    findings = read_results(gmp, config.get("min_qod") or 70, config.get("min_severity") or "0.1", config.get("max_age_days") or 30)
    return version, findings, last_scan(gmp)


def connect(config):
    servers, findings, notes = [], [], []
    for gmp in parse_servers(config):
        try:
            gmp.open()
            version, rows, scanned = read(gmp, config)
        except AuthRefused:
            raise
        except GvmError as exc:
            notes.append(str(exc))
            continue
        finally:
            gmp.close()
        warnings = []
        if scanned is None:
            warnings.append("no scan has finished yet: start a task in Greenbone")
        servers.append({"id": gmp.id, "name": "Greenbone", "version": version, "online": True, "last_scan": scanned, "warnings": warnings})
        for f in rows:
            findings.append({"id": f"{gmp.id}:{f['id']}"[:100], "server_id": gmp.id, "host_ip": f["host_ip"], "host_name": f["host_name"], "title": f["title"], "cve": f["cve"],
                             "severity": f["severity"], "score": f["score"], "port": f["port"], "proto": f["proto"], "last_seen": f["seen"], "exploited": f["exploited"], "solution": f["solution"]})
    if not servers:
        raise GvmError("; ".join(notes) or "no Greenbone server answered")
    return servers, findings, notes


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, findings, notes = connect(config)
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    shown = ", ".join(f"{by[s]} {s}" for s in ("critical", "high", "medium", "low") if by.get(s)) or "no findings"
    message = f"Connected to {len(servers)} Greenbone server ({', '.join(sorted({s['version'] for s in servers if s['version']})) or 'version unknown'}): {len(findings)} findings ({shown}) on {len({f['host_ip'] for f in findings})} host(s)"
    for s in servers:
        for w in s["warnings"]:
            message += f". Note: {w}"
    if notes:
        message += ". Not reachable: " + "; ".join(notes)
    return {"message": message}


def fetch(config):
    servers, findings, _ = connect(config)
    return {"servers": servers, "findings": findings}


def _problem(exc, gmp=None):
    text = str(exc)
    if gmp is not None:
        text = text.replace(gmp.id, "<server>").replace(gmp.host, "<server>")
    text = re.sub(r"https?://[^\s/]+", "<server>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Greenbone answers, as counts and enumerations (no host names, addresses, titles or CVE numbers)."""
    try:
        servers = parse_servers(config)
    except (ValueError, GvmError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for gmp in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            gmp.open()
            entry["steps"]["version"] = {"ok": True, "version": (gmp.command("<get_version/>").findtext("version") or "")}
            gmp.login()
            entry["steps"]["login"] = {"ok": True}
            tasks = gmp.command('<get_tasks filter="rows=-1"/>').findall("task")
            entry["steps"]["tasks"] = {"ok": True, "count": len(tasks), "statuses": sorted({(t.findtext("status") or "?") for t in tasks})[:10], "with_report": sum(1 for t in tasks if t.find("last_report/report") is not None)}
            response = gmp.command(f'<get_results filter="apply_overrides=1 min_qod=70 severity>0.0 rows=100 first=1" details="1"/>')
            rows = response.findall("result")
            parsed = [p for p in (parse_result(r) for r in rows) if p]
            entry["steps"]["results"] = {"ok": True, "sample": len(rows), "usable": len(parsed), "levels": {s: sum(1 for p in parsed if p["severity"] == s) for s in sorted({p["severity"] for p in parsed})},
                                         "with_cve": sum(1 for p in parsed if p["cve"]), "with_port": sum(1 for p in parsed if p["port"]), "with_solution": sum(1 for p in parsed if p["solution"]),
                                         "exploited": sum(1 for p in parsed if p["exploited"]), "child_tags": sorted({c.tag for r in rows[:50] for c in r})[:30],
                                         "ref_types": sorted({x.get("type", "?") for r in rows[:50] for x in r.iter("ref")})[:20]}
        except AuthRefused:
            raise
        except GvmError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, gmp)}
        finally:
            gmp.close()
    return report
