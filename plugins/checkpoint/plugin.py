"""Check Point Management plugin (kind "topology"): the gateways, clusters, cluster members and servers a management server manages.

Talks to the Management API (POST /web_api/<command>, JSON). It logs in with a read-only session, runs only "show" commands and logs out:

    login                       with an API key or a user name and password ("read-only": true)
    show-gateways-and-servers   every managed object with its address, version, hardware and operating system (details-level full)
    logout

The management server knows its gateways but has no ARP or DHCP tables, so no clients are reported and the cluster state is not read here:
use the SNMP plugin on the gateways for the devices behind them. Objects are known by address only, so Netlens matches them to devices by IP.
`diagnose` lists the fields the server answers with, without any address or name. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

PAGE = 100
MAX_NODES = 500


class CheckpointError(Exception):
    pass


class AuthRefused(CheckpointError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified else None


class Server:
    def __init__(self, url, api_key="", username="", password="", domain="", verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise CheckpointError(f"{url!r} is not an address like https://192.168.1.10")
        self.base, self.id, self.host, self.timeout = f"https://{parts.netloc}/web_api", parts.netloc, parts.hostname, float(timeout)
        self.api_key, self.username, self.password, self.domain = api_key.strip(), username.strip(), password, domain.strip()
        if not self.api_key and not (self.username and password):
            raise CheckpointError(f"{self.id}: enter an API key, or a user name and password")
        self.sid = None
        self.context = ssl.create_default_context()
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, command, body=None):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        request = urllib.request.Request(f"{self.base}/{command}", data=json.dumps(body or {}).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8", "replace"))
                message = str(detail.get("message") or detail.get("code") or "")[:200]
            except (ValueError, AttributeError):
                message = ""
            if exc.code in (401, 403) or "authentication" in message.lower() or "wrong" in message.lower() and "password" in message.lower():
                raise AuthRefused(f"{self.id} refused the login ({message or 'wrong API key, user name or password, or this machine may not call the API'})")
            raise CheckpointError(f"{self.id} answered HTTP {exc.code} for {command}" + (f" ({message})" if message else ""))
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise CheckpointError(f"{self.id}: the certificate is not trusted ({exc.reason.verify_message}); install your own certificate or untick Verify TLS certificate")
            raise CheckpointError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise CheckpointError(f"{self.id} did not answer properly (is the Management API on?): {exc}")

    def login(self):
        body = {"read-only": True}
        body.update({"api-key": self.api_key} if self.api_key else {"user": self.username, "password": self.password})
        if self.domain:
            body["domain"] = self.domain
        answer = self.call("login", body)
        if not isinstance(answer, dict) or not answer.get("sid"):
            raise AuthRefused(f"{self.id} did not open a session")
        self.sid = answer["sid"]
        return answer

    def logout(self):
        if self.sid:
            try:
                self.call("logout", {})
            except CheckpointError:
                pass
            self.sid = None

    def objects(self):
        out, offset = [], 0
        while offset < MAX_NODES * 4:
            answer = self.call("show-gateways-and-servers", {"limit": PAGE, "offset": offset, "details-level": "full"})
            page = [o for o in (answer.get("objects") or []) if isinstance(o, dict)] if isinstance(answer, dict) else []
            out.extend(page)
            total = answer.get("total") if isinstance(answer, dict) else None
            offset += PAGE
            if not page or (isinstance(total, int) and offset >= total):
                break
        return out


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of a Check Point management server")
    out = []
    for i, r in enumerate(items, 1):
        if not str(r.get("host") or "").strip():
            raise ValueError(f"line {i}: enter the address")
        out.append(Server(str(r["host"]), str(r.get("api_key") or ""), str(r.get("username") or ""), str(r.get("password") or ""), str(r.get("domain") or ""),
                          config.get("verify_tls", True), config.get("timeout") or 30))
    return out


KINDS = {"simple-gateway": "gateway", "CpmiGatewayCluster": "cluster", "simple-cluster": "cluster", "CpmiClusterMember": "member", "cluster-member": "member",
         "CpmiHostCkp": "management server", "checkpoint-host": "server", "CpmiGatewayPlain": "gateway", "CpmiVsClusterNetobj": "virtual system cluster", "CpmiVsxClusterNetobj": "VSX cluster"}


def _name(value):
    return value.get("name") if isinstance(value, dict) else value


def read(server):
    server.login()
    try:
        objects = server.objects()
    finally:
        server.logout()
    nodes, problems = [], []
    for o in objects:
        ip = _ipv4(o.get("ipv4-address"))
        name = str(o.get("name") or "")[:100]
        if not ip or not name:
            continue
        kind = KINDS.get(str(o.get("type") or ""), str(o.get("type") or "")[:40])
        model = " ".join(str(x) for x in (_name(o.get("hardware")), _name(o.get("operating-system"))) if x)[:100] or None
        version = str(_name(o.get("version")) or "")[:60]
        node = {"ip": ip, "name": name, "role": "node", "model": model}
        if version:
            node["firewall"] = {"version": version, "model": kind}
        nodes.append(node)
        sic = str(_name(o.get("sic-state")) or o.get("communication-state") or "").lower()
        if sic and sic not in ("communicating", "trust established", "established", "ok"):
            problems.append(f"{name}: {sic}")
    return nodes[:MAX_NODES], problems


def connect(config):
    reads, errors = [], []
    for server in parse_servers(config):
        try:
            reads.append((server,) + read(server))
        except AuthRefused:
            raise
        except CheckpointError as exc:
            errors.append(str(exc))
    if not reads:
        raise CheckpointError("; ".join(errors) or "no management server answered")
    return reads, errors


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, errors = connect(config)
    total = sum(len(r[1]) for r in reads)
    message = f"Connected to {len(reads)} management server(s): {total} gateway(s), cluster(s) and server(s) with an address"
    problems = [p for r in reads for p in r[2]]
    if problems:
        message += ". Not communicating with the management server: " + "; ".join(problems[:5])
    if errors:
        message += ". Not reachable: " + "; ".join(errors)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    seen, nodes = set(), []
    for _, found, _ in reads:
        for node in found:
            if node["ip"] not in seen:
                seen.add(node["ip"])
                nodes.append(node)
    return {"nodes": nodes, "clients": []}


def _problem(exc):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{2,5})?\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the management servers answer, as counts and field names (no addresses, names or keys)."""
    try:
        servers = parse_servers(config)
    except (ValueError, CheckpointError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            answer = server.login()
            entry["steps"]["login"] = {"ok": True, "fields": sorted(answer)[:30], "api_server_version": str(answer.get("api-server-version") or "")}
            try:
                objects = server.objects()
                entry["steps"]["gateways_and_servers"] = {"ok": True, "count": len(objects), "types": sorted({str(o.get("type")) for o in objects})[:20],
                                                           "fields": sorted({k for o in objects[:50] for k in o})[:60], "with_address": sum(1 for o in objects if _ipv4(o.get("ipv4-address")))}
            finally:
                server.logout()
        except AuthRefused:
            raise
        except CheckpointError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc)}
    return report
