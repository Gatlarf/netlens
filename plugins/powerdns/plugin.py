"""PowerDNS Authoritative plugin (kind "dns"): register devices in DNS and keep their addresses current.

Talks to PowerDNS's built-in HTTP API (header X-API-Key) under /api/v1/servers/<server id>:

    GET   /zones                  the zones: name, kind (Native, Master, Primary, Slave, Secondary ...)
    GET   /zones/<id>             one zone with all record sets: name, type, ttl, records [{content, disabled}], comments [{content, account}]
    PATCH /zones/<id>             {"rrsets": [{name, type, ttl, changetype: REPLACE | DELETE, records, comments}]}

PowerDNS keeps records in *record sets* (all A records of one name) and attaches comments to a set, not to a record. So the marker goes on the
set, and the plugin only touches a set when it carries the marker AND holds exactly the one record Netlens wrote. Where a set has records of
other origin, an add is refused ("got a record in the meantime"), so a foreign record is never taken over. Reverse zones (`...in-addr.arpa.`)
are found by themselves. Names are dotted at the end in PowerDNS and without the dot in Netlens. Standard library only.
"""

import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MARKER = "managed by Netlens"
TYPES = ("A", "AAAA", "PTR", "CNAME")
WRITABLE_KINDS = ("native", "master", "primary", "producer")
REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


class PowerdnsError(Exception):
    pass


class AuthRefused(PowerdnsError):
    auth_failed = True


def _name(value):
    return str(value or "").strip().rstrip(".").lower()


def _dotted(value):
    return _name(value) + "."


class Server:
    def __init__(self, url, api_key, server_id="localhost", verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if not re.match(r"^https?://[^/\s]+$", url):
            raise PowerdnsError(f"{url!r} is not an address like http://192.168.0.2:8081")
        sid = (server_id or "localhost").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", sid):
            raise PowerdnsError(f"{sid!r} is not a server id")
        self.url, self.key, self.timeout, self.base = url, api_key, float(timeout), f"/api/v1/servers/{sid}"
        self.id = url.split("//", 1)[-1]
        self.version = None
        self.zones = {}        # name (no dot) -> {"id", "kind"}
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"X-API-Key": self.key, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.url}{self.base}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the API key")
            try:
                detail = json.loads(exc.read().decode("utf-8", "replace")).get("error")
            except (ValueError, AttributeError):
                detail = None
            raise PowerdnsError(f"{self.id} answered HTTP {exc.code}" + (f": {str(detail)[:200]}" if detail else ""))
        except urllib.error.URLError as exc:
            raise PowerdnsError(f"cannot reach {self.id}: {exc.reason}")
        except OSError as exc:
            raise PowerdnsError(f"{self.id} did not answer properly: {exc}")
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise PowerdnsError(f"{self.id} did not answer properly (not JSON; is this the PowerDNS API?)")

    def load(self):
        info = self.call("GET", "")
        if not isinstance(info, dict) or info.get("daemon_type") not in (None, "authoritative"):
            raise PowerdnsError(f"{self.id} is not PowerDNS Authoritative (daemon_type {info.get('daemon_type') if isinstance(info, dict) else '?'})")
        self.version = info.get("version")
        for zone in self.call("GET", "/zones"):
            self.zones[_name(zone.get("name"))] = {"id": zone.get("id"), "kind": str(zone.get("kind") or "").lower()}
        return self

    def writable(self, zone):
        return self.zones.get(zone, {}).get("kind") in WRITABLE_KINDS

    def rrsets(self, zone):
        return self.call("GET", f"/zones/{urllib.parse.quote(self.zones[zone]['id'], safe='')}").get("rrsets") or []

    def patch(self, zone, rrset):
        self.call("PATCH", f"/zones/{urllib.parse.quote(self.zones[zone]['id'], safe='')}", {"rrsets": [rrset]})


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one PowerDNS server")
    out = []
    for i, r in enumerate(items, 1):
        url, key = str(r.get("host") or "").strip(), str(r.get("api_key") or "").strip()
        if not url:
            raise ValueError(f"server {i}: enter its address")
        if not key:
            raise ValueError(f"{url}: enter the API key")
        out.append(Server(url, key, str(r.get("server_id") or "localhost"), config.get("verify_tls", True), config.get("timeout") or 15))
    return out


def connect(config):
    servers, problems = [], []
    for server in parse_servers(config):
        try:
            servers.append(server.load())
        except AuthRefused:
            raise
        except PowerdnsError as exc:
            problems.append(str(exc))
    if not servers:
        raise PowerdnsError("; ".join(problems) or "no PowerDNS server answered")
    return servers, problems


def _is_reverse(zone):
    return zone.endswith(REVERSE_SUFFIXES)


def _zone_for(name, zones):
    best = None
    for zone in zones:
        if (name == zone or name.endswith("." + zone)) and (best is None or len(zone) > len(best)):
            best = zone
    return best


def _marked(rrset, marker):
    return any(marker in str(c.get("content") or "").lower() for c in rrset.get("comments") or [])


def _ours(rrset, marker):
    """A set is Netlens' own when it carries the marker. A set with several records still counts, but only its records are changed one by one."""
    return _marked(rrset, marker)


def _value(rtype, content):
    return _name(content) if rtype in ("PTR", "CNAME") else str(content or "").strip()


def _content(rtype, value):
    return _dotted(value) if rtype in ("PTR", "CNAME") else value


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, problems = connect(config)
    marker = (config.get("marker") or DEFAULT_MARKER).lower()
    parts = [f"Connected to {len(servers)} server(s)" + (f" (PowerDNS {', '.join(sorted({s.version for s in servers if s.version}))})" if any(s.version for s in servers) else "")]
    for zone in [_name(z) for z in config.get("zones", [])]:
        holders = [s for s in servers if zone in s.zones]
        parts.append(f"zone {zone} NOT found on any server" if not holders else f"zone {zone} writable" if any(s.writable(zone) for s in holders) else f"zone {zone} found, but only as a secondary zone (read-only)")
    parts.append(f"{len({z for s in servers for z in s.zones if _is_reverse(z)})} reverse zone(s)")
    if problems:
        parts.append("not reachable: " + "; ".join(problems))
    return {"message": ", ".join(parts)}


def fetch(config):
    servers, _ = connect(config)
    marker = (config.get("marker") or DEFAULT_MARKER).lower()
    forward = [_name(z) for z in config.get("zones", [])]
    names = list(dict.fromkeys(forward + sorted({z for s in servers for z in s.zones if _is_reverse(z)})))
    zones, records = [], []
    for zone in names:
        holder = next((s for s in servers if s.writable(zone)), None) or next((s for s in servers if zone in s.zones), None)
        if holder is None:
            continue
        zones.append({"name": zone, "kind": "reverse" if _is_reverse(zone) else "forward", "writable": holder.writable(zone)})
        for rrset in holder.rrsets(zone):
            if rrset.get("type") not in TYPES:
                continue
            marked = _ours(rrset, marker)
            comment = "; ".join(str(c.get("content") or "") for c in rrset.get("comments") or [])[:200]
            for record in rrset.get("records") or []:
                if record.get("disabled"):
                    continue
                records.append({"zone": zone, "name": _name(rrset.get("name")), "type": rrset["type"], "value": _value(rrset["type"], record.get("content")), "ttl": rrset.get("ttl"),
                                "managed": marked, "comment": comment})
    return {"zones": zones, "records": records, "server": ", ".join(s.id for s in servers if any(s.writable(z) for z in names))[:100] or None}


def _set(server, zone, name, rtype, ttl, values, marker):
    server.patch(zone, {"name": _dotted(name), "type": rtype, "ttl": ttl, "changetype": "REPLACE", "records": [{"content": _content(rtype, v), "disabled": False} for v in values],
                        "comments": [{"content": marker, "account": "netlens", "modified_at": int(time.time())}]})


def _find(server, zone, name, rtype):
    return next((r for r in server.rrsets(zone) if _name(r.get("name")) == name and r.get("type") == rtype), None)


def _apply_one(server, change, default_ttl):
    action, rtype, name, zone = change["action"], change["type"], change["name"], change["zone"]
    marker = change.get("comment") or DEFAULT_MARKER
    if rtype not in TYPES:
        raise PowerdnsError(f"{rtype} records are not handled by this plugin")
    if zone not in server.zones or not server.writable(zone):
        raise PowerdnsError(f"{zone} is not a writable zone on {server.id}")
    current = _find(server, zone, name, rtype)
    if action == "add":
        others = [r for r in server.rrsets(zone) if _name(r.get("name")) == name and r.get("type") in ("A", "AAAA", "CNAME") and r.get("records")] if rtype != "PTR" else \
                 [r for r in server.rrsets(zone) if _name(r.get("name")) == name and r.get("type") == "PTR" and r.get("records")]
        if others:
            raise PowerdnsError(f"{name} got a record in the meantime; nothing was written")
        _set(server, zone, name, rtype, default_ttl, [change["value"]], marker)
    elif action == "update":
        if current is None or not _ours(current, marker.lower()):
            raise PowerdnsError(f"{name} is not a record Netlens made; nothing was changed")
        values = [_value(rtype, r.get("content")) for r in current.get("records") or []]
        if len(values) != 1 or values[0] != _value(rtype, change["old_value"]):
            raise PowerdnsError(f"{name} no longer points to {change['old_value']}; nothing was changed")
        _set(server, zone, name, rtype, current.get("ttl") or default_ttl, [change["value"]], marker)
    elif action == "delete":
        if current is None:
            return
        if not _ours(current, marker.lower()):
            raise PowerdnsError(f"{name} is not a record Netlens made; it is left alone")
        values = [_value(rtype, r.get("content")) for r in current.get("records") or []]
        if values != [_value(rtype, change["value"])]:
            raise PowerdnsError(f"{name} holds other records than the one Netlens made; it is left alone")
        server.patch(zone, {"name": _dotted(name), "type": rtype, "changetype": "DELETE"})
    else:
        raise PowerdnsError(f"unknown action {action!r}")


def apply(config, changes):
    servers, _ = connect(config)
    ttl = int(config.get("ttl") or 3600)
    results = []
    for change in changes:
        targets = [s for s in servers if s.writable(change["zone"])]
        if not targets:
            results.append({"id": change["id"], "ok": False, "error": f"no server has {change['zone']} as a writable zone"})
            continue
        errors = []
        for server in targets:
            try:
                _apply_one(server, change, ttl)
            except AuthRefused:
                raise
            except PowerdnsError as exc:
                errors.append(f"{server.id}: {exc}" if len(targets) > 1 else str(exc))
        results.append({"id": change["id"], "ok": not errors, "error": "; ".join(errors)[:300] or None})
    return results


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What the servers answer, as counts and yes/no (no names, addresses or keys)."""
    try:
        servers = parse_servers(config)
    except ValueError as exc:
        return {"error": str(exc)}
    marker = (config.get("marker") or DEFAULT_MARKER).lower()
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            server.load()
        except AuthRefused:
            raise
        except PowerdnsError as exc:
            entry["error"] = _problem(exc)
            continue
        entry["version"] = server.version
        entry["zones"] = {"count": len(server.zones), "kinds": {k: sum(1 for z in server.zones.values() if z["kind"] == k) for k in sorted({z["kind"] for z in server.zones.values()})},
                          "reverse": sum(1 for z in server.zones if _is_reverse(z))}
        sample = next((z for z in [_name(z) for z in config.get("zones", [])] if z in server.zones), None)
        if sample:
            try:
                sets = server.rrsets(sample)
                entry["steps"]["records"] = {"ok": True, "rrsets": len(sets), "types": sorted({r.get("type", "?") for r in sets}), "with_comments": sum(1 for r in sets if r.get("comments")),
                                             "marked": sum(1 for r in sets if _marked(r, marker)), "multi_record_sets": sum(1 for r in sets if len(r.get("records") or []) > 1)}
            except PowerdnsError as exc:
                entry["steps"]["records"] = {"ok": False, "error": _problem(exc)}
    return report
