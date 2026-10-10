"""Technitium DNS Server plugin (kind "dns"): register devices in DNS and keep their addresses current.

Talks to the Technitium HTTP API with a token (Authorization: Bearer). Per server it reads:

    GET /api/zones/list                                                   the zones and their type (Primary / Secondary ...)
    GET /api/zones/records/get?domain=<zone>&zone=<zone>&listZone=true   every record of a zone (with its comment)
    GET /api/admin/cluster/state                                          whether the server is a node of a cluster

and writes with records/add, records/update and records/delete. Netlens decides WHAT to change (see app/dns/plan.py); this
plugin only does it, and it adds its own safety net: before an add it asks the server whether the name is still free, and an
update or delete names the exact current value, so a record that changed meanwhile is never overwritten.

Where to write: a zone is written on every server that holds it as a *Primary* zone. With a primary and a secondary server that
is the primary; in a cluster it is the primary node (the other nodes carry the zone as Secondary and receive it from there).

Netlens passes two extra settings next to the user's: `zones` (the forward zones to read) and `marker` (the comment that marks
records as made by Netlens). Standard library only.
"""

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_MARKER = "managed by Netlens"
TYPES = ("A", "AAAA", "PTR", "CNAME")
REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


class TechnitiumError(Exception):
    pass


class AuthRefused(TechnitiumError):
    auth_failed = True


def _name(value):
    return str(value or "").strip().rstrip(".").lower()


class Server:
    def __init__(self, url, token, verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if not re.match(r"^https?://[^/\s]+$", url):
            raise TechnitiumError(f"{url!r} is not an address like http://192.168.0.2:5380")
        self.url, self.token, self.timeout = url, token, float(timeout)
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.zones = {}       # name -> Technitium zone type
        self.cluster = None   # None, or the node type of this server ("Primary" / "Secondary")

    def call(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        request = urllib.request.Request(f"{self.url}{path}?{query}", headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raise TechnitiumError(f"{self.url} answered HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise TechnitiumError(f"cannot reach {self.url}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise TechnitiumError(f"{self.url} did not answer properly: {exc}")
        status = data.get("status") if isinstance(data, dict) else None
        if status == "invalid-token":
            raise AuthRefused(f"{self.url} refused the token (wrong, expired or revoked)")
        if status != "ok":
            raise TechnitiumError(str(data.get("errorMessage") or "the server reported an error")[:300] if isinstance(data, dict) else "unexpected answer")
        return data.get("response") or {}

    def load(self):
        for zone in self.call("/api/zones/list").get("zones", []):
            if not zone.get("internal"):
                self.zones[_name(zone.get("name"))] = zone.get("type")
        try:
            state = self.call("/api/admin/cluster/state")
            if state.get("clusterInitialized"):
                me = next((n for n in state.get("clusterNodes", []) if n.get("state") == "Self"), None)
                self.cluster = (me or {}).get("type") or "Secondary"
        except AuthRefused:
            raise
        except TechnitiumError:
            self.cluster = None   # no permission to ask, or an older server without clusters
        return self

    def records(self, zone):
        return self.call("/api/zones/records/get", domain=zone, zone=zone, listZone="true").get("records", [])


def parse_servers(config):
    urls = [u for u in re.split(r"[,;\s]+", str(config.get("servers") or "").strip()) if u]
    if not urls:
        raise ValueError("enter the address of at least one Technitium server")
    tokens = [t for t in re.split(r"[,;\s]+", str(config.get("tokens") or "").strip()) if t]
    if not tokens:
        raise ValueError("enter an API token")
    if len(tokens) not in (1, len(urls)):
        raise ValueError(f"enter one token for all servers or one for each of the {len(urls)} servers")
    timeout = config.get("timeout") or 15
    verify = config.get("verify_tls", True)
    return [Server(url, tokens[0] if len(tokens) == 1 else tokens[i], verify, timeout) for i, url in enumerate(urls)]


def connect(config):
    servers, problems = [], []
    for server in parse_servers(config):
        try:
            servers.append(server.load())
        except AuthRefused:
            raise
        except TechnitiumError as exc:
            problems.append(str(exc))
    if not servers:
        raise TechnitiumError("; ".join(problems) or "no server answered")
    return servers, problems


def _primaries(servers, zone):
    """The servers on which `zone` is a Primary zone: that is where it can be written."""
    return [s for s in servers if s.zones.get(zone) == "Primary"]


def _holder(servers, zone):
    primaries = _primaries(servers, zone)
    if primaries:
        return primaries[0]
    return next((s for s in servers if zone in s.zones), None)


def _value(row):
    data = row.get("rData") or {}
    rtype = row.get("type")
    if rtype in ("A", "AAAA"):
        return str(data.get("ipAddress") or "")
    if rtype == "PTR":
        return _name(data.get("ptrName"))
    if rtype == "CNAME":
        return _name(data.get("cname"))
    return ""


def _is_reverse(zone):
    return zone.endswith(REVERSE_SUFFIXES)


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, problems = connect(config)
    wanted = [_name(z) for z in config.get("zones", [])]
    parts = [f"Connected to {len(servers)} server(s)"]
    clusters = [s.cluster for s in servers if s.cluster]
    if clusters:
        parts.append("cluster: " + ", ".join(f"{c.lower()} node" for c in clusters))
    for zone in wanted:
        holder = _holder(servers, zone)
        if holder is None:
            parts.append(f"zone {zone} NOT found on any server")
        elif not _primaries(servers, zone):
            parts.append(f"zone {zone} found, but only as a secondary zone (read-only)")
        else:
            parts.append(f"zone {zone} writable")
    reverse = sorted({z for s in servers for z in s.zones if _is_reverse(z)})
    parts.append(f"{len(reverse)} reverse zone(s)")
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
        holder = _holder(servers, zone)
        if holder is None:
            continue
        zones.append({"name": zone, "kind": "reverse" if _is_reverse(zone) else "forward", "writable": bool(_primaries(servers, zone))})
        for row in holder.records(zone):
            if row.get("type") not in TYPES or row.get("disabled"):
                continue
            comment = str(row.get("comments") or "")
            records.append({
                "zone": zone, "name": _name(row.get("name")), "type": row["type"], "value": _value(row), "ttl": row.get("ttl"),
                "managed": marker in comment.lower(), "comment": comment[:200],
            })
    writable = [s.url.split("//", 1)[-1] for s in servers if any(s.zones.get(z) == "Primary" for z in names)]
    return {"zones": zones, "records": records, "server": ", ".join(writable)[:100] or None}


def _exists(server, zone, change):
    """Is there already a record of this kind at this name? (checked right before an add, in case someone was faster)"""
    rows = server.call("/api/zones/records/get", domain=change["name"], zone=zone).get("records", [])
    kinds = ("PTR",) if change["type"] == "PTR" else ("A", "AAAA", "CNAME")
    return [r for r in rows if r.get("type") in kinds and _name(r.get("name")) == _name(change["name"])]


def _apply_one(server, change):
    zone, rtype, name = change["zone"], change["type"], change["name"]
    comment = change.get("comment") or DEFAULT_MARKER
    action = change["action"]
    if action == "add":
        if _exists(server, zone, change):
            raise TechnitiumError(f"{name} got a record in the meantime; nothing was written")
        params = {"domain": name, "zone": zone, "type": rtype, "comments": comment}
        if rtype == "PTR":
            params["ptrName"] = change["value"]
        else:
            params.update(ipAddress=change["value"], ptr="false")
        server.call("/api/zones/records/add", **params)
    elif action == "update":
        params = {"domain": name, "zone": zone, "type": rtype, "comments": comment}
        if rtype == "PTR":
            params.update(ptrName=change["old_value"], newPtrName=change["value"])
        else:
            params.update(ipAddress=change["old_value"], newIpAddress=change["value"], ptr="false")
        server.call("/api/zones/records/update", **params)
    elif action == "delete":
        params = {"domain": name, "zone": zone, "type": rtype}
        if rtype == "PTR":
            params["ptrName"] = change["value"]
        else:
            params["ipAddress"] = change["value"]
        server.call("/api/zones/records/delete", **params)
    else:
        raise TechnitiumError(f"unknown action {action!r}")


def apply(config, changes):
    servers, _ = connect(config)
    results = []
    for change in changes:
        targets = _primaries(servers, change["zone"])
        if not targets:
            results.append({"id": change["id"], "ok": False, "error": f"no server has {change['zone']} as a primary zone (it is read-only or missing)"})
            continue
        errors = []
        for server in targets:
            try:
                _apply_one(server, change)
            except AuthRefused:
                raise
            except TechnitiumError as exc:
                errors.append(f"{server.url.split('//', 1)[-1]}: {exc}" if len(targets) > 1 else str(exc))
        results.append({"id": change["id"], "ok": not errors, "error": "; ".join(errors)[:300] or None})
    return results


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What the servers answer, as counts and yes/no (no names, addresses or tokens)."""
    report = {"servers": []}
    try:
        servers = parse_servers(config)
    except ValueError as exc:
        return {"error": str(exc)}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            server.load()
        except AuthRefused:
            raise
        except TechnitiumError as exc:
            entry["error"] = _problem(exc)
            continue
        entry["zones"] = {"count": len(server.zones), "primary": sum(1 for t in server.zones.values() if t == "Primary"),
                          "secondary": sum(1 for t in server.zones.values() if t == "Secondary"), "reverse": sum(1 for z in server.zones if _is_reverse(z))}
        entry["cluster"] = server.cluster
        sample = next((z for z in [_name(z) for z in config.get("zones", [])] if z in server.zones), None)
        if sample:
            try:
                rows = server.records(sample)
                entry["steps"]["records"] = {"ok": True, "count": len(rows), "types": sorted({r.get("type", "?") for r in rows}),
                                             "comments_returned": any("comments" in r for r in rows), "with_comment": sum(1 for r in rows if r.get("comments"))}
            except TechnitiumError as exc:
                entry["steps"]["records"] = {"ok": False, "error": _problem(exc)}
            try:
                options = server.call("/api/zones/options/get", zone=sample)
                entry["steps"]["dynamic_updates"] = {"ok": True, "policy": options.get("update")}
            except TechnitiumError as exc:
                entry["steps"]["dynamic_updates"] = {"ok": False, "error": _problem(exc)}
    return report
