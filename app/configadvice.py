"""Recommendations from the settings a router, firewall or controller reports (see app/configchange.py).

Two layers. A small set of rules that read the same on every vendor (DNS servers outside the network, remote administration, Telnet, open or old Wi-Fi security, WPS, UPnP,
firewall off, a DMZ host, port forwards to dangerous ports, "allow everything" rules): deterministic, tested, offline, and the source of the events, the dashboard and the
problem list. And an optional review by the language model of the digital engineer, for the long tail and for vendors without rules: advice only, shown apart, never an alert.

Read-only. Nothing is ever written to a device. A finding can be accepted by an administrator with a reason ("the DMZ host is the game console"): it then stays out of the
problem list but remains visible on the device.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import sqlite3

from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

VENDORS = ("asus", "unifi", "omada")                 # plugins whose setting names the rules know
ACCEPTED_KEY = "config.advice.accepted"            # {"<device id>:<finding id>": {"reason", "who", "ts"}}
SEEN_KEY = "config.advice.seen."                   # + device id: the findings (risk or warn) the last evaluation had, to raise an event only for a new one
REVIEW_KEY = "config.review."                      # + device id: the last review of the language model
RISKY_PORTS = {21, 23, 69, 135, 137, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}
PORT_NAMES = {21: "FTP", 23: "Telnet", 69: "TFTP", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL",
              3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def supported(plugin_id: str) -> bool:
    return plugin_id in VENDORS


# ----------------------------------------------------------------------------- small helpers
def _ip(text: str):
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def _is_private(text: str) -> bool:
    ip = _ip(text)
    return bool(ip and (ip.is_private or ip.is_link_local or ip.is_loopback))


def _is_public(text: str) -> bool:
    ip = _ip(text)
    return bool(ip and ip.version == 4 and not (ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved))


def typo_of_private(text: str) -> str | None:
    """A public address that is one mistyped first number away from a private range ("102.168.0.200" for "192.168.0.200"), or None."""
    ip = _ip(text)
    if not ip or ip.version != 4 or not _is_public(text):
        return None
    a, b, c, d = str(ip).split(".")
    if b == "168":
        return f"192.168.{c}.{d}"
    if 16 <= int(b) <= 31 and a != "172":
        return f"172.{b}.{c}.{d}"
    return None


def _on(value: str | None) -> bool | None:
    if value is None:
        return None
    return str(value).strip().lower() in ("1", "true", "on", "yes", "enabled")


def _dns_list(items: dict, *keys: str) -> list[str]:
    return [v.strip() for v in (items.get(k, "") for k in keys) if v and v.strip() and v.strip() != "0.0.0.0"]


def _forward_ports(value: str) -> set[int]:
    text = IPV4.sub(" ", value)
    return {int(n) for n in re.findall(r"\b\d{1,5}\b", text) if 0 < int(n) <= 65535}


# ----------------------------------------------------------------------------- facts per vendor
ASUS_AUTH = {"open": "open", "shared": "wep", "psk": "wpa1", "psk2": "wpa2", "pskpsk2": "wpa1+2", "sae": "wpa3", "psk2sae": "wpa2+3", "wpa": "enterprise", "wpa2": "enterprise", "wpawpa2": "enterprise", "radius": "enterprise"}
LABELS = {"open": "no password (open)", "wep": "WEP", "wpa1": "WPA (the old version)", "wpa1+2": "WPA and WPA2 together"}


def _wifi_asus(items: dict) -> list[dict]:
    out = []
    for band, label in (("2g", "2.4 GHz"), ("5g", "5 GHz")):
        auth = ASUS_AUTH.get(items.get(f"wifi.{band}.auth", ""), None)
        if auth:
            out.append({"name": f"{label} ({items.get(f'wifi.{band}.ssid', '')})".replace(" ()", ""), "auth": auth, "tkip": False, "keys": [f"wifi.{band}.auth"]})
    return out


def _networks(items: dict, prefix: str) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for key, value in items.items():
        if key.startswith(prefix + "."):
            name, _, field = key[len(prefix) + 1:].rpartition(".")
            if name:
                found.setdefault(name, {})[field] = value
    return found


def _wifi_unifi(items: dict) -> list[dict]:
    out = []
    for name, f in _networks(items, "wifi").items():
        if f.get("enabled") == "false":
            continue
        sec, mode = f.get("security", ""), f.get("wpa_mode", "")
        auth = "open" if sec == "open" else ("enterprise" if sec == "wpaeap" else ("wpa1" if mode == "wpa1" else None))
        if auth:
            out.append({"name": name, "auth": auth, "tkip": f.get("wpa_enc") == "tkip" and auth != "open", "keys": [f"wifi.{name}.security"]})
        elif f.get("wpa_enc") == "tkip":
            out.append({"name": name, "auth": "wpa2", "tkip": True, "keys": [f"wifi.{name}.wpa_enc"]})
    return out


def _wifi_omada(items: dict) -> list[dict]:
    out = []
    for name, f in _networks(items, "wifi").items():
        if f.get("enable") == "false":
            continue
        auth = {"0": "open", "1": "wep", "2": "enterprise"}.get(f.get("security", ""))
        if auth:
            out.append({"name": name, "auth": auth, "tkip": False, "keys": [f"wifi.{name}.security"]})
    return out


def facts(plugin_id: str, items: dict[str, str]) -> dict:
    """What the rules look at, the same shape for every vendor. A value that the plugin does not report stays None, and no rule fires on it."""
    f: dict = {"wan_dns": [], "dhcp_dns": [], "dhcp_dns_all_read": False, "remote_admin": None, "telnet": None, "ssh_wan": None, "http_admin": None, "upnp": None, "wps": None,
               "firewall": None, "dmz": None, "wifi": [], "forwards": [], "rules": []}
    if plugin_id == "asus":
        f["wan_dns"] = _dns_list(items, "wan.dns1", "wan.dns2") if items.get("wan.dns_auto") == "0" else []
        f["dhcp_dns"] = _dns_list(items, "lan.dhcp_dns1", "lan.dhcp_dns2")
        f["dhcp_dns_all_read"] = "lan.dhcp_dns2" in items
        f["remote_admin"] = _on(items.get("admin.wan_access"))
        f["telnet"] = _on(items.get("admin.telnet"))
        f["ssh_wan"] = _on(items.get("admin.ssh_wan")) if items.get("admin.ssh") not in (None, "0") else False
        f["http_admin"] = {"0": "http", "1": "https", "2": "both"}.get(items.get("admin.http", ""))
        f["upnp"] = _on(items.get("nat.upnp"))
        f["wps"] = _on(items.get("wifi.wps"))
        f["firewall"] = _on(items.get("security.firewall"))
        f["dmz"] = items.get("nat.dmz") or None
        f["wifi"] = _wifi_asus(items)
    elif plugin_id == "unifi":
        f["wifi"] = _wifi_unifi(items)
    elif plugin_id == "omada":
        f["wifi"] = _wifi_omada(items)
    f["forwards"] = [(k.split(".", 1)[1], v) for k, v in items.items() if k.startswith("portforward.") and "enabled=false" not in v]
    f["rules"] = [(k.split(".", 1)[1], v) for k, v in items.items() if k.startswith("firewall.") and "enabled=false" not in v]
    return f


# ----------------------------------------------------------------------------- rules
def _f(fid: str, title: str, status: str, severity: str, evidence: str, steps: list[str], keys: list[str] | None = None) -> dict:
    return {"id": fid, "title": title, "status": status, "severity": severity, "evidence": evidence, "steps": steps, "keys": keys or []}


def evaluate(plugin_id: str, items: dict[str, str], known_dns: dict[str, str] | None = None) -> tuple[list[dict], int]:
    """(findings, rules checked). `known_dns`: addresses of devices Netlens knows, with their name, to say what a DNS server is."""
    f = facts(plugin_id, items)
    known_dns = known_dns or {}
    out: list[dict] = []
    checked = 0

    # DNS servers
    for where, servers, keys in (("The router's own DNS servers", f["wan_dns"], ["wan.dns1", "wan.dns2"]), ("The DNS servers handed out by DHCP", f["dhcp_dns"], ["lan.dhcp_dns1", "lan.dhcp_dns2"])):
        if not servers:
            continue
        checked += 1
        private = [s for s in servers if _is_private(s)]
        for s in [s for s in servers if _is_public(s)]:
            guess = typo_of_private(s)
            if guess:
                out.append(_f(f"dns-typo:{s}", "A DNS server looks like a typing mistake", "risk", "high",
                              f"{where} include {s}, a public address, next to local ones ({', '.join(private) or 'none'}). It differs from {guess} in the first number only. Whenever the first server is slow or down, names are resolved by whoever owns {s}.",
                              [f"Open the router's WAN or DHCP DNS settings and check the server {s}", f"If {guess} was meant, correct it; otherwise remove the entry or use a resolver you trust"], keys))
            elif private:
                out.append(_f(f"dns-mixed:{s}", "A public DNS server sits next to local ones", "warn", "medium",
                              f"{where} include {s}, a public address, next to local ones ({', '.join(private)}). Queries that fall back to it leave the network and are not filtered by your own resolver.",
                              ["Remove the public server if it is not intended, or make it the intended fallback on purpose"], keys))
        if len(servers) == 1 and (where.startswith("The DNS servers handed out") and f["dhcp_dns_all_read"] or where.startswith("The router's")):
            name = known_dns.get(servers[0])
            out.append(_f(f"dns-single:{keys[0]}", "Only one DNS server is configured", "warn", "low",
                          f"{where} list one server only: {servers[0]}{f' ({name})' if name else ''}. If it stops, name resolution stops for everything that uses it.",
                          ["Add a second resolver (another Pi-hole/AdGuard instance, the router, or a trusted public one)"], keys[:1]))

    def flag(value, fid, title, status, severity, evidence, steps, keys):
        nonlocal checked
        if value is None:
            return
        checked += 1
        if value:
            out.append(_f(fid, title, status, severity, evidence, steps, keys))

    flag(f["remote_admin"], "remote-admin", "The router can be administered from the internet", "risk", "critical",
         "Remote administration from the WAN is switched on. Anybody on the internet can reach the login page.", ["Switch off remote (WAN) access to the administration page", "If you need it, use a VPN into the network instead"], ["admin.wan_access"])
    flag(f["telnet"], "telnet", "Telnet is enabled", "risk", "high", "Telnet sends the password in clear text and is a favourite target.", ["Switch Telnet off; use SSH if you need a shell"], ["admin.telnet"])
    flag(f["ssh_wan"], "ssh-wan", "SSH can be reached from the internet", "risk", "high", "SSH is enabled and allowed from the WAN.", ["Allow SSH from the LAN only, or use key-only login behind a VPN"], ["admin.ssh_wan"])
    if f["http_admin"] is not None:
        checked += 1
        if f["http_admin"] == "http":
            out.append(_f("http-admin", "The admin page works over HTTP only", "warn", "medium", "The administration page is served without encryption; the password crosses the network in clear text.", ["Switch the router's administration to HTTPS only"], ["admin.http"]))
        elif f["http_admin"] == "both":
            out.append(_f("http-admin", "The admin page also answers over HTTP", "warn", "low", "HTTP and HTTPS are both enabled for administration. Many routers redirect HTTP to HTTPS before the login, which is harmless; check yours does.", ["Set the administration to HTTPS only"], ["admin.http"]))
    flag(f["upnp"], "upnp", "UPnP is switched on", "warn", "medium",
         "Any device on the network can open ports to the internet without asking. A compromised device or a careless app can expose itself that way.", ["Switch UPnP off and add the port forwards you need by hand", "If a console or game needs it, accept this finding with the reason"], ["nat.upnp"])
    flag(f["wps"], "wps", "WPS is switched on", "warn", "low", "WPS lets a device join with a short PIN, which can be guessed; several routers are known to be weak here.", ["Switch WPS off; join devices with the Wi-Fi password"], ["wifi.wps"])
    if f["firewall"] is not None:
        checked += 1
        if not f["firewall"]:
            out.append(_f("firewall-off", "The router's firewall is switched off", "risk", "critical", "The firewall setting reports off.", ["Switch the firewall on"], ["security.firewall"]))
    if f["dmz"] is not None or plugin_id == "asus":
        checked += 1
        if f["dmz"]:
            out.append(_f("dmz", "A DMZ host is set", "risk", "high", f"Everything from the internet that no rule claims goes to {f['dmz']}. That device is fully exposed.", ["Remove the DMZ host and forward only the ports that are needed"], ["nat.dmz"]))

    # Wi-Fi
    for w in f["wifi"]:
        checked += 1
        name = w["name"]
        if w["auth"] == "open":
            out.append(_f(f"wifi-open:{name}", "A Wi-Fi network has no password", "risk", "high", f"{name}: anybody in range can join and see the traffic of the other open-network users. If it is a guest network, it should at least be isolated from the LAN.", ["Set a WPA2 or WPA3 password, or make it a guest network with isolation and a captive portal"], w["keys"]))
        elif w["auth"] in ("wep", "wpa1"):
            out.append(_f(f"wifi-old:{name}", f"A Wi-Fi network uses old security ({LABELS[w['auth']]})", "risk", "high", f"{name}: {LABELS[w['auth']]} can be broken within minutes.", ["Switch to WPA2 (AES) or WPA3"], w["keys"]))
        elif w["auth"] == "wpa1+2" or w["tkip"]:
            out.append(_f(f"wifi-legacy:{name}", "A Wi-Fi network still allows legacy WPA", "warn", "medium", f"{name}: the network still allows WPA with TKIP for old devices, which weakens the whole network.", ["Switch to WPA2 (AES) only, or WPA2/WPA3"], w["keys"]))

    # port forwards and rules
    for name, value in f["forwards"]:
        checked += 1
        ports = sorted(_forward_ports(value) & RISKY_PORTS)
        if ports:
            what = ", ".join(f"{p} ({PORT_NAMES[p]})" for p in ports)
            out.append(_f(f"forward-risky:{name}", f"A port forward exposes {what}", "risk", "high", f"The rule '{name}' ({value}) sends internet traffic to a service that should not be reachable from outside.", ["Remove the forward and reach the service through a VPN"], [f"portforward.{name}"]))
    for name, value in f["rules"]:
        checked += 1
        v = value.lower()
        if re.match(r"^(accept|allow|1)\b", v) and re.search(r"from any\b", v) and re.search(r"to any\b", v):
            out.append(_f(f"rule-any:{name}", "A firewall rule allows everything", "warn", "medium", f"The rule '{name}' ({value}) accepts all traffic from anywhere to anywhere, which cancels the rules below it.", ["Narrow the rule to the sources, destinations and ports that are needed"], [f"firewall.{name}"]))
    return out, checked


# ----------------------------------------------------------------------------- state: accepted findings, events
def _load(conn: sqlite3.Connection, key: str, default):
    try:
        value = json.loads(get_setting(conn, key) or "")
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def accepted(conn: sqlite3.Connection) -> dict:
    return _load(conn, ACCEPTED_KEY, {})


def accept(conn: sqlite3.Connection, device_id: int, finding_id: str, reason: str, who: str) -> None:
    data = accepted(conn)
    data[f"{device_id}:{finding_id}"] = {"reason": reason.strip()[:300], "who": who, "ts": utcnow()}
    set_setting(conn, ACCEPTED_KEY, json.dumps(data))


def unaccept(conn: sqlite3.Connection, device_id: int, finding_id: str) -> bool:
    data = accepted(conn)
    gone = data.pop(f"{device_id}:{finding_id}", None) is not None
    set_setting(conn, ACCEPTED_KEY, json.dumps(data))
    return gone


def _known_dns(conn: sqlite3.Connection) -> dict[str, str]:
    return {r["primary_ip"]: (r["hostname"] or r["primary_ip"]) for r in conn.execute("SELECT primary_ip, hostname FROM devices WHERE primary_ip IS NOT NULL")}


def _items_of(conn: sqlite3.Connection, device_id: int):
    row = conn.execute("SELECT plugin_id, items, updated FROM config_state WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        return None
    try:
        items = json.loads(row["items"])
    except ValueError:
        return None
    return row["plugin_id"], items if isinstance(items, dict) else {}, row["updated"]


def for_device(conn: sqlite3.Connection, device_id: int) -> dict | None:
    """The recommendations for one device: open findings, accepted ones (with the reason) and how many rules were checked. None when no plugin reports its settings."""
    got = _items_of(conn, device_id)
    if got is None:
        return None
    plugin_id, items, updated = got
    if not supported(plugin_id):
        return {"plugin": plugin_id, "updated": updated, "rules": False, "checked": 0, "findings": [], "accepted": []}
    findings, checked = evaluate(plugin_id, items, _known_dns(conn))
    ok = accepted(conn)
    open_, done = [], []
    for x in findings:
        mark = ok.get(f"{device_id}:{x['id']}")
        (done if mark else open_).append({**x, "accepted": mark} if mark else x)
    return {"plugin": plugin_id, "updated": updated, "rules": True, "checked": checked, "findings": open_, "accepted": done}


def refresh(conn: sqlite3.Connection, device_id: int, now: str | None = None) -> int:
    """After a sync: raise `config_advice` for a risk or warning that was not there at the last evaluation (the first evaluation only reports risks). Returns how many."""
    advice = for_device(conn, device_id)
    if not advice or not advice["rules"]:
        return 0
    now = now or utcnow()
    current = {x["id"]: x for x in advice["findings"] if x["status"] in ("risk", "warn")}
    raw = get_setting(conn, SEEN_KEY + str(device_id))
    first = raw is None
    try:
        seen = set(json.loads(raw)) if raw else set()
    except ValueError:
        seen = set()
    new = [x for fid, x in current.items() if fid not in seen and (x["status"] == "risk" or not first)]
    name = conn.execute("SELECT COALESCE(hostname, primary_ip, mac) FROM devices WHERE id = ?", (device_id,)).fetchone()
    name = name[0] if name else f"device {device_id}"
    for x in new:
        add_event(conn, "config_advice", f"{name}: {x['title']}"[:400], device_id=device_id, now=now)
    set_setting(conn, SEEN_KEY + str(device_id), json.dumps(sorted(current)))
    conn.commit()
    return len(new)


def attention(conn: sqlite3.Connection) -> list[dict]:
    """Every open risk or warning on every device, for the dashboard, the problem list and Ask."""
    out = []
    for r in conn.execute("SELECT s.device_id, COALESCE(d.hostname, d.primary_ip, d.mac) AS name FROM config_state s JOIN devices d ON d.id = s.device_id"):
        advice = for_device(conn, r["device_id"])
        for x in (advice or {}).get("findings", []):
            if x["status"] in ("risk", "warn"):
                out.append({"device_id": r["device_id"], "device": r["name"], "id": x["id"], "title": x["title"], "status": x["status"], "severity": x["severity"]})
    return out


# ----------------------------------------------------------------------------- the language model's review (optional, advice only)
HINTS = {
    "asus": ("ASUSWRT. Values are the router's own: admin.http 0=HTTP only, 1=HTTPS only, 2=both; 1/0 flags; wifi.*.auth open|shared(WEP)|psk(WPA)|psk2(WPA2)|sae(WPA3)|psk2sae; empty channel = automatic; "
             "nat.dmz empty = none; portforward.* = external port, internal address, internal port, protocol."),
    "unifi": "UniFi Network controller. network.* = networks and VLANs, wifi.* = SSIDs (never their passwords), portforward.* and firewall.* = rules written as action/protocol/source/destination.",
    "omada": "TP-Link Omada controller. network.* = networks, wifi.* = SSIDs (security 0=open, 1=WEP, 2=enterprise, 3=personal; never their passwords), portforward.* and firewall.* = rules.",
}
REVIEW_SYSTEM = (
    "You review the configuration of a network device for a network administrator. You get the settings as 'key = value' lines. Report only real weaknesses or misconfigurations that "
    "follow from these exact lines, and cite the setting key for each. Do not repeat the findings that are listed as already known. Do not invent settings, do not guess values that are not given, "
    "and do not suggest changes that are not needed. Answer with a JSON list only, at most 8 items: "
    '[{"key": "<a key from the list>", "title": "<short>", "why": "<one or two sentences>", "fix": "<one sentence>", "severity": "low|medium|high"}]. An empty list [] is a good answer.'
)


def _digest(items: dict) -> str:
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()[:16]


def _parse_review(text: str, items: dict) -> list[dict]:
    """Only items that cite a setting that exists; anything else the model made up is dropped."""
    start, end = text.find("["), text.rfind("]")
    if start < 0 or end < start:
        return []
    try:
        raw = json.loads(text[start:end + 1])
    except ValueError:
        return []
    out = []
    for r in raw if isinstance(raw, list) else []:
        if not isinstance(r, dict) or str(r.get("key", "")) not in items:
            continue
        sev = r.get("severity") if r.get("severity") in ("low", "medium", "high") else "low"
        out.append({"key": str(r["key"])[:120], "title": str(r.get("title", ""))[:120], "why": str(r.get("why", ""))[:400], "fix": str(r.get("fix", ""))[:300], "severity": sev})
    return [x for x in out if x["title"]][:8]


def review(conn: sqlite3.Connection, device_id: int, force: bool = False, ask=None) -> dict:
    """Ask the language model for a second opinion on the settings. Cached by a digest of the settings, so an unchanged configuration is not sent again.
    Raises LookupError (nothing recorded), PermissionError (no model set up or Insights not allowed)."""
    from app import insights

    got = _items_of(conn, device_id)
    if got is None:
        raise LookupError("no settings are recorded for this device")
    plugin_id, items, _updated = got
    if ask is None and not (insights.allowed(conn) and insights.llm_ready(conn)):
        raise PermissionError("the digital engineer is not set up for Insights (Settings → AI)")
    digest = _digest(items)
    cached = _load(conn, REVIEW_KEY + str(device_id), {})
    if cached.get("digest") == digest and not force:
        return {**cached, "cached": True}
    known, _n = evaluate(plugin_id, items, _known_dns(conn)) if supported(plugin_id) else ([], 0)
    lines = "\n".join(f"{k} = {v}" for k, v in sorted(items.items()))
    user = (f"Device type: {HINTS.get(plugin_id, plugin_id + ' (no notes available)')}\n\nAlready known findings: "
            + ("; ".join(x["title"] for x in known) or "none") + f"\n\nSettings:\n{lines}")
    answer = insights.complete(conn, REVIEW_SYSTEM, user, ask=ask, timeout=120)
    if answer is None:
        raise ConnectionError("the language model did not answer")
    result = {"digest": digest, "ts": utcnow(), "items": _parse_review(answer, items)}
    set_setting(conn, REVIEW_KEY + str(device_id), json.dumps(result))
    return {**result, "cached": False}


def last_review(conn: sqlite3.Connection, device_id: int) -> dict | None:
    cached = _load(conn, REVIEW_KEY + str(device_id), {})
    got = _items_of(conn, device_id)
    if not cached or got is None:
        return None
    return {**cached, "outdated": cached.get("digest") != _digest(got[1])}
