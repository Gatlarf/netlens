"""OpenWrt plugin (kind "topology"): the router or access point as a node, the devices around it as clients.

Talks to OpenWrt's ubus through its HTTP JSON-RPC endpoint (uhttpd-mod-ubus, POST /ubus). After session.login, read-only calls only:

    session login                       the session id every later call carries (session destroy at the end)
    system board                        host name, model, release
    network.interface dump              interfaces and their IPv4 addresses (the LAN address, is there an active wan?)
    network.device status {name}        the MAC address of the LAN bridge
    luci-rpc getDHCPLeases              leases: macaddr, ipaddr, hostname
    luci-rpc getHostHints               every neighbour the router has seen: MAC -> addresses and name
    luci-rpc getWirelessDevices         radios and their interfaces (ifname)       } only on routers with Wi-Fi
    iwinfo info / assoclist {device}    frequency, and the associated stations: mac, signal, rx/tx rate }

A client that is associated with a radio is `wifi` (band from the frequency, `rssi` from the signal, rates in Mbit/s); every other device the router
knows is `wired`. The router's own MAC addresses are never reported as clients. Several routers and access points can be listed; an access point's
`uplink` (the address of the node it hangs from) becomes its parent. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

NO_SESSION = "00000000000000000000000000000000"
MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_CLIENTS = 4000


class OpenwrtError(Exception):
    pass


class AuthRefused(OpenwrtError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


class Router:
    def __init__(self, url, username, password, role="", uplink="", verify_tls=False, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise OpenwrtError(f"{url!r} is not an address like http://192.168.1.1")
        self.endpoint, self.id, self.host = f"{parts.scheme}://{parts.netloc}/ubus", parts.netloc, parts.hostname
        self.username, self.password, self.timeout = username, password, float(timeout)
        self.role = (role or "auto").strip().lower()
        if self.role not in ("auto", "gateway", "ap"):
            raise OpenwrtError(f"{self.id}: the role must be auto, gateway or ap")
        self.uplink = _ipv4(uplink) if uplink else None
        if uplink and not self.uplink:
            raise OpenwrtError(f"{self.id}: the uplink must be an IPv4 address")
        self.sid = None
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def rpc(self, obj, method, args=None, allow=()):
        """One ubus call; returns the result dict. `allow` lists ubus status codes that mean "nothing there" (returns None)."""
        body = {"jsonrpc": "2.0", "id": 1, "method": "call", "params": [self.sid or NO_SESSION, obj, method, args or {}]}
        request = urllib.request.Request(self.endpoint, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                answer = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raise OpenwrtError(f"{self.id} answered HTTP {exc.code} (is uhttpd-mod-ubus installed?)")
        except urllib.error.URLError as exc:
            raise OpenwrtError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise OpenwrtError(f"{self.id} did not answer properly (is this OpenWrt's /ubus?): {exc}")
        if isinstance(answer, dict) and answer.get("error"):
            code = answer["error"].get("code")
            if code == -32002:
                raise AuthRefused(f"{self.id} says access is denied for {obj} {method}: the login may not use it (see the box at the top of this page)")
            raise OpenwrtError(f"{self.id} reported an error for {obj} {method}: {answer['error'].get('message')}")
        result = (answer or {}).get("result") if isinstance(answer, dict) else None
        if not isinstance(result, list) or not result:
            raise OpenwrtError(f"{self.id} sent an unexpected answer for {obj} {method}")
        if result[0] == 0:
            return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}
        if result[0] in allow:
            return None
        if result[0] == 6:
            raise AuthRefused(f"{self.id} says access is denied for {obj} {method}: the login may not use it (see the box at the top of this page)")
        raise OpenwrtError(f"{self.id}: {obj} {method} failed with ubus status {result[0]}" + (" (not installed)" if result[0] in (3, 4) else ""))

    def login(self):
        data = None
        try:
            data = self.rpc("session", "login", {"username": self.username, "password": self.password, "timeout": 60})
        except AuthRefused:
            data = None
        if not data or not data.get("ubus_rpc_session"):
            raise AuthRefused(f"{self.id} refused the login (wrong user name or password)")
        self.sid = data["ubus_rpc_session"]
        return self

    def logout(self):
        if self.sid:
            try:
                self.rpc("session", "destroy", allow=(3, 4, 6))
            except OpenwrtError:
                pass
            self.sid = None


def parse_routers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one OpenWrt device")
    out = []
    for i, r in enumerate(items, 1):
        url = str(r.get("host") or "").strip()
        if not url:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("username") or "").strip() or not str(r.get("password") or ""):
            raise ValueError(f"{url}: enter the user name and password")
        out.append(Router(url, str(r["username"]).strip(), str(r["password"]), r.get("role"), r.get("uplink"), config.get("verify_tls", False), config.get("timeout") or 15))
    return out


def band_of(freq):
    try:
        f = int(float(freq))
    except (TypeError, ValueError):
        return None
    if f < 1000:       # a channel number instead of MHz
        return None
    return "2.4 GHz" if f < 3000 else "6 GHz" if f >= 5925 else "5 GHz"


def _lan(dump):
    """(lan interface, wan interface) from `network.interface dump`: the wan is the interface named wan* or one that dials (pppoe, 3g, qmi ...),
    the lan the other one with an IPv4 address (an access point has its default route on the lan, so a route does not make a wan)."""
    lan = wan = None
    for iface in (dump or {}).get("interface") or []:
        name = str(iface.get("interface") or "")
        if name == "loopback" or not iface.get("ipv4-address"):
            continue
        if name.startswith("wan") or iface.get("proto") in ("pppoe", "pppoa", "3g", "qmi", "ncm", "wwan", "l2tp", "pptp"):
            wan = wan or iface
        elif lan is None or name == "lan":
            lan = iface
    return lan, wan


def read(router):
    """Everything about one router: its node entry and its clients."""
    board = router.rpc("system", "board")
    lan, wan = _lan(router.rpc("network.interface", "dump"))
    ip = _ipv4(((lan or {}).get("ipv4-address") or [{}])[0].get("address")) or _ipv4(router.host)
    own = set()
    mac = None
    for device in {d for d in ((lan or {}).get("device"), (lan or {}).get("l3_device"), "br-lan") if d}:
        status = router.rpc("network.device", "status", {"name": device}, allow=(4,))
        if status:
            mac = mac or _mac(status.get("macaddr"))
            own.add(_mac(status.get("macaddr")))
    role = router.role if router.role != "auto" else ("gateway" if wan else "ap")
    node = {"mac": mac, "ip": ip, "name": str(board.get("hostname") or router.id)[:100], "model": str(board.get("model") or "")[:100] or None, "role": role}
    if role == "ap" and router.uplink:
        node["uplink_ip"] = router.uplink

    clients = {}
    leases = router.rpc("luci-rpc", "getDHCPLeases", allow=(3, 4, 6)) or {}
    for lease in leases.get("dhcp_leases") or []:
        m = _mac(lease.get("macaddr"))
        if m:
            clients[m] = {"mac": m, "ip": _ipv4(lease.get("ipaddr")), "name": str(lease.get("hostname") or "")[:100] or None, "medium": "wired"}
    hints = router.rpc("luci-rpc", "getHostHints", allow=(3, 4, 6)) or {}
    for key, hint in hints.items():
        m = _mac(key)
        if not m or not isinstance(hint, dict):
            continue
        ip4 = next((a for a in (_ipv4(x) for x in hint.get("ipaddrs") or []) if a), None)
        entry = clients.setdefault(m, {"mac": m, "ip": ip4, "name": None, "medium": "wired"})
        entry["ip"] = entry["ip"] or ip4
        entry["name"] = entry["name"] or (str(hint.get("name") or "")[:100] or None)
    wifi = wireless_stations(router)
    for m, st in wifi.items():
        entry = clients.setdefault(m, {"mac": m, "ip": None, "name": None, "medium": "wifi"})
        entry.update(medium="wifi", **{k: v for k, v in st.items() if v is not None})
    own.discard(None)
    if mac:
        own.add(mac)
    out = [{k: v for k, v in c.items() if v is not None} for m, c in clients.items() if m not in own and c.get("ip") != ip and (c.get("ip") or c["medium"] == "wifi")]
    return node, out[:MAX_CLIENTS], {"wan": bool(wan), "version": (board.get("release") or {}).get("description"), "stations": len(wifi)}


def wireless_stations(router):
    """{mac: {band, rssi, tx_mbps, rx_mbps}} for every station associated with a radio of this router."""
    radios = router.rpc("luci-rpc", "getWirelessDevices", allow=(3, 4, 6)) or {}
    stations = {}
    for radio in radios.values():
        for iface in (radio or {}).get("interfaces") or []:
            ifname = iface.get("ifname")
            if not ifname or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", str(ifname)):
                continue
            info = router.rpc("iwinfo", "info", {"device": ifname}, allow=(3, 4, 6)) or {}
            band = band_of(info.get("frequency"))
            assoc = router.rpc("iwinfo", "assoclist", {"device": ifname}, allow=(3, 4, 6)) or {}
            for st in assoc.get("results") or []:
                m = _mac(st.get("mac"))
                if not m:
                    continue
                signal = st.get("signal")
                rate = lambda d: round(float((st.get(d) or {}).get("rate") or 0) / 1000, 1) or None
                stations[m] = {"band": band, "rssi": int(signal) if isinstance(signal, (int, float)) and -127 <= signal <= 0 else None, "tx_mbps": rate("tx"), "rx_mbps": rate("rx")}
    return stations


def connect(config):
    nodes, clients, notes, problems = [], [], [], []
    for router in parse_routers(config):
        try:
            router.login()
            try:
                node, found, note = read(router)
            finally:
                router.logout()
        except AuthRefused:
            raise
        except OpenwrtError as exc:
            problems.append(str(exc))
            continue
        nodes.append((router, node))
        clients.append((node, found))
        notes.append(note)
    if not nodes:
        raise OpenwrtError("; ".join(problems) or "no OpenWrt device answered")
    return nodes, clients, notes, problems


def assemble(nodes, clients):
    """Turn the per-router reads into the topology output: parents by uplink address, clients assigned to the router that saw them."""
    by_ip = {n["ip"]: n["mac"] for _, n in nodes if n.get("ip") and n.get("mac")}
    out_nodes, out_clients, seen = [], [], set()
    gateways = [n for _, n in nodes if n["role"] == "gateway"]
    for index, (_, node) in enumerate(nodes):
        entry = {k: v for k, v in node.items() if k not in ("uplink_ip",) and v is not None}
        if "mac" not in entry:
            continue
        if node["role"] == "gateway" and gateways and node is not gateways[0]:
            entry["role"] = "node"
        parent = by_ip.get(node.get("uplink_ip"))
        if parent and parent != entry["mac"]:
            entry["parent_mac"] = parent
        out_nodes.append(entry)
    node_macs = {n["mac"] for n in out_nodes}
    # a station is reported by the access point it is associated with; the same device seen as a neighbour elsewhere is kept there only if not wifi
    ordered = sorted(clients, key=lambda c: 0 if any(x["medium"] == "wifi" for x in c[1]) else 1)
    for node, found in ordered:
        for c in sorted(found, key=lambda x: 0 if x["medium"] == "wifi" else 1):
            if c["mac"] in seen or c["mac"] in node_macs or not node.get("mac"):
                continue
            seen.add(c["mac"])
            out_clients.append({**c, "node_mac": node["mac"]})
    return out_nodes, out_clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    nodes, clients, notes, problems = connect(config)
    total = sum(len(c) for _, c in clients)
    wifi = sum(n["stations"] for n in notes)
    message = f"Connected to {len(nodes)} OpenWrt device(s) ({', '.join(sorted({n['version'] for n in notes if n['version']})) or 'version unknown'}): {total} client(s), {wifi} on Wi-Fi"
    if not wifi:
        message += " (no Wi-Fi stations: this device has no Wi-Fi, or iwinfo is not installed or not allowed)"
    if len([1 for _, n in nodes if n["role"] == "gateway"]) > 1:
        message += ". More than one device counts as gateway: the first is used, set the role of the others to ap"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    nodes, clients, _, _ = connect(config)
    out_nodes, out_clients = assemble(nodes, clients)
    return {"nodes": out_nodes, "clients": out_clients}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<router>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<router>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<router>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<router>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the routers answer, as counts and field names (no MAC or IP addresses, names or passwords)."""
    try:
        routers = parse_routers(config)
    except (ValueError, OpenwrtError) as exc:
        return {"error": str(exc)}
    report = {"routers": []}
    for router in routers:
        entry = {"steps": {}}
        report["routers"].append(entry)
        try:
            router.login()
        except AuthRefused:
            raise
        except OpenwrtError as exc:
            entry["error"] = _problem(exc)
            continue
        try:
            for step, obj, method, args in (("board", "system", "board", None), ("interfaces", "network.interface", "dump", None), ("leases", "luci-rpc", "getDHCPLeases", None),
                                            ("host_hints", "luci-rpc", "getHostHints", None), ("wireless_devices", "luci-rpc", "getWirelessDevices", None)):
                try:
                    data = router.rpc(obj, method, args, allow=(3, 4, 6))
                    if data is None:
                        entry["steps"][step] = {"ok": False, "error": "not available (ubus status 3, 4 or 6)"}
                    elif step == "board":
                        entry["steps"][step] = {"ok": True, "release": str((data.get("release") or {}).get("version") or ""), "fields": sorted(data)}
                    elif step == "interfaces":
                        entry["steps"][step] = {"ok": True, "count": len(data.get("interface") or []), "with_ipv4": sum(1 for i in data.get("interface") or [] if i.get("ipv4-address"))}
                    elif step == "leases":
                        rows = data.get("dhcp_leases") or []
                        entry["steps"][step] = {"ok": True, "count": len(rows), "fields": sorted({k for r in rows for k in r}), "with_hostname": sum(1 for r in rows if r.get("hostname"))}
                    elif step == "host_hints":
                        entry["steps"][step] = {"ok": True, "count": len(data), "fields": sorted({k for h in data.values() if isinstance(h, dict) for k in h}), "with_name": sum(1 for h in data.values() if isinstance(h, dict) and h.get("name"))}
                    else:
                        entry["steps"][step] = {"ok": True, "radios": len(data), "interfaces": sum(len((r or {}).get("interfaces") or []) for r in data.values())}
                except AuthRefused:
                    entry["steps"][step] = {"ok": False, "error": "access denied for this login"}
                except OpenwrtError as exc:
                    entry["steps"][step] = {"ok": False, "error": _problem(exc)}
            try:
                node, found, note = read(router)
                entry["result"] = {"role": node["role"], "clients": len(found), "wifi_stations": note["stations"], "wan": note["wan"]}
            except OpenwrtError as exc:
                entry["result"] = {"error": _problem(exc)}
        finally:
            router.logout()
    return report
