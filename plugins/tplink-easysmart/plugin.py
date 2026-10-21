"""TP-Link Easy Smart switch plugin (kind "topology").

Easy Smart switches have no SNMP and no MAC address table. Their web interface does have two pages that hold what can be monitored:

    SystemInfoRpm.htm       model, MAC address, IP address, firmware and hardware version   (script variable info_ds)
    PortStatisticsRpm.htm   per port: enabled, link status (speed) and four packet counters (script variable all_info)

The plugin logs in (POST /logon.cgi), reads the two pages, logs out (GET /Logout.htm) and reports the switch as a node with its ports.
The switch can show only one kind of problem per port: packets sent and received without and with errors, so those are reported as
packets and errors. Which device sits behind which port is not available.

The page format was learned from the public projects check_tplink (MIT) and essstat (GPL-3); no code was taken from them.
Standard library only.
"""

import http.cookiejar
import ipaddress
import re
import urllib.error
import urllib.parse
import urllib.request

MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
# link_status of the port statistics page. 0 = no link; 1 is what a port reports before it has negotiated; 2..6 are real links
LINK = {2: (10, "half"), 3: (10, "full"), 4: (100, "half"), 5: (100, "full"), 6: (1000, "full")}
LOGIN_ERRORS = {
    1: ("login refused: wrong user name or password", True),
    2: ("login refused: this user may not log in", True),
    3: ("the switch has no room for another login (sessions full); close open browser tabs on it and try again", False),
    4: ("the switch has no room for another login (sessions full); close open browser tabs on it and try again", False),
    5: ("the switch's session timed out; try again", False),
    6: ("the switch wants a new password to be set first: open its web page once and change it", True),
}


class SwitchError(Exception):
    pass


class AuthRefused(SwitchError):
    auth_failed = True


def _base(host):
    host = str(host or "").strip().rstrip("/")
    if not host:
        raise SwitchError("enter the switch address")
    if not re.match(r"^https?://", host):
        host = "http://" + host
    return host


class Switch:
    def __init__(self, server):
        self.base = _base(server.get("host"))
        self.user = str(server.get("username") or "admin")
        self.password = str(server.get("password") or "")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.logged_in = False

    def _request(self, path, data=None, referer="/"):
        request = urllib.request.Request(self.base + path, data, {"Referer": self.base + referer, "User-Agent": "Netlens"})
        try:
            with self.opener.open(request, timeout=10) as response:
                return response.read().decode("latin-1")
        except urllib.error.URLError as exc:
            raise SwitchError(f"cannot reach the switch at {self.base}: {getattr(exc, 'reason', exc)}")
        except OSError as exc:
            raise SwitchError(f"cannot reach the switch at {self.base}: {exc}")

    def login(self):
        form = urllib.parse.urlencode({"logon": "Login", "username": self.user, "password": self.password}).encode()
        page = self._request("/logon.cgi", form, "/Logout.htm")
        code = re.search(r"logonInfo\s*=\s*new Array\(\s*(\d+)", page)
        if code and int(code.group(1)) != 0:
            message, auth = LOGIN_ERRORS.get(int(code.group(1)), (f"login failed (code {code.group(1)})", False))
            raise (AuthRefused if auth else SwitchError)(message)
        self.logged_in = True

    def page(self, name):
        text = self._request("/" + name)
        if "logonInfo" in text and "info_ds" not in text and "all_info" not in text:
            raise SwitchError(f"the switch showed its login page instead of {name}: not a TP-Link Easy Smart switch, or the session was refused")
        return text

    def logout(self):
        if self.logged_in:
            try:
                self._request("/Logout.htm")
            except SwitchError:
                pass
            self.logged_in = False


def _mac(value):
    value = str(value or "").strip().lower()
    return value.replace("-", ":") if MAC.match(value) else None


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def parse_system_info(text):
    """The first string of each `name:["value"]` entry of the info_ds script variable."""
    if "info_ds" not in text:
        raise SwitchError("SystemInfoRpm.htm has no info_ds block: this firmware is not supported")
    out = {}
    for key in ("descriStr", "macStr", "ipStr", "netmaskStr", "gatewayStr", "firmwareStr", "hardwareStr"):
        m = re.search(rf'{key}\s*:\s*\[\s*"([^"]*)"', text)
        out[key] = m.group(1).strip() if m else ""
    return out


def _numbers(text, key):
    m = re.search(rf"\b{key}\s*:\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        raise SwitchError(f"PortStatisticsRpm.htm has no '{key}' list: this firmware is not supported")
    return [int(x) for x in re.findall(r"-?\d+", m.group(1))]


def parse_ports(text):
    """One dict per port, in the Netlens format. The lists the switch sends end with two padding values; they are ignored."""
    m = re.search(r"max_port_num\s*=\s*(\d+)", text)
    if not m:
        raise SwitchError("PortStatisticsRpm.htm has no max_port_num: this firmware is not supported")
    count = int(m.group(1))
    if not 1 <= count <= 128:
        raise SwitchError(f"the switch says it has {count} ports")
    state, link, packets = _numbers(text, "state"), _numbers(text, "link_status"), _numbers(text, "pkts")
    if len(state) < count or len(link) < count or len(packets) < count * 4:
        raise SwitchError(f"the port lists are too short for {count} ports ({len(state)}, {len(link)} and {len(packets)} values)")
    ports = []
    for i in range(count):
        speed, duplex = LINK.get(link[i], (None, None))
        port = {
            "port": i + 1,
            "enabled": state[i] == 1,
            "up": link[i] in LINK,
            "tx_packets": packets[i * 4],
            "tx_errors": packets[i * 4 + 1],
            "rx_packets": packets[i * 4 + 2],
            "rx_errors": packets[i * 4 + 3],
        }
        if speed:
            port["speed_mbps"], port["duplex"] = speed, duplex
        ports.append(port)
    return ports


def read(server):
    """(system info, ports) of one switch; always logs out."""
    switch = Switch(server)
    try:
        switch.login()
        info = parse_system_info(switch.page("SystemInfoRpm.htm"))
        ports = parse_ports(switch.page("PortStatisticsRpm.htm"))
    finally:
        switch.logout()
    return info, ports


def _node(server, info, ports):
    mac = _mac(info["macStr"])
    if not mac:
        raise SwitchError("the switch did not report a valid MAC address")
    model = info["hardwareStr"]       # "TL-SG1016PE 3.0"; descriStr is the name the owner gave the switch ("SW_KELDER")
    return {
        "mac": mac,
        "ip": _ipv4(info["ipStr"]) or _ipv4(urllib.parse.urlparse(_base(server.get("host"))).hostname),
        "name": str(server.get("name") or "").strip() or info["descriStr"] or model or mac,
        "model": model[:100],
        "role": "switch",
        "ports": ports,
    }


def _servers(config):
    servers = [s for s in (config.get("servers") or []) if str(s.get("host") or "").strip()]
    if not servers:
        raise SwitchError("add a switch")
    return servers


def test(config):
    parts = []
    for server in _servers(config):
        info, ports = read(server)
        up = sum(1 for p in ports if p["up"])
        parts.append(f"{info['descriStr'] or 'switch'} (firmware {info['firmwareStr'] or '?'}): {up} of {len(ports)} ports have a link")
    return {"message": "; ".join(parts)}


def fetch(config):
    nodes, errors = [], []
    for server in _servers(config):
        try:
            info, ports = read(server)
            nodes.append(_node(server, info, ports))
        except AuthRefused:
            raise
        except SwitchError as exc:
            errors.append(f"{server.get('host')}: {exc}")
    if errors:                       # report it: the last good data stays on the map instead of a switch silently vanishing
        raise SwitchError("; ".join(errors))
    seen = set()
    unique = []
    for n in nodes:
        if n["mac"] not in seen:
            seen.add(n["mac"])
            unique.append(n)
    return {"nodes": unique, "clients": []}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if MAC.match(value.lower()):
            return "<mac>"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def diagnose(config):
    report = {"steps": {}}
    for index, server in enumerate(_servers(config)):
        entry = report["steps"][f"switch {index + 1}"] = {}
        switch = Switch(server)
        try:
            switch.login()
            entry["login"] = {"ok": True}
            for name, parser in (("SystemInfoRpm.htm", parse_system_info), ("PortStatisticsRpm.htm", None)):
                try:
                    text = switch.page(name)
                    if parser:
                        entry[name] = {"ok": True, "values": describe(parser(text)), "model": parse_system_info(text)["hardwareStr"]}
                    else:
                        ports = parse_ports(text)
                        codes = {}
                        for code in _numbers(text, "link_status"):
                            codes[str(code)] = codes.get(str(code), 0) + 1
                        entry[name] = {"ok": True, "ports": len(ports), "link_status_codes": codes, "first_port": describe(ports[0]), "enabled": sum(1 for p in ports if p["enabled"]), "up": sum(1 for p in ports if p["up"])}
                except SwitchError as exc:
                    entry[name] = {"ok": False, "error": str(exc)[:300]}
        except AuthRefused:
            raise
        except SwitchError as exc:
            entry["login"] = {"ok": False, "error": str(exc)[:300]}
        finally:
            switch.logout()
    return report
