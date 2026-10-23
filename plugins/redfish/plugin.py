"""Redfish plugin (kind "storage"): servers and storage systems through their management controller (BMC): Dell iDRAC, HPE iLO, Lenovo XClarity,
Supermicro, Cisco CIMC, and any array or appliance that speaks the DMTF Redfish standard.

Talks to the BMC's Redfish REST API, read-only, with HTTP Basic authentication (no session is left behind). Calls (all GET):

    /redfish/v1/                       service root (vendor, Redfish version)
    /redfish/v1/Systems/*              the computer systems: model, serial, BIOS, power state, health, network interfaces, storage and drives
    /redfish/v1/Managers/*             the BMC itself: firmware, network interfaces (address and MAC)
    /redfish/v1/Chassis/*              chassis health, power supplies, fans and temperatures (PowerSubsystem/ThermalSubsystem, or Power/Thermal on older BMCs)

Every system becomes a storage *system* (health, vendor, model, serial); the BMC and the network cards become *controllers* (found on the network
by address or MAC); drives are *disks*; RAID volumes are *volumes*; a component that is not healthy is an *alert*. Standard library only.
A refused login (HTTP 401) is reported with `auth_failed` so Netlens stops retrying until the user acts. Every part but the service root is optional.
"""

import base64
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 8 * 1024 * 1024
MAX_REQUESTS = 400
MAX_SYSTEMS = 16
MAX_DRIVES = 400
HEALTH = {"ok": "ok", "warning": "warning", "critical": "critical"}
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


class RedfishError(Exception):
    pass


class ConnectError(RedfishError):
    """The BMC could not be reached (not a login problem)."""


class LoginRefused(RedfishError):
    auth_failed = True


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the BMC (for example https://192.168.0.70)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// or http:// and name the BMC")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Redfish:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.id = urllib.parse.urlsplit(self.base).netloc
        self.user, self.password = str(config.get("username") or ""), str(config.get("password") or "")
        if not self.user or not self.password:
            raise ValueError("enter the user name and the password")
        self.timeout = int(config.get("timeout") or 30)
        context = ssl.create_default_context()
        if not config.get("verify_tls"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.auth = "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.requests = 0
        self.notes = []

    def get(self, path):
        """One GET; the parsed JSON object. Raises LoginRefused on 401, RedfishError on 404 and other errors."""
        if not isinstance(path, str) or not path.startswith("/") or "\n" in path:
            raise RedfishError("bad link")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise RedfishError("too many requests (this BMC has more parts than Netlens reads)")
        request = urllib.request.Request(self.base + path, headers={"Authorization": self.auth, "Accept": "application/json", "OData-Version": "4.0"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                code, raw = response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read(MAX_BODY)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the BMC at {self.host}: {getattr(exc, 'reason', exc)}") from None
        if code in (401, 403):
            raise LoginRefused(f"login refused (HTTP {code}): check the user name and password, and that the user has at least the ReadOnly role")
        if code == 404:
            raise RedfishError(f"{path}: not found")
        if code >= 400:
            raise RedfishError(f"{path}: HTTP {code}")
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError(f"this does not look like a Redfish service (HTTP {code}, the answer is not JSON)") from None
        if not isinstance(data, dict):
            raise ConnectError("this does not look like a Redfish service (unexpected answer)")
        return data

    def optional(self, label, path):
        """A part that may be missing or fail: the data, or None with a note."""
        try:
            return self.get(path)
        except LoginRefused:
            raise
        except RedfishError as exc:
            self.notes.append(f"{label}: {exc}")
        return None

    def members(self, label, link, limit):
        """The linked objects of a collection (or of one object that is not a collection: itself)."""
        path = _link(link)
        if not path:
            return []
        collection = self.optional(label, path)
        if not collection:
            return []
        found = []
        for ref in (collection.get("Members") or [])[:limit]:
            target = _link(ref)
            if not target:
                continue
            item = self.optional(label, target)
            if item:
                item["@odata.id"] = item.get("@odata.id") or target
                found.append(item)
        return found

    def snapshot(self):
        root = self.get("/redfish/v1/")
        systems = []
        for system in self.members("systems", root.get("Systems"), MAX_SYSTEMS):
            system["_nics"] = self.members("network interfaces", system.get("EthernetInterfaces"), 16)
            system["_storage"] = []
            for st in self.members("storage", system.get("Storage"), 16):
                st["_drives"] = [d for d in (self._drive(ref) for ref in (st.get("Drives") or [])[:MAX_DRIVES]) if d]
                st["_volumes"] = self.members("volumes", st.get("Volumes"), 64)
                system["_storage"].append(st)
            for simple in self.members("simple storage", system.get("SimpleStorage"), 16):
                system["_storage"].append({"Id": simple.get("Id"), "Name": simple.get("Name"), "Status": simple.get("Status"), "_drives": [_simple_drive(d, simple, i) for i, d in enumerate(simple.get("Devices") or [])], "_volumes": []})
            systems.append(system)
        managers = []
        for mgr in self.members("managers", root.get("Managers"), 8):
            mgr["_nics"] = self.members("manager network interfaces", mgr.get("EthernetInterfaces"), 8)
            managers.append(mgr)
        chassis = []
        for ch in self.members("chassis", root.get("Chassis"), 16):
            ch["_parts"] = self._chassis_parts(ch)
            chassis.append(ch)
        return {"root": root, "systems": systems, "managers": managers, "chassis": chassis, "notes": self.notes}

    def _drive(self, ref):
        path = _link(ref)
        drive = self.optional("drives", path) if path else None
        return drive

    def _chassis_parts(self, ch):
        """(label, health) of the power supplies, fans and temperature sensors of one chassis."""
        parts = []
        sub = self.optional("power", _link(ch.get("PowerSubsystem")) or "") if _link(ch.get("PowerSubsystem")) else None
        if sub:
            for item in self.members("power supplies", sub.get("PowerSupplies"), 16):
                parts.append((item.get("Name") or item.get("Id") or "Power supply", item.get("Status")))
        sub = self.optional("thermal", _link(ch.get("ThermalSubsystem")) or "") if _link(ch.get("ThermalSubsystem")) else None
        if sub:
            for item in self.members("fans", sub.get("Fans"), 32):
                parts.append((item.get("Name") or item.get("Id") or "Fan", item.get("Status")))
        if not parts and _link(ch.get("Power")):
            power = self.optional("power", _link(ch.get("Power")))
            for item in (power or {}).get("PowerSupplies") or []:
                if isinstance(item, dict):
                    parts.append((item.get("Name") or "Power supply", item.get("Status")))
        if not any("fan" in p[0].lower() for p in parts) and _link(ch.get("Thermal")):
            thermal = self.optional("thermal", _link(ch.get("Thermal")))
            for key, fallback in (("Fans", "Fan"), ("Temperatures", "Temperature")):
                for item in (thermal or {}).get(key) or []:
                    if isinstance(item, dict):
                        parts.append((item.get("Name") or item.get("FanName") or fallback, item.get("Status")))
        return parts


def _link(ref):
    if isinstance(ref, dict):
        ref = ref.get("@odata.id")
    return ref if isinstance(ref, str) and ref.startswith("/") else None


def _simple_drive(device, simple, index):
    return {"Id": f"{simple.get('Id') or 'simple'}-{index}", "Name": device.get("Name") or f"Device {index}", "Model": device.get("Model"), "CapacityBytes": device.get("CapacityBytes"), "Status": device.get("Status")}


# ----------------------------------------------------------------------------- mapping to the storage contract
def health_of(status, rollup=True):
    """ok / warning / critical / unknown from a Redfish Status object."""
    if not isinstance(status, dict):
        return "unknown"
    value = (status.get("HealthRollup") if rollup and status.get("HealthRollup") else status.get("Health")) or ""
    return HEALTH.get(str(value).lower(), "unknown")


def worst(*levels):
    return max(levels, key=lambda x: RANK.get(x, 0)) if levels else "unknown"


def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _ip(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified and not addr.is_loopback else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _nic_ips(nic):
    return [ip for ip in (_ip(a.get("Address")) for a in (nic.get("IPv4Addresses") or []) if isinstance(a, dict)) if ip]


def _text(value, limit=100):
    return str(value or "").strip()[:limit]


def to_storage(snapshot, connect_host=""):
    root = snapshot["root"]
    vendor = _text(root.get("Vendor"), 60)
    bmc_ip = _ip(connect_host)
    systems, controllers, volumes, disks, alerts = [], [], [], [], []
    chassis_health = worst(*[health_of(c.get("Status")) for c in snapshot["chassis"]]) if snapshot["chassis"] else "unknown"
    for mgr in snapshot["managers"]:
        macs = [(_mac(n.get("PermanentMACAddress") or n.get("MACAddress")), _nic_ips(n)) for n in mgr["_nics"]]
        macs = [(m, ips) for m, ips in macs if m or ips]
        for j, (mac, ips) in enumerate(macs or [(None, [bmc_ip] if bmc_ip else [])]):
            if not mac and not ips:
                continue
            controllers.append({"id": f"bmc-{mgr.get('Id') or 'bmc'}-{j}", "name": _text(mgr.get("Name") or "BMC") + (f" ({mgr.get('FirmwareVersion')})" if mgr.get("FirmwareVersion") and j == 0 else ""),
                                "ip": (bmc_ip if bmc_ip in ips else (ips[0] if ips else bmc_ip)) if j == 0 else (ips[0] if ips else None), "mac": mac,
                                "online": True, "health": health_of(mgr.get("Status"))})
    for system in snapshot["systems"]:
        sid = _text(system.get("Id") or system.get("Name") or "system")
        nic_macs = [(_mac(n.get("PermanentMACAddress") or n.get("MACAddress")), _nic_ips(n)) for n in system["_nics"]]
        os_ips = [ip for _, ips in nic_macs for ip in ips]
        status = system.get("Status")
        level = worst(health_of(status), chassis_health) if health_of(status) != "unknown" else chassis_health
        warnings = []
        power = _text(system.get("PowerState"), 20)
        if power and power.lower() != "on":
            warnings.append(f"The server is powered {power.lower()}")
        for cond in (status or {}).get("Conditions") or [] if isinstance(status, dict) else []:
            if isinstance(cond, dict) and cond.get("Message") and len(warnings) < 8:
                warnings.append(_text(cond.get("Message"), 300))
        systems.append({"id": sid, "name": _text(system.get("HostName") or system.get("Name") or sid), "ip": os_ips[0] if os_ips else None, "vendor": _text(system.get("Manufacturer") or vendor, 60),
                        "model": _text(system.get("Model")), "version": _text(system.get("BiosVersion"), 60), "serial": _text(system.get("SerialNumber"), 60), "online": True,
                        "health": level, "warnings": warnings})
        for k, (mac, ips) in enumerate(nic_macs):
            if mac or ips:
                controllers.append({"id": f"{sid}-nic-{k}", "system_id": sid, "name": _text(system.get("HostName") or "Host") + f" network card {k + 1}", "ip": ips[0] if ips else None, "mac": mac,
                                    "online": True, "health": "unknown"})
        for st in system["_storage"]:
            for vol in st.get("_volumes") or []:
                volumes.append({"id": f"{sid}/{vol.get('Id') or vol.get('Name')}", "system_id": sid, "name": _text(vol.get("Name") or vol.get("Id"), 200), "kind": "volume",
                                "protocol": _text(vol.get("RAIDType") or vol.get("VolumeType"), 20), "size": _int(vol.get("CapacityBytes")), "health": health_of(vol.get("Status"))})
            for drive in st.get("_drives") or []:
                state = _drive_state(drive)
                if state is None:
                    continue
                disks.append({"id": f"{sid}/{st.get('Id') or 'st'}/{drive.get('Id') or drive.get('Name')}", "system_id": sid, "name": _text(drive.get("Name") or drive.get("Id")),
                              "slot": _text(drive.get("Id"), 40), "model": _text(drive.get("Model")), "size": _int(drive.get("CapacityBytes")), "state": state})
    # chassis parts belong to the chassis, which usually is the (only) system; with several systems they are listed under the first
    first = systems[0]["id"] if systems else None
    if first:
        for ch in snapshot["chassis"]:
            for name, status in ch["_parts"]:
                level = health_of(status, rollup=False)
                if level in ("warning", "critical"):
                    alerts.append({"id": f"{ch.get('Id')}/{name}", "system_id": first, "severity": level, "text": f"{_text(name, 100)}: {level}"})
            if health_of(ch.get("Status")) in ("warning", "critical") and not [a for a in alerts if a["id"].startswith(f"{ch.get('Id')}/")]:
                alerts.append({"id": f"{ch.get('Id')}/chassis", "system_id": first, "severity": health_of(ch.get("Status")), "text": f"Chassis {_text(ch.get('Name') or ch.get('Id'), 100)}: {health_of(ch.get('Status'))}"})
        for d in disks:
            if d["state"] in ("failed", "degraded"):
                alerts.append({"id": "disk/" + d["id"], "system_id": d["system_id"], "severity": "critical" if d["state"] == "failed" else "warning", "text": f"Drive {d['slot'] or d['name']}: {d['state']}"})
    for s in systems:      # a failing part makes the whole server at least that unhealthy
        s["health"] = worst(s["health"], *[a["severity"] for a in alerts if a["system_id"] == s["id"]])
        if s["health"] == "unknown" and s["id"] in {d["system_id"] for d in disks}:
            s["health"] = "ok"
    for c in controllers:
        c.setdefault("system_id", first or "")
    if not systems:
        raise RedfishError("this Redfish service lists no computer systems")
    controllers = [c for c in controllers if c["system_id"]]
    return {"systems": systems, "controllers": _unique(controllers), "pools": [], "volumes": _unique(volumes), "disks": _unique(disks), "alerts": _unique(alerts)}


def _unique(items):
    seen, out = set(), []
    for item in items:
        if item["id"] in seen:
            item = {**item, "id": item["id"] + "#" + str(len(seen))}
        seen.add(item["id"])
        out.append(item)
    return out


def _drive_state(drive):
    status = drive.get("Status") if isinstance(drive.get("Status"), dict) else {}
    state = str(status.get("State") or "").lower()
    if state == "absent":
        return None                       # an empty bay
    health = health_of(status, rollup=False)
    if health == "critical" or state in ("unavailableoffline", "disabled") and health != "ok":
        return "failed"
    if health == "warning" or state in ("standbyoffline",):
        return "degraded"
    if str(drive.get("HotspareType") or "").lower() in ("global", "chassis", "dedicated"):
        return "spare"
    return "ok" if health == "ok" or state == "enabled" else "unknown"


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one BMC")
    return out


def _each(config, work):
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - the type stays (a refused login must stay recognisable)
            label = urllib.parse.urlsplit(str(one.get("url") or "")).netloc or str(one.get("url") or "") if len(servers) > 1 else ""
            if label and exc.args:
                exc.args = (f"{label}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


def _fetch_one(one):
    client = Redfish(one)
    snapshot = client.snapshot()
    return to_storage(snapshot, client.host), snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        s = out["systems"][0]
        message = (f"Connected to {s['name']} ({' '.join(x for x in (s['vendor'], s['model']) if x) or 'Redfish'}): health {s['health']}, "
                   f"{len(out['disks'])} drive(s), {len(out['volumes'])} volume(s), {len(out['alerts'])} problem(s)")
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"][:5])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} BMCs answered. " + " | ".join(messages)}


def fetch(config):
    merged = {"systems": [], "controllers": [], "pools": [], "volumes": [], "disks": [], "alerts": []}
    taken = set()
    for out, _ in _each(config, _fetch_one):
        prefix = ""
        if any(s["id"] in taken for s in out["systems"]):
            prefix = f"{len(taken)}-"
        remap = {s["id"]: prefix + s["id"] for s in out["systems"]}
        for s in out["systems"]:
            taken.add(remap[s["id"]])
        for key in merged:
            for item in out[key]:
                item = dict(item)
                if key == "systems":
                    item["id"] = remap[item["id"]]
                else:
                    item["system_id"] = remap.get(item["system_id"], item["system_id"])
                    item["id"] = prefix + item["id"]
                merged[key].append(item)
    return merged


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"Health", "HealthRollup", "State", "PowerState", "Protocol", "MediaType", "RAIDType", "VolumeType", "HotspareType", "RedfishVersion", "InterfaceEnabled", "LinkStatus"}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items() if not str(k).startswith("@odata") or k == "@odata.type"}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if (key in KEEP_WORDS or key == "@odata.type") and isinstance(value, str) and len(value) < 60:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac>"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def _problem(exc, server=None):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = str(exc)
    if server is not None:
        for secret in (getattr(server, "id", ""), getattr(server, "base", ""), getattr(server, "host", "")):
            if secret:
                text = text.replace(secret, "<url>")
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<url>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<url>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<url>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What this BMC answers, described by field names and types, and what the plugin made of it (no names, serials, MACs or IPs)."""
    client = Redfish(_servers(config)[0])
    report = {"steps": {}}
    try:
        root = client.get("/redfish/v1/")
    except LoginRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        return {"steps": {"root": {"ok": False, "error": _problem(exc, client)}}}
    report["steps"]["root"] = {"ok": True, "shape": describe(root)}
    for name in ("Systems", "Managers", "Chassis"):
        try:
            collection = client.get(_link(root.get(name)) or "/redfish/v1/" + name)
            first = _link((collection.get("Members") or [None])[0])
            report["steps"][name.lower()] = {"ok": True, "count": len(collection.get("Members") or []), "first": describe(client.get(first)) if first else None}
        except LoginRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name.lower()] = {"ok": False, "error": _problem(exc, client)}
    try:
        client.requests, client.notes = 0, []
        snapshot = client.snapshot()
        out = to_storage(snapshot, client.host)
        report["result"] = {"systems": len(out["systems"]), "controllers": len(out["controllers"]), "controllers_with_mac": sum(1 for c in out["controllers"] if c["mac"]),
                            "controllers_with_ip": sum(1 for c in out["controllers"] if c["ip"]), "volumes": len(out["volumes"]), "disks": len(out["disks"]),
                            "disk_states": {k: sum(1 for d in out["disks"] if d["state"] == k) for k in ("ok", "degraded", "failed", "spare", "unknown")},
                            "alerts": len(out["alerts"]), "health": [s["health"] for s in out["systems"]], "requests": client.requests,
                            "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, client)
    return report
