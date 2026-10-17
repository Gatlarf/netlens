"""VMware ESXi / vCenter plugin (kind "hypervisor"): hosts and virtual machines through the vSphere web service (SOAP, /sdk), read-only.

The calls, all on the vim25 web service (no write operation is ever sent):

    RetrieveServiceContent        product name/version, the ids of SessionManager, PropertyCollector, ViewManager, root folder
    Login / Logout                SessionManager (the session lives in the cookie vmware_soap_session)
    CreateContainerView           a view of every HostSystem and VirtualMachine below the root folder (destroyed at the end)
    RetrievePropertiesEx          (+ ContinueRetrievePropertiesEx) the properties below

    HostSystem:     name, summary.runtime.connectionState, config.network.vnic (management address)
    VirtualMachine: name, runtime.powerState, runtime.host, config.template, config.hardware.numCPU, config.hardware.memoryMB, config.guestFullName,
                    config.hardware.device (virtual network cards: macAddress), guest.net (VMware Tools: addresses), guest.toolsRunningStatus

Works against a standalone ESXi and a vCenter alike. Templates are left out. Standard library only (xml.etree for the answers).
"""

import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

MAX_OBJECTS = 6000
NS = 'xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
POWER = {"poweredon": "running", "poweredoff": "stopped", "suspended": "suspended"}
HOST_PROPS = ["name", "summary.runtime.connectionState", "config.network.vnic"]
VM_PROPS = ["name", "runtime.powerState", "runtime.host", "config.template", "config.hardware.numCPU", "config.hardware.memoryMB", "config.guestFullName",
            "config.hardware.device", "guest.net", "guest.toolsRunningStatus"]


class VsphereError(Exception):
    pass


class AuthRefused(VsphereError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def local(tag):
    return tag.rsplit("}", 1)[-1]


def find(node, name):
    return next((c for c in node.iter() if local(c.tag) == name), None)


def children(node, name):
    return [c for c in node if local(c.tag) == name]


def text_of(node, name):
    found = find(node, name) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


class Session:
    def __init__(self, url, username, password, verify_tls=False, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise VsphereError(f"{url!r} is not an address like https://192.168.0.30")
        self.endpoint, self.id, self.host, self.timeout = f"{parts.scheme}://{parts.netloc}/sdk", parts.netloc, parts.hostname, float(timeout)
        self.username, self.password = username, password
        self.cookie, self.content = None, {}
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, inner):
        body = (f'<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
                f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><{method} {NS}>{inner}</{method}></soapenv:Body></soapenv:Envelope>').encode()
        headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '"urn:vim25/8.0.0.0"'}
        if self.cookie:
            headers["Cookie"] = self.cookie
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
                cookie = response.headers.get("Set-Cookie")
        except urllib.error.HTTPError as exc:
            raw, cookie = exc.read(), None
            if not raw.lstrip().startswith(b"<"):
                raise VsphereError(f"{self.id} answered HTTP {exc.code} (is this ESXi or vCenter?)")
        except urllib.error.URLError as exc:
            raise VsphereError(f"cannot reach {self.id}: {exc.reason}")
        except OSError as exc:
            raise VsphereError(f"{self.id} did not answer properly: {exc}")
        if cookie and "vmware_soap_session" in cookie:
            self.cookie = cookie.split(";", 1)[0]
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise VsphereError(f"{self.id} did not return XML (is this ESXi or vCenter on /sdk?)")
        fault = find(root, "Fault")
        if fault is not None:
            detail = find(fault, "faultstring")
            kind = (find(fault, "detail").attrib.get("{http://www.w3.org/2001/XMLSchema-instance}type") if find(fault, "detail") is not None else "") or ""
            message = (detail.text or "fault") if detail is not None else "fault"
            if "InvalidLogin" in message or "InvalidLogin" in ET.tostring(fault, encoding="unicode") or "NoPermission" in kind:
                raise AuthRefused(f"{self.id} refused the login or the permission: {message[:120]}")
            raise VsphereError(f"{self.id} reported a fault for {method}: {message[:200]}")
        return root

    def login(self):
        content = find(self.call("RetrieveServiceContent", '<_this type="ServiceInstance">ServiceInstance</_this>'), "returnval")
        if content is None:
            raise VsphereError(f"{self.id} did not return a service content")
        self.content = {k: text_of(content, k) for k in ("rootFolder", "propertyCollector", "viewManager", "sessionManager")}
        about = find(content, "about")
        self.product = text_of(about, "fullName") or "VMware"
        self.api_type = text_of(about, "apiType")                     # "HostAgent" = a standalone ESXi, "VirtualCenter" = a vCenter
        self.call("Login", f'<_this type="SessionManager">{escape(self.content["sessionManager"])}</_this><userName>{escape(self.username)}</userName><password>{escape(self.password)}</password>')
        return self

    def logout(self):
        if self.cookie:
            try:
                self.call("Logout", f'<_this type="SessionManager">{escape(self.content["sessionManager"])}</_this>')
            except VsphereError:
                pass
            self.cookie = None

    def properties(self, view, type_name, paths):
        """{object id: {property path: <val> element}} for every object of one type in the view."""
        pc = escape(self.content["propertyCollector"])
        path_xml = "".join(f"<pathSet>{escape(p)}</pathSet>" for p in paths)
        spec = (f'<_this type="PropertyCollector">{pc}</_this><specSet><propSet><type>{type_name}</type>{path_xml}</propSet>'
                f'<objectSet><obj type="ContainerView">{escape(view)}</obj><skip>true</skip><selectSet xsi:type="TraversalSpec"><name>view</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet></objectSet></specSet>'
                '<options/>')
        result, root = {}, self.call("RetrievePropertiesEx", spec)
        while True:
            returned = find(root, "returnval")
            if returned is None:
                break
            for obj in children(returned, "objects"):
                oid = (find(obj, "obj").text or "").strip()
                props = {text_of(p, "name"): find(p, "val") for p in children(obj, "propSet")}
                result[oid] = props
            token = text_of(returned, "token")
            if not token or len(result) > MAX_OBJECTS:
                break
            root = self.call("ContinueRetrievePropertiesEx", f'<_this type="PropertyCollector">{pc}</_this><token>{escape(token)}</token>')
        return result

    def view_of(self, type_name):
        root = self.call("CreateContainerView", f'<_this type="ViewManager">{escape(self.content["viewManager"])}</_this><container type="Folder">{escape(self.content["rootFolder"])}</container><type>{type_name}</type><recursive>true</recursive>')
        return text_of(root, "returnval")

    def destroy_view(self, view):
        try:
            self.call("DestroyView", f'<_this type="ContainerView">{escape(view)}</_this>')
        except VsphereError:
            pass


def parse_sessions(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one ESXi host or vCenter")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("username") or "").strip() or not str(r.get("password") or ""):
            raise ValueError(f"{host}: enter the user name and password")
        out.append(Session(host, str(r["username"]).strip(), str(r["password"]), config.get("verify_tls", False), config.get("timeout") or 30))
    return out


def _val_text(val):
    return (val.text or "").strip() if val is not None and val.text else ""


def _macs(val):
    """MAC addresses of the virtual network cards in the config.hardware.device array."""
    return [m.text.strip().lower() for m in val.iter() if local(m.tag) == "macAddress" and m.text] if val is not None else []


def _guest_ips(val):
    """(macs, IPv4 addresses) from the guest.net array (VMware Tools)."""
    macs, ips = [], []
    for nic in children(val, "GuestNicInfo") if val is not None else []:
        if text_of(nic, "macAddress"):
            macs.append(text_of(nic, "macAddress").lower())
        for ip in children(nic, "ipAddress"):
            addr = _ipv4(ip.text)
            if addr and not addr.startswith("169.254."):
                ips.append(addr)
    return macs, ips


def read(session):
    session.login()
    try:
        host_view = session.view_of("HostSystem")
        vm_view = session.view_of("VirtualMachine")
        raw_hosts = session.properties(host_view, "HostSystem", HOST_PROPS)
        raw_vms = session.properties(vm_view, "VirtualMachine", VM_PROPS)
        session.destroy_view(host_view)
        session.destroy_view(vm_view)
    finally:
        session.logout()
    hosts, host_ids = [], {}
    for oid, props in raw_hosts.items():
        ip = None        # the first VMkernel address that is not a loopback or link-local one (vmk0 is the management interface)
        for nic in children(props.get("config.network.vnic"), "HostVirtualNic") if props.get("config.network.vnic") is not None else []:
            candidate = _ipv4(text_of(find(nic, "spec"), "ipAddress") if find(nic, "spec") is not None else "")
            if candidate and not candidate.startswith(("127.", "169.254.")):
                ip = ip or candidate
        hid = f"{session.id}/{oid}"
        host_ids[oid] = hid
        name = _val_text(props.get("name")) or oid
        hosts.append({"id": hid, "name": name[:100], "ip": ip or _ipv4(name) or (_ipv4(session.host) if session.api_type == "HostAgent" else None),
                      "online": _val_text(props.get("summary.runtime.connectionState")).lower() == "connected"})
    guests = []
    for oid, props in raw_vms.items():
        if _val_text(props.get("config.template")).lower() == "true":
            continue
        power = _val_text(props.get("runtime.powerState")).lower()
        tools_macs, ips = _guest_ips(props.get("guest.net"))
        macs = list(dict.fromkeys(_macs(props.get("config.hardware.device")) + tools_macs))
        cpus, mem = _val_text(props.get("config.hardware.numCPU")), _val_text(props.get("config.hardware.memoryMB"))
        details = {"os": _val_text(props.get("config.guestFullName"))[:100], "cpus": int(cpus) if cpus.isdigit() else None, "memory_mb": int(mem) if mem.isdigit() else None,
                   "health": "healthy" if _val_text(props.get("guest.toolsRunningStatus")) == "guestToolsRunning" and power == "poweredon" else ""}
        guest = {"id": f"{session.id}/{oid}", "name": (_val_text(props.get("name")) or oid)[:100], "kind": "vm", "status": POWER.get(power, power or "unknown")[:30], "macs": macs, "ips": list(dict.fromkeys(ips)),
                 "details": {k: v for k, v in details.items() if v not in ("", None)}}
        host = _val_text(props.get("runtime.host"))
        if host in host_ids:
            guest["host_id"] = host_ids[host]
        guests.append(guest)
    return session.product, hosts, guests


def connect(config):
    products, hosts, guests, problems = [], [], [], []
    for session in parse_sessions(config):
        try:
            product, found_hosts, found = read(session)
        except AuthRefused:
            raise
        except VsphereError as exc:
            problems.append(str(exc))
            continue
        products.append(product)
        hosts.extend(found_hosts)
        guests.extend(found)
    if not products:
        raise VsphereError("; ".join(problems) or "no ESXi or vCenter answered")
    return products, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    products, hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected to {', '.join(sorted(set(products)))}: {len(hosts)} host(s), {len(guests)} virtual machine(s), {running} running, {sum(1 for g in guests if g['ips'])} with an address from VMware Tools"
    down = sum(1 for h in hosts if not h["online"])
    if down:
        message += f". {down} host(s) are not connected"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the servers answer, as counts and enumerations (no names, addresses or guests' system names)."""
    try:
        sessions = parse_sessions(config)
    except (ValueError, VsphereError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for session in sessions:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            session.login()
        except AuthRefused:
            raise
        except VsphereError as exc:
            entry["steps"]["login"] = {"ok": False, "error": _problem(exc)}
            continue
        try:
            entry["steps"]["login"] = {"ok": True, "product": session.product[:60], "api_type": session.api_type}
            for step, type_name, paths in (("hosts", "HostSystem", HOST_PROPS), ("vms", "VirtualMachine", VM_PROPS)):
                try:
                    view = session.view_of(type_name)
                    data = session.properties(view, type_name, paths)
                    session.destroy_view(view)
                    entry["steps"][step] = {"ok": True, "count": len(data), "properties_returned": sorted({p for props in data.values() for p in props})}
                    if step == "vms":
                        entry["steps"][step]["power_states"] = {s: sum(1 for p in data.values() if _val_text(p.get("runtime.powerState")) == s) for s in sorted({_val_text(p.get("runtime.powerState")) for p in data.values()})}
                        entry["steps"][step]["with_tools_addresses"] = sum(1 for p in data.values() if _guest_ips(p.get("guest.net"))[1])
                except VsphereError as exc:
                    entry["steps"][step] = {"ok": False, "error": _problem(exc)}
        finally:
            session.logout()
    return report


POWER_CALLS = {"reset": "ResetVM_Task", "reboot": "RebootGuest", "shutdown": "ShutdownGuest", "start": "PowerOnVM_Task"}


def power(config, payload):
    """Reset, restart (needs VMware Tools), shut down (needs VMware Tools) or start one virtual machine. payload: {"guest_id": "<server>/<vm-id>", "action": "reset"}."""
    action = payload.get("action")
    if action not in POWER_CALLS:
        raise ValueError(f"unknown action {action!r}")
    server_id, _, oid = str(payload.get("guest_id") or "").rpartition("/")
    session = next((s for s in parse_sessions(config) if s.id == server_id), None)
    if session is None or not re.fullmatch(r"[A-Za-z0-9_-]+", oid):
        raise VsphereError("this virtual machine's vSphere server is not in the plugin's settings")
    session.login()
    try:
        session.call(POWER_CALLS[action], f'<_this type="VirtualMachine">{oid}</_this>')
    finally:
        session.logout()
    return {"message": f"{POWER_CALLS[action].split('_')[0]} sent to {payload.get('name') or oid}"}
