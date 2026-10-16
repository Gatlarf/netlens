"""The vSphere plugin against a simulated vSphere web service (the XML shapes were recorded from the govmomi simulator vcsim 6.5 on 2026-10-16;
VMware Tools addresses and the ESXi host vnic follow the vSphere API documentation)."""

import importlib.util
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "vsphere"
spec = importlib.util.spec_from_file_location("vsphere_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

ENV = ('<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
       'xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soapenv:Body>{}</soapenv:Body></soapenv:Envelope>')


def prop(name, value, xsi="xsd:string"):
    return f'<propSet><name>{name}</name><val xsi:type="{xsi}">{value}</val></propSet>'


def obj(kind, oid, *props):
    return f'<objects><obj type="{kind}">{oid}</obj>{"".join(props)}</objects>'


def nic(mac):
    return f'<VirtualDevice xsi:type="VirtualVmxnet3"><key>4000</key><macAddress>{mac}</macAddress></VirtualDevice>'


HOSTS = (obj("HostSystem", "host-1", prop("name", "esx1.lan"), prop("summary.runtime.connectionState", "connected"),
             prop("config.network.vnic", '<HostVirtualNic><spec><ip><ipAddress>127.0.0.1</ipAddress></ip></spec></HostVirtualNic>'
                  '<HostVirtualNic><spec><ip><ipAddress>192.168.0.31</ipAddress></ip></spec></HostVirtualNic>', "ArrayOfHostVirtualNic"))
         + obj("HostSystem", "host-2", prop("name", "esx2.lan"), prop("summary.runtime.connectionState", "disconnected")))


def vm(oid, name, power="poweredOn", host="host-1", template="false", macs=("00:50:56:aa:00:01",), ips=(), tools="guestToolsRunning"):
    net = "".join(f'<GuestNicInfo><network>VM Network</network><macAddress>{macs[0]}</macAddress>{"".join(f"<ipAddress>{ip}</ipAddress>" for ip in ips)}</GuestNicInfo>' for _ in [0]) if ips else ""
    return obj("VirtualMachine", oid, prop("name", name), prop("runtime.powerState", power, "VirtualMachinePowerState"),
               f'<propSet><name>runtime.host</name><val type="HostSystem" xsi:type="ManagedObjectReference">{host}</val></propSet>',
               prop("config.template", template, "xsd:boolean"), prop("config.hardware.numCPU", "2", "xsd:int"), prop("config.hardware.memoryMB", "4096", "xsd:int"),
               prop("config.guestFullName", "Debian GNU/Linux 12 (64-bit)"), prop("config.hardware.device", "".join(nic(m) for m in macs), "ArrayOfVirtualDevice"),
               prop("guest.net", net, "ArrayOfGuestNicInfo") if ips else "", prop("guest.toolsRunningStatus", tools))


class Vsphere:
    def __init__(self, password="pw", api_type="VirtualCenter", page_size=2):
        self.password, self.api_type, self.page_size = password, api_type, page_size
        self.logged_out = self.views_destroyed = 0
        self.vms = [vm("vm-1", "web", ips=("192.168.0.50", "169.254.1.1", "fe80::1")), vm("vm-2", "db", power="poweredOff", macs=("00:50:56:aa:00:02",)), vm("vm-3", "tpl", template="true"),
                    vm("vm-4", "app", host="host-2", macs=("00:50:56:aa:00:04",), tools="guestToolsNotRunning")]
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                method = re.search(r"<soapenv:Body><(\w+)", body).group(1)
                headers, payload = {}, ""
                if method == "RetrieveServiceContent":
                    payload = (f'<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><rootFolder type="Folder">group-d1</rootFolder><propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>'
                               f'<viewManager type="ViewManager">ViewManager</viewManager><sessionManager type="SessionManager">SessionManager</sessionManager><about><fullName>VMware vCenter Server 8.0</fullName><apiType>{outer.api_type}</apiType></about></returnval></RetrieveServiceContentResponse>')
                elif method == "Login":
                    if f"<password>{outer.password}</password>" not in body:
                        payload = '<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>Cannot complete login due to an incorrect user name or password.</faultstring><detail><InvalidLoginFault xsi:type="InvalidLogin" xmlns="urn:vim25"/></detail></soapenv:Fault>'
                    else:
                        headers["Set-Cookie"] = 'vmware_soap_session="abc"; Path=/; HttpOnly; Secure'
                        payload = '<LoginResponse xmlns="urn:vim25"><returnval><key>abc</key></returnval></LoginResponse>'
                elif "vmware_soap_session" not in (self.headers.get("Cookie") or ""):
                    payload = '<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>The session is not authenticated.</faultstring><detail><NotAuthenticatedFault xsi:type="NotAuthenticated" xmlns="urn:vim25"/></detail></soapenv:Fault>'
                elif method == "CreateContainerView":
                    payload = '<CreateContainerViewResponse xmlns="urn:vim25"><returnval type="ContainerView">session[abc]view</returnval></CreateContainerViewResponse>'
                elif method == "RetrievePropertiesEx":
                    if "<type>HostSystem</type>" in body:
                        payload = f'<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>{HOSTS}</returnval></RetrievePropertiesExResponse>'
                    else:
                        payload = f'<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>{"".join(outer.vms[:outer.page_size])}<token>page2</token></returnval></RetrievePropertiesExResponse>'
                elif method == "ContinueRetrievePropertiesEx":
                    payload = f'<ContinueRetrievePropertiesExResponse xmlns="urn:vim25"><returnval>{"".join(outer.vms[outer.page_size:])}</returnval></ContinueRetrievePropertiesExResponse>'
                elif method == "DestroyView":
                    outer.views_destroyed += 1
                    payload = '<DestroyViewResponse xmlns="urn:vim25"/>'
                elif method == "Logout":
                    outer.logged_out += 1
                    payload = '<LogoutResponse xmlns="urn:vim25"/>'
                raw = ENV.format(payload).encode()
                self.send_response(500 if "<soapenv:Fault>" in payload else 200)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def config(s, password="pw"):
    return {"servers": [{"host": s.url, "username": "netlens@vsphere.local", "password": password}], "timeout": 5}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "hypervisor"
    with Vsphere() as s:
        out = validate_output("hypervisor", plugin.fetch(config(s)))
        assert s.logged_out == 1 and s.views_destroyed == 2                                      # a clean logout, views destroyed
    hosts = {h["name"]: h for h in out["hosts"]}
    assert (hosts["esx1.lan"]["ip"], hosts["esx1.lan"]["online"]) == ("192.168.0.31", True) and hosts["esx2.lan"]["online"] is False     # loopback vnic skipped
    guests = {g["name"]: g for g in out["guests"]}
    assert sorted(guests) == ["app", "db", "web"]                                                # the template and the second page are handled
    web = guests["web"]
    assert (web["status"], web["ips"], web["macs"], web["host_id"].endswith("/host-1")) == ("running", ["192.168.0.50"], ["00:50:56:aa:00:01"], True)
    assert web["details"]["cpus"] == 2 and web["details"]["memory_mb"] == 4096 and web["details"]["os"].startswith("Debian") and web["details"]["health"] == "healthy"
    assert guests["db"]["status"] == "stopped" and guests["app"]["host_id"].endswith("/host-2") and "health" not in guests["app"]["details"]


def test_message_for_a_standalone_esxi():
    with Vsphere(api_type="HostAgent") as s:
        message = plugin.test(config(s))["message"]
    assert "Connected to VMware vCenter Server 8.0: 2 host(s), 3 virtual machine(s), 2 running, 1 with an address from VMware Tools. 1 host(s) are not connected" in message


def test_wrong_password_and_diagnose():
    with Vsphere() as s:
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config(s, "wrong"))
        assert caught.value.auth_failed is True
        text = json.dumps(plugin.diagnose(config(s)))
    assert "192.168" not in text and "esx1" not in text and '"api_type": "VirtualCenter"' in text and '"with_tools_addresses": 1' in text
