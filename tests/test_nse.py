import xml.etree.ElementTree as ET

from app.scanner.classify import classify_device
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.options import ScanOptions, option_args, options_from_dict

XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="arp-response"/><address addr="10.0.0.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>
<script id="http-title" output="Synology DiskStation"><elem key="title">Synology DiskStation</elem></script></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
<script id="ssl-cert" output="..."><table key="subject"><elem key="commonName">nas.local</elem><elem key="organizationName">Synology Inc.</elem></table></script></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/><script id="banner" output="SSH-2.0-dropbear_2020.81"/></port>
</ports>
<hostscript>
<script id="smb-os-discovery" output="..."><elem key="os">Windows 10 Pro 19045</elem><elem key="server">DESKTOP-ABC</elem></script>
<script id="nbstat" output="NetBIOS name: DESKTOP-ABC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: aa"/>
<script id="upnp-info" output="&#10;  Name: x&#10;  Model Name: Chromecast"/>
</hostscript></host></nmaprun>"""


def test_scripts_give_names_and_hints():
    host = parse_nmap_xml(XML)[0]
    names = set(host.hostnames)
    assert ("title:Synology DiskStation", "hint") in names
    assert ("cert:Synology Inc.", "hint") in names
    assert ("os:Windows 10 Pro 19045", "hint") in names
    assert ("DESKTOP-ABC", "smb") in names and ("DESKTOP-ABC", "netbios") in names
    assert ("model:Chromecast", "hint") in names
    assert any(n.startswith("banner:SSH-2.0-dropbear") for n, _ in names)


def test_boring_output_is_ignored():
    xml = XML.replace("Synology DiskStation</elem>", "Did not follow redirect to https://x</elem>").replace("Synology Inc.", "Internet Widgits Pty Ltd")
    names = set(parse_nmap_xml(xml)[0].hostnames)
    assert not any(n.startswith(("title:", "cert:")) for n, _ in names)


def test_classifier_uses_script_findings():
    assert classify_device(hints=["title:Synology DiskStation"]) == "nas"
    assert classify_device(hints=["os:Windows 10 Pro 19045"]) == "pc"
    assert classify_device(hints=["os:Windows Server 2019 Standard"]) == "server"
    assert classify_device(hints=["model:iPhone14,2"]) == "phone"
    assert classify_device(hints=["model:Chromecast"]) == "tv"
    assert classify_device(hints=["ctl:printer"]) == "printer"
    assert classify_device(hints=["ctl:bogus"]) == "unknown"


def test_option_is_off_by_default_and_adds_scripts():
    assert "--script" not in option_args("deep", ScanOptions())
    args = option_args("deep", options_from_dict({"deep_scripts": True}))
    assert "--script-timeout" in args and "http-title" in args[args.index("--script") + 1]
    assert "--script" in option_args("full", options_from_dict({"deep_scripts": True}))
