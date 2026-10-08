import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from app.db import connect, init_db
from app.scanner import names
from app.scanner.classify import classify_device
from app.scanner.names import fetch_upnp_description, hints_from_mdns, hints_from_upnp, parse_upnp_description
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

NOW = "2026-03-10T12:00:00Z"


def host(ip="10.0.0.9", mac="aa:bb:cc:00:00:09", hostnames=(), vendor=None):
    return ScanHost(ip=ip, mac=mac, vendor=vendor, hostnames=list(hostnames), os_name=None, os_accuracy=None, os_type=None, ports=[], ttl=64, via="arp", timed_out=False)


# ------------------------------------------------------------------ classification
@pytest.mark.parametrize("kwargs,expected", [
    (dict(hints=["upnp:internetgatewaydevice"], vendor="Acme"), "router"),
    (dict(hints=["upnp:wlanaccesspoint"]), "ap"),
    (dict(hints=["mdns:_ipp._tcp"], vendor="Acme"), "printer"),
    (dict(hints=["mdns:_axis-video._tcp"]), "camera"),
    (dict(hints=["mdns:_googlecast._tcp"], vendor="Acme"), "iot"),
    (dict(hints=["mdns:_hap._tcp"]), "iot"),
    (dict(hints=["mdns:_workstation._tcp"]), "pc"),
    (dict(hostnames=["Bert-iPhone.home.lan"]), "unknown"),  # "bert-iphone" splits into bert, iphone -> phone
    (dict(hostnames=["shelly1-AB12.lan"]), "iot"),
    (dict(hostnames=["hp-laserjet-4.lan"]), "printer"),
    (dict(hostnames=["DESKTOP-9F2K.home"], vendor="ASUSTek Computer"), "pc"),  # the name beats "ASUS means router"
    (dict(hostnames=["esxi.home.codeshrimp.com"]), "server"),
    (dict(hostnames=["somebox.tv.example.com"]), "unknown"),  # only the first label counts: the domain says nothing
    (dict(hostnames=["living-room-tv.lan"]), "iot"),
])
def test_hints_and_names_classify(kwargs, expected):
    if expected == "unknown" and kwargs.get("hostnames") == ["Bert-iPhone.home.lan"]:
        expected = "phone"
    assert classify_device(**kwargs) == expected


def test_strong_hints_beat_vendor_but_weak_hints_do_not_beat_the_os():
    assert classify_device(vendor="ASUSTek", hints=["mdns:_ipp._tcp"]) == "printer"
    assert classify_device(os_name="Windows 11", hints=["mdns:_airplay._tcp"]) == "pc"  # a PC that can receive AirPlay is still a PC
    assert classify_device(hints=["mdns:_airplay._tcp"]) == "iot"
    assert classify_device(vendor="vmware", hints=["mdns:_ipp._tcp"]) == "vm"  # VM detection stays first


# ------------------------------------------------------------------ discovery helpers
DESC = """<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Home Gateway</friendlyName><manufacturer>Acme</manufacturer><modelName>GW-9</modelName></device></root>"""


def test_upnp_description_gives_a_kind_and_a_model():
    desc = parse_upnp_description(DESC)
    assert desc["device_type"].endswith("InternetGatewayDevice:1") and desc["friendly_name"] == "Home Gateway"
    assert hints_from_upnp(desc) == ["upnp:internetgatewaydevice", "model:Acme GW-9"]
    assert hints_from_upnp({}) == []


def test_mdns_service_gives_hints_and_a_friendly_name():
    hints, friendly = hints_from_mdns("_googlecast._tcp.local.", {b"fn": b"Living room TV", b"md": b"Chromecast"})
    assert hints == ["mdns:_googlecast._tcp", "model:Chromecast"] and friendly == ["Living room TV"]
    assert hints_from_mdns("weird", None) == ([], [])


async def test_upnp_description_is_only_fetched_from_the_announcing_host():
    assert await fetch_upnp_description("http://10.0.0.99/desc.xml", "10.0.0.5") == {}  # points at another host
    assert await fetch_upnp_description("https://10.0.0.5/desc.xml", "10.0.0.5") == {}  # not plain http
    assert await fetch_upnp_description("file:///etc/passwd", "10.0.0.5") == {}
    assert await fetch_upnp_description("http://127.0.0.1:1/desc.xml", "127.0.0.1", timeout=0.5) == {}  # unreachable: no exception


async def test_collect_names_adds_what_upnp_devices_say_about_themselves():
    async def fake_ssdp(timeout, locations=None):
        locations["10.0.0.5"] = "http://10.0.0.5:5000/desc.xml"
        return {"10.0.0.5": [("Linux", "ssdp")]}

    with patch.object(names, "ssdp_search", fake_ssdp), patch.object(names, "mdns_browse", AsyncMock(return_value={})), \
            patch.object(names, "fetch_upnp_description", AsyncMock(return_value=parse_upnp_description(DESC))):
        result = await names.collect_names(0.1)
    assert ("Home Gateway", "upnp") in result["10.0.0.5"] and ("upnp:internetgatewaydevice", "hint") in result["10.0.0.5"]
    assert ("Linux", "ssdp") in result["10.0.0.5"]


# ------------------------------------------------------------------ storing
@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    return c


def test_hints_are_kept_not_listed_as_names_and_classify_the_device(conn):
    extra = {"10.0.0.9": [("Office printer", "mdns"), ("mdns:_ipp._tcp", "hint"), ("model:HP LaserJet", "hint")]}
    save_scan_results(conn, [host()], "quick", NOW, extra_names=extra)
    row = conn.execute("SELECT hostname, device_type, hints FROM devices").fetchone()
    assert row["hostname"] == "Office printer" and row["device_type"] == "printer"
    assert json.loads(row["hints"]) == ["mdns:_ipp._tcp", "model:HP LaserJet"]
    assert [tuple(r) for r in conn.execute("SELECT name, source FROM device_names")] == [("Office printer", "mdns")]
    # the next scan finds nothing new, but the device keeps its type
    save_scan_results(conn, [host()], "quick", "2026-03-10T12:15:00Z", extra_names=None)
    assert conn.execute("SELECT device_type FROM devices").fetchone()[0] == "printer"
    # hints are not duplicated
    save_scan_results(conn, [host()], "quick", "2026-03-10T12:30:00Z", extra_names=extra)
    assert len(json.loads(conn.execute("SELECT hints FROM devices").fetchone()[0])) == 2


def test_an_ssdp_product_token_is_not_used_as_the_hostname(conn):
    save_scan_results(conn, [host()], "quick", NOW, extra_names={"10.0.0.9": [("Linux", "ssdp")]})
    row = conn.execute("SELECT hostname FROM devices").fetchone()
    assert row["hostname"] is None  # still shows its IP
    assert conn.execute("SELECT COUNT(*) FROM device_names WHERE source = 'ssdp'").fetchone()[0] == 1  # but the alias is kept
    save_scan_results(conn, [host(hostnames=[("nas.lan", "ptr")])], "quick", "2026-03-10T12:15:00Z", extra_names={"10.0.0.9": [("Linux", "ssdp")]})
    assert conn.execute("SELECT hostname FROM devices").fetchone()[0] == "nas.lan"


def test_hostname_tokens_classify_during_a_scan(conn):
    save_scan_results(conn, [host(hostnames=[("shelly1-AB12.lan", "ptr")], vendor="Espressif")], "quick", NOW)
    assert conn.execute("SELECT device_type FROM devices").fetchone()[0] == "iot"
