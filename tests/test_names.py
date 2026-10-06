import pytest
from unittest.mock import AsyncMock, patch
from app.scanner.names import parse_ssdp_response, parse_upnp_description, collect_names


def test_parse_ssdp_response_basic():
    text = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux/4.9 UPnP/1.0 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n"
    result = parse_ssdp_response(text)
    assert result["location"] == "http://192.168.1.1:5000/desc.xml"
    assert result["server"] == "Linux/4.9 UPnP/1.0 MiniUPnPd/2.1"
    assert result["st"] == "upnp:rootdevice"
    assert result["usn"] == "uuid:abc::upnp:rootdevice"


def test_parse_ssdp_response_mixed_case_headers():
    text = "HTTP/1.1 200 OK\r\nCache-Control: max-age=1800\r\nLocation: http://192.168.1.1:5000/desc.xml\r\nServer: Linux/4.9 UPnP/1.0 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n"
    result = parse_ssdp_response(text)
    assert result["location"] == "http://192.168.1.1:5000/desc.xml"
    assert result["server"] == "Linux/4.9 UPnP/1.0 MiniUPnPd/2.1"
    assert result["st"] == "upnp:rootdevice"
    assert result["usn"] == "uuid:abc::upnp:rootdevice"


def test_parse_ssdp_response_empty():
    assert parse_ssdp_response("") == {}


def test_parse_ssdp_response_garbage():
    assert parse_ssdp_response("garbage") == {}


def test_parse_upnp_description_full():
    xml = """<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:tv:1</deviceType>
    <friendlyName>Living Room TV</friendlyName>
    <manufacturer>Samsung</manufacturer>
    <modelName>UE55</modelName>
    <modelNumber>1.0</modelNumber>
  </device>
</root>"""
    result = parse_upnp_description(xml)
    assert result["friendly_name"] == "Living Room TV"
    assert result["manufacturer"] == "Samsung"
    assert result["model_name"] == "UE55"
    assert result["model_number"] == "1.0"


def test_parse_upnp_description_only_friendlyName():
    xml = """<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>Living Room TV</friendlyName>
  </device>
</root>"""
    result = parse_upnp_description(xml)
    assert result == {"friendly_name": "Living Room TV"}


def test_parse_upnp_description_invalid_xml():
    assert parse_upnp_description("invalid xml") == {}


@pytest.mark.asyncio
async def test_collect_names_merged():
    ssdp_result = {"192.168.1.5": [("tv", "ssdp")]}
    mdns_result = {"192.168.1.5": [("tv.local", "mdns")], "192.168.1.9": [("nas", "mdns")]}

    with patch("app.scanner.names.ssdp_search", new_callable=AsyncMock) as mock_ssdp, \
         patch("app.scanner.names.mdns_browse", new_callable=AsyncMock) as mock_mdns:
        mock_ssdp.return_value = ssdp_result
        mock_mdns.return_value = mdns_result

        result = await collect_names()
        assert result == {
            "192.168.1.5": [("tv", "ssdp"), ("tv.local", "mdns")],
            "192.168.1.9": [("nas", "mdns")],
        }


@pytest.mark.asyncio
async def test_collect_names_ssdp_error():
    ssdp_result = {"192.168.1.5": [("tv", "ssdp")]}
    mdns_result = {"192.168.1.5": [("tv.local", "mdns")], "192.168.1.9": [("nas", "mdns")]}

    with patch("app.scanner.names.ssdp_search", new_callable=AsyncMock) as mock_ssdp, \
         patch("app.scanner.names.mdns_browse", new_callable=AsyncMock) as mock_mdns:
        mock_ssdp.side_effect = RuntimeError("ssdp failed")
        mock_mdns.return_value = mdns_result

        result = await collect_names()
        assert result == {
            "192.168.1.5": [("tv.local", "mdns")],
            "192.168.1.9": [("nas", "mdns")],
        }


@pytest.mark.asyncio
async def test_collect_names_mdns_error():
    ssdp_result = {"192.168.1.5": [("tv", "ssdp")]}
    mdns_result = {"192.168.1.5": [("tv.local", "mdns")], "192.168.1.9": [("nas", "mdns")]}

    with patch("app.scanner.names.ssdp_search", new_callable=AsyncMock) as mock_ssdp, \
         patch("app.scanner.names.mdns_browse", new_callable=AsyncMock) as mock_mdns:
        mock_ssdp.return_value = ssdp_result
        mock_mdns.side_effect = RuntimeError("mdns failed")

        result = await collect_names()
        assert result == {
            "192.168.1.5": [("tv", "ssdp")],
        }


@pytest.mark.asyncio
async def test_collect_names_both_error():
    with patch("app.scanner.names.ssdp_search", new_callable=AsyncMock) as mock_ssdp, \
         patch("app.scanner.names.mdns_browse", new_callable=AsyncMock) as mock_mdns:
        mock_ssdp.side_effect = RuntimeError("ssdp failed")
        mock_mdns.side_effect = RuntimeError("mdns failed")

        result = await collect_names()
        assert result == {}