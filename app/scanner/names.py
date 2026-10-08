"""
app/scanner/names.py

Collect extra device names from the LAN without root privileges.
"""

import asyncio
import re
from typing import Optional

import xml.etree.ElementTree as ET


def parse_ssdp_response(text: str) -> dict[str, str]:
    """
    Parse an SSDP/HTTP-style response.

    Header lines are "NAME: value", case-insensitive names.
    Returns a dict with lowercase keys.
    Ignores the status line and malformed lines.
    """
    result: dict[str, str] = {}
    lines = text.splitlines()

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Skip status line (e.g., "HTTP/1.1 200 OK")
        if line.startswith("HTTP/"):
            continue

        # Parse header lines: NAME: value
        match = re.match(r"^([^:]+):\s*(.*)$", line)
        if match:
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            if key:
                result[key] = value

    return result


def parse_upnp_description(xml_text: str) -> dict[str, str]:
    """
    Parse a UPnP device description XML.

    Namespace-agnostic: match on local tag names.
    Return values of friendlyName, manufacturer, modelName, modelNumber.
    Keys: "friendly_name", "manufacturer", "model_name", "model_number".
    Invalid XML returns {}.
    """
    if "<!ENTITY" in xml_text:
        return {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    result: dict[str, str] = {}

    # Map local tag names to desired keys
    tag_to_key = {
        "friendlyName": "friendly_name",
        "manufacturer": "manufacturer",
        "modelName": "model_name",
        "modelNumber": "model_number",
        "deviceType": "device_type",
    }

    for elem in root.iter():
        # Get local tag name (strip namespace)
        tag = elem.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        if tag in tag_to_key:
            key = tag_to_key[tag]
            if key not in result:
                value = elem.text
                if value:
                    result[key] = value.strip()

    return result


def hints_from_upnp(desc: dict[str, str]) -> list[str]:
    """Discovery hints from a parsed UPnP description: its device type and make/model."""
    hints = []
    device_type = desc.get("device_type", "")
    if device_type:
        # urn:schemas-upnp-org:device:InternetGatewayDevice:1 -> internetgatewaydevice
        parts = [p for p in device_type.split(":") if p]
        kind = next((parts[i + 1] for i, p in enumerate(parts[:-1]) if p == "device"), parts[-1])
        hints.append(f"upnp:{kind.lower()}")
    model = " ".join(x for x in (desc.get("manufacturer"), desc.get("model_name")) if x)
    if model:
        hints.append(f"model:{model[:60]}")
    return hints


def hints_from_mdns(service_type: str, properties: dict | None = None) -> tuple[list[str], list[str]]:
    """(hints, friendly names) for one mDNS service: its type, and the names/models devices put in the TXT record."""
    hints = []
    kind = service_type.strip(".").removesuffix(".local").lower()
    if kind.startswith("_"):
        hints.append(f"mdns:{kind}")
    names = []

    def text(value) -> str:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return str(value).strip() if value else ""

    props = {text(k).lower(): text(v) for k, v in (properties or {}).items()}
    if props.get("fn"):  # Chromecast and friends: the friendly name
        names.append(props["fn"][:80])
    for key in ("md", "am", "model", "ty"):  # model strings
        if props.get(key):
            hints.append(f"model:{props[key][:60]}")
            break
    return hints, names


async def fetch_upnp_description(location: str, expected_ip: str, timeout: float = 2.0) -> dict[str, str]:
    """Fetch a device's UPnP description (only from the host that announced it, plain http, small answers only)."""
    from urllib.parse import urlparse

    parsed = urlparse(location)
    if parsed.scheme != "http" or parsed.hostname != expected_ip:
        return {}

    def get() -> str:
        import urllib.request

        with urllib.request.urlopen(location, timeout=timeout) as resp:  # noqa: S310 - checked above
            return resp.read(65536).decode("utf-8", errors="replace")

    try:
        return parse_upnp_description(await asyncio.to_thread(get))
    except Exception:  # noqa: BLE001 - discovery is best effort
        return {}


async def ssdp_search(timeout: float = 3.0, locations: dict[str, str] | None = None) -> dict[str, list[tuple[str, str]]]:
    """
    Send an M-SEARCH over UDP multicast 239.255.255.250:1900.

    Collect responses for `timeout` seconds.
    Map sender IP -> [(name, "ssdp")] where name is the SERVER header's product token.
    Never raise: return {} on any OSError.
    """
    result: dict[str, list[tuple[str, str]]] = {}

    try:
        # Create a UDP socket for multicast
        sock = asyncio.socket.socket(asyncio.socket.AF_INET, asyncio.socket.SOCK_DGRAM)
        sock.setblocking(False)

        # Set multicast TTL
        sock.setsockopt(asyncio.socket.IPTOS_MULTICAST, 0, 1)

        # Bind to a random port
        sock.bind(("", 0))

        # Send M-SEARCH
        m_search = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"Host: 239.255.255.250:1900\r\n"
            b"Man: \"ssdp:discover\"\r\n"
            b"ST: ssdp:all\r\n"
            b"MX: 2\r\n"
            b"\r\n"
        )

        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, m_search, ("239.255.255.250", 1900))

        # Collect responses
        deadline = asyncio.get_event_loop().time() + timeout

        while asyncio.get_event_loop().time() < deadline:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096),
                    timeout=deadline - asyncio.get_event_loop().time(),
                )
            except asyncio.TimeoutError:
                break
            except OSError:
                break

            if not data:
                continue

            text = data.decode("utf-8", errors="replace")
            headers = parse_ssdp_response(text)

            if locations is not None and headers.get("location") and addr[0] not in locations:
                locations[addr[0]] = headers["location"]
            server = headers.get("server", "")
            if server:
                # Extract product token from SERVER header
                # SERVER format: "OS/Version" or just "Product"
                # We take the first token before '/' or the whole string
                product = server.split("/")[0].strip()
                if product:
                    sender_ip = addr[0]
                    if sender_ip not in result:
                        result[sender_ip] = []
                    entry = (product, "ssdp")
                    if entry not in result[sender_ip]:
                        result[sender_ip].append(entry)

        sock.close()

    except OSError:
        return {}

    return result


async def mdns_browse(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
    """
    Use zeroconf to browse services and map IP -> [(server name, "mdns")].

    Import zeroconf inside the function. Return {} if missing or anything fails.
    """
    result: dict[str, list[tuple[str, str]]] = {}

    try:
        import zeroconf
        from zeroconf.asyncio import AsyncZeroconf, AsyncServiceBrowser
    except ImportError:
        return {}

    try:
        azeroconf = await AsyncZeroconf()
        browser = AsyncServiceBrowser(
            azeroconf,
            [
                "_workstation._tcp.local.",
                "_http._tcp.local.",
                "_ssh._tcp.local.",
                "_airplay._tcp.local.",
                "_ipp._tcp.local.",
                "_ipps._tcp.local.",
                "_printer._tcp.local.",
                "_pdl-datastream._tcp.local.",
                "_smb._tcp.local.",
                "_googlecast._tcp.local.",
                "_hap._tcp.local.",
                "_raop._tcp.local.",
                "_spotify-connect._tcp.local.",
                "_esphomelib._tcp.local.",
                "_rtsp._tcp.local.",
                "_axis-video._tcp.local.",
            ],
        )

        # Wait for timeout seconds
        await asyncio.sleep(timeout)

        # Resolve services
        for service in browser.services:
            try:
                info = await azeroconf.async_get_service_info(service)
                if info is None:
                    continue

                kind_hints, friendly = hints_from_mdns(info.type or service, info.properties)
                for ip in info.parsed_addresses():
                    for hint in kind_hints:
                        entry = (hint, "hint")
                        if entry not in result.setdefault(ip, []):
                            result[ip].append(entry)
                    for fn in friendly:
                        entry = (fn, "mdns")
                        if entry not in result[ip]:
                            result[ip].append(entry)
                server_name = info.server
                if server_name:
                    # Remove trailing ".local." and trailing dot
                    name = server_name
                    if name.endswith(".local."):
                        name = name[:-7]
                    if name.endswith("."):
                        name = name[:-1]

                    if not name:
                        continue

                    addresses = info.parsed_addresses()
                    for ip in addresses:
                        if ip not in result:
                            result[ip] = []
                        entry = (name, "mdns")
                        if entry not in result[ip]:
                            result[ip].append(entry)
            except Exception:
                continue

        await azeroconf.async_close()

    except Exception:
        return {}

    return result


async def collect_names(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
    """
    Run ssdp_search and mdns_browse concurrently.

    Merge the dicts (dedupe). Never raise.
    """
    locations: dict[str, str] = {}
    try:
        ssdp_result, mdns_result = await asyncio.gather(
            ssdp_search(timeout, locations),
            mdns_browse(timeout),
            return_exceptions=True,
        )
    except Exception:
        return {}

    # Handle exceptions from gather
    if isinstance(ssdp_result, Exception):
        ssdp_result = {}
    if isinstance(mdns_result, Exception):
        mdns_result = {}

    # Merge and dedupe
    merged: dict[str, list[tuple[str, str]]] = {}

    for ip, entries in ssdp_result.items():
        if ip not in merged:
            merged[ip] = []
        for entry in entries:
            if entry not in merged[ip]:
                merged[ip].append(entry)

    for ip, entries in mdns_result.items():
        if ip not in merged:
            merged[ip] = []
        for entry in entries:
            if entry not in merged[ip]:
                merged[ip].append(entry)

    # what the UPnP devices say about themselves (name, make, model, kind of device)
    if locations:
        gate = asyncio.Semaphore(8)

        async def describe(ip: str, location: str) -> tuple[str, dict[str, str]]:
            async with gate:
                return ip, await fetch_upnp_description(location, ip)

        for ip, desc in await asyncio.gather(*(describe(i, l) for i, l in locations.items())):
            if not desc:
                continue
            extra = []
            if desc.get("friendly_name"):
                extra.append((desc["friendly_name"][:80], "upnp"))
            extra += [(h, "hint") for h in hints_from_upnp(desc)]
            for entry in extra:
                if entry not in merged.setdefault(ip, []):
                    merged[ip].append(entry)

    return merged