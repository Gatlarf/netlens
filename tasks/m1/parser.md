Create app/scanner/nmap_parser.py. Parse nmap XML (-oX output) with xml.etree.ElementTree (stdlib; the input is from our own nmap run, but still never evaluate anything from it).

Dataclasses (frozen not required):
- ScanPort(proto: str, port: int, state: str, service: str | None, product: str | None, version: str | None, extrainfo: str | None)
- ScanHost(ip: str, mac: str | None, vendor: str | None, hostnames: list[tuple[str, str]] (name, type e.g. "PTR"/"user"), ports: list[ScanPort], os_name: str | None, os_accuracy: int | None, os_type: str | None (osclass type of the best match), ttl: int | None (reason_ttl of the status element if > 0 else None), via: str (the status reason attribute, e.g. "arp-response"))

def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
- Only hosts whose status state is "up". Skip hosts without an ipv4 address (ignore ipv6-only hosts).
- MAC lowercase with colons; vendor from the mac address element's vendor attribute (None if absent).
- Ports: include every port element; state from the state element's state attribute; service attrs name/product/version/extrainfo optional. Keep only ports whose state starts with "open" (so "open" and "open|filtered") in the result.
- OS: choose the osmatch with the highest accuracy (int). os_type is the type attribute of its first osclass. No os element means all None.
- Raise ValueError("invalid nmap xml") if the XML cannot be parsed or the root tag is not nmaprun.
- Pure function, no I/O.
