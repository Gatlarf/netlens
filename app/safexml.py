"""XML that comes from the network (a UPnP description from a device, an answer from a router or a Windows host) is untrusted.

The standard library parser can be made to use a lot of memory or time with entity declarations in a DOCTYPE ("billion laughs", "quadratic blow-up"). None of the documents
Netlens reads this way needs a DOCTYPE or an entity, so a document that declares either is refused, and a document that is too large is refused too.
(nmap's own XML output has a DOCTYPE line, but it comes from the local nmap process, not from the network, and is read elsewhere.)
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

MAX_BYTES = 2_000_000
_DECLARATION = re.compile(rb"<!\s*(DOCTYPE|ENTITY|ELEMENT|ATTLIST)", re.I)


class UnsafeXml(ValueError):
    """The document is refused (too large, or it declares a DOCTYPE or entities)."""


def fromstring(text: str | bytes) -> ET.Element:
    data = text.encode("utf-8", "replace") if isinstance(text, str) else bytes(text)
    if len(data) > MAX_BYTES:
        raise UnsafeXml("the XML document is too large")
    if _DECLARATION.search(data):
        raise UnsafeXml("the XML document declares a DOCTYPE or entities, which is refused")
    return ET.fromstring(data)
