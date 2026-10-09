"""What nmap's identification scripts (see options.IDENTIFY_SCRIPTS) found, as names and discovery hints.

Names go in as (name, source) like any other hostname; hints are stored on the device as "title:", "cert:", "os:",
"model:" and "banner:" and are weighed by the classifier.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

MAX_TEXT = 80
_BORING_TITLES = ("did not follow redirect", "site doesn't have a title", "document moved", "301 moved", "302 found", "index of /", "403 forbidden", "404 not found", "401 unauthorized", "welcome to nginx", "apache2 default page", "it works", "error")
_BORING_ORGS = ("internet widgits", "default company", "somewhere", "unspecified", "none", "example", "localhost")


def _clean(text: str | None) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()[:MAX_TEXT]


def _elems(script: ET.Element) -> dict[str, str]:
    """All <elem key=...> values of a script, also nested ones (key -> text; the first one wins)."""
    found: dict[str, str] = {}
    for el in script.iter("elem"):
        key = el.get("key")
        if key and el.text and key not in found:
            found[key] = el.text.strip()
    return found


def _title(script: ET.Element) -> str | None:
    raw = _elems(script).get("title")
    if not raw:
        lines = re.sub(r"^title:\s*", "", script.get("output", "").strip()).splitlines()
        raw = lines[0] if lines else ""
    title = _clean(raw)
    if not title or any(b in title.lower() for b in _BORING_TITLES):
        return None
    return title


def _cert(script: ET.Element) -> list[str]:
    values = _elems(script)
    org = _clean(values.get("organizationName"))
    if org and not any(b in org.lower() for b in _BORING_ORGS):
        return [org]
    return []


def _smb(script: ET.Element) -> tuple[list[str], list[str]]:
    values = _elems(script)
    hints, names = [], []
    os_text = _clean(values.get("os"))
    if os_text and os_text.lower() != "unknown":
        hints.append(f"os:{os_text}")
    server = _clean(values.get("server"))
    if server:
        names.append(server)
    return hints, names


def _netbios(script: ET.Element) -> list[str]:
    match = re.search(r"NetBIOS name:\s*([^,\s]+)", script.get("output", ""))
    return [_clean(match.group(1))] if match else []


def _upnp(script: ET.Element) -> list[str]:
    output = script.get("output", "")
    model = re.search(r"Model Name:\s*(.+)", output, re.I) or re.search(r"Model:\s*(.+)", output, re.I)
    return [f"model:{_clean(model.group(1))}"] if model and _clean(model.group(1)) else []


def _banner(script: ET.Element) -> str | None:
    text = _clean(script.get("output"))
    return text if text and len(text) >= 4 else None


def names_and_hints(host: ET.Element) -> list[tuple[str, str]]:
    """(name, source) pairs for the parser's hostname list; source "hint" marks a discovery hint."""
    out: list[tuple[str, str]] = []
    scripts = list(host.iter("script"))
    for script in scripts:
        sid = script.get("id", "")
        try:
            if sid == "http-title":
                title = _title(script)
                if title:
                    out.append((f"title:{title}", "hint"))
            elif sid == "ssl-cert":
                out += [(f"cert:{org}", "hint") for org in _cert(script)]
            elif sid == "smb-os-discovery":
                hints, names = _smb(script)
                out += [(h, "hint") for h in hints] + [(n, "smb") for n in names]
            elif sid == "nbstat":
                out += [(n, "netbios") for n in _netbios(script)]
            elif sid == "upnp-info":
                out += [(h, "hint") for h in _upnp(script)]
            elif sid == "banner":
                banner = _banner(script)
                if banner:
                    out.append((f"banner:{banner}", "hint"))
        except (ValueError, IndexError):
            continue  # one odd script output never breaks the scan
    return out
