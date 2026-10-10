"""DNS names for devices: valid labels, generated names for devices that have none, and collision handling."""

from __future__ import annotations

import ipaddress
import re
import unicodedata

DEFAULT_TEMPLATE = "{type}-{vendor}-{mac4}"
MAX_LABEL = 63


def clean_label(text: str | None) -> str | None:
    """A valid host label (lower case letters, digits and hyphens, at most 63 characters), or None when nothing usable is left."""
    if not text:
        return None
    text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode("ascii").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    text = re.sub(r"-{2,}", "-", text)[:MAX_LABEL].strip("-")
    if not text:
        return None
    try:
        ipaddress.ip_address(text.replace("-", "."))   # "192-168-0-5" reads as an address, not a name
        return None
    except ValueError:
        return text


def first_label(hostname: str | None) -> str | None:
    """"desktop-abc.home.example.com" -> "desktop-abc" (the domain part says nothing about the device)."""
    return clean_label((hostname or "").split(".")[0]) if hostname else None


def _vendor_word(vendor: str | None) -> str:
    words = [w for w in re.split(r"[^A-Za-z0-9]+", vendor or "") if w]
    for word in words:
        if word.lower() not in ("the", "inc", "corp", "corporation", "co", "ltd", "gmbh", "llc", "technologies", "international"):
            return clean_label(word) or ""
    return ""


def generated_name(template: str | None, device_type: str | None, vendor: str | None, mac: str | None, ip: str | None) -> str:
    """A stable name for a device that has none, for example "tv-samsung-a1b2". Always returns something usable."""
    mac_hex = re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    ip_tail = "-".join((ip or "").split(".")[-2:]) if ip else ""
    tokens = {
        "type": clean_label(device_type) if device_type and device_type != "unknown" else "device",
        "vendor": _vendor_word(vendor),
        "mac4": mac_hex[-4:],
        "mac6": mac_hex[-6:],
        "ip": ip_tail,
    }
    label = clean_label((template or DEFAULT_TEMPLATE).format_map(_Safe(tokens)))
    if not label or label == "device":
        label = clean_label(f"device-{tokens['mac4'] or ip_tail}") or "device"
    return label


class _Safe(dict):
    def __missing__(self, key):
        return ""


def fqdn(label: str, zone: str) -> str:
    return f"{label}.{zone}".lower()


def resolve_collisions(wanted: dict[int, str], keep: dict[int, str] | None = None, blocked: set[str] | None = None) -> dict[int, str]:
    """Give every device a different label. `wanted` {device id: label}; `keep` {device id: label it already has in DNS}
    wins its label first, then the lowest device id; the others get -2, -3... `blocked` labels are never handed out."""
    keep = keep or {}
    blocked = set(blocked or ())
    taken: set[str] = set()
    result: dict[int, str] = {}
    order = sorted(wanted, key=lambda d: (0 if keep.get(d) == wanted[d] else 1, d))
    for device_id in order:
        base = wanted[device_id]
        label, n = base, 1
        while label in taken or label in blocked:
            n += 1
            suffix = f"-{n}"
            label = base[: MAX_LABEL - len(suffix)].rstrip("-") + suffix
        taken.add(label)
        result[device_id] = label
    return result


def reverse_name(ip: str) -> str:
    """"192.168.0.7" -> "7.0.168.192.in-addr.arpa"."""
    return ipaddress.ip_address(ip).reverse_pointer
