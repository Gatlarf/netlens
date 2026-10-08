"""Pure device classification logic for Netlens."""

from __future__ import annotations

import re
from typing import Iterable

DEVICE_TYPES: tuple[str, ...] = (
    "router",
    "switch",
    "ap",
    "server",
    "pc",
    "phone",
    "printer",
    "iot",
    "camera",
    "nas",
    "vm",
    "unknown",
)

# Rule 1: VM MAC prefixes
VM_MAC_PREFIXES: tuple[str, ...] = (
    "52:54:00",
    "00:50:56",
    "00:0c:29",
    "08:00:27",
    "bc:24:11",
    "00:15:5d",
)

# Rule 1: VM vendor keywords
VM_VENDOR_KEYWORDS: tuple[str, ...] = (
    "vmware",
    "qemu",
    "virtualbox",
    "microsoft hyper-v",
    "proxmox",
)

# Rule 2: os_type mapping
OS_TYPE_MAP: dict[str, str] = {
    "router": "router",
    "switch": "switch",
    "wap": "ap",
    "printer": "printer",
    "webcam": "camera",
    "phone": "phone",
    "storage-misc": "nas",
    "media device": "iot",
    "game console": "iot",
    "specialized": "iot",
    "power-device": "iot",
    "pda": "iot",
    "terminal": "iot",
}

# Rule 3: Vendor keyword groups
VENDOR_NAS_KEYWORDS: tuple[str, ...] = (
    "synology",
    "qnap",
    "western digital",
)

VENDOR_CAMERA_KEYWORDS: tuple[str, ...] = (
    "hikvision",
    "dahua",
    "axis communications",
    "reolink",
    "amcrest",
)

VENDOR_PRINTER_KEYWORDS: tuple[str, ...] = (
    "hp",
    "hewlett",
    "canon",
    "epson",
    "brother",
    "xerox",
    "lexmark",
    "kyocera",
    "ricoh",
)

PRINTER_PORTS: frozenset[int] = frozenset({631, 9100, 515})

VENDOR_IOT_KEYWORDS: tuple[str, ...] = (
    "espressif",
    "tuya",
    "sonoff",
    "shelly",
)

VENDOR_ROUTER_KEYWORDS: tuple[str, ...] = (
    "ubiquiti",
    "mikrotik",
    "tp-link",
    "netgear",
    "cisco",
    "aruba",
    "ruckus",
    "zyxel",
    "d-link",
    "avm",
    "fritz",
    "belkin",
    "asus",
    "linksys",
    "huawei",
)

VENDOR_PHONE_KEYWORDS: tuple[str, ...] = (
    "apple",
    "samsung",
    "xiaomi",
    "oneplus",
    "google",
    "huawei device",
    "oppo",
    "motorola",
)

# Discovery hints (stored per device as "mdns:<service type>", "upnp:<device type>", "model:<text>").
# Strong hints name the kind of device outright; weak hints only say "something smart / a computer" and are
# used after the operating system rules.
STRONG_HINTS: tuple[tuple[str, str], ...] = (
    ("upnp:internetgatewaydevice", "router"),
    ("upnp:wlanaccesspoint", "ap"),
    ("upnp:printer", "printer"),
    ("mdns:_ipp._tcp", "printer"),
    ("mdns:_ipps._tcp", "printer"),
    ("mdns:_printer._tcp", "printer"),
    ("mdns:_pdl-datastream._tcp", "printer"),
    ("mdns:_scanner._tcp", "printer"),
    ("mdns:_axis-video._tcp", "camera"),
    ("mdns:_rtsp._tcp", "camera"),
)
WEAK_HINTS: tuple[tuple[str, str], ...] = (
    ("mdns:_googlecast._tcp", "iot"),
    ("mdns:_hap._tcp", "iot"),
    ("mdns:_homekit._tcp", "iot"),
    ("mdns:_esphomelib._tcp", "iot"),
    ("mdns:_arduino._tcp", "iot"),
    ("mdns:_spotify-connect._tcp", "iot"),
    ("mdns:_airplay._tcp", "iot"),
    ("mdns:_raop._tcp", "iot"),
    ("upnp:mediarenderer", "iot"),
    ("upnp:mediaserver", "iot"),
    ("mdns:_workstation._tcp", "pc"),
)

# Words in a device's name that say what it is (the name is split on anything that is not a letter or digit).
HOSTNAME_TOKENS: tuple[tuple[str, frozenset[str]], ...] = (
    ("phone", frozenset({"iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi", "huawei-phone"})),
    ("camera", frozenset({"cam", "camera", "ipcam", "doorbell", "reolink", "wyze"})),
    ("printer", frozenset({"printer", "laserjet", "officejet", "deskjet", "pixma", "envy"})),
    ("iot", frozenset({"shelly", "tasmota", "esp", "esp32", "esp8266", "esphome", "sonoff", "tuya", "wled", "chromecast", "roku", "firetv", "appletv", "sonos", "hue", "tv"})),
    ("nas", frozenset({"nas", "synology", "qnap", "truenas", "diskstation"})),
    ("server", frozenset({"pve", "proxmox", "esxi", "docker", "srv", "server", "homeassistant", "pihole"})),
    ("pc", frozenset({"desktop", "laptop", "macbook", "imac", "thinkpad", "workstation", "pc"})),
)

# Rule 4: Port-based rules
CAMERA_PORTS: frozenset[int] = frozenset({554, 8554})
NAS_PORTS: frozenset[int] = frozenset({5000, 5001, 2049, 548})
ROUTER_PORTS: frozenset[int] = frozenset({53, 67})

# Rule 5: OS name rules
WINDOWS_SERVER_PORTS: frozenset[int] = frozenset({3389, 445, 1433, 80, 443})
LINUX_SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 3306, 5432, 8080, 8006})

# Rule 6: General server ports
SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 8080, 3306})


def _token_matches(token: str, word: str) -> bool:
    """'shelly1' is the word 'shelly' plus a number; long words also match as a prefix ('thinkpadx1')."""
    return token == word or re.fullmatch(rf"{re.escape(word)}\d+", token) is not None or (len(word) >= 6 and token.startswith(word))


def classify_device(
    *,
    vendor: str | None = None,
    os_name: str | None = None,
    os_type: str | None = None,
    open_ports: Iterable[int] = (),
    services: Iterable[str] = (),
    hostnames: Iterable[str] = (),
    mac: str | None = None,
    hints: Iterable[str] = (),
) -> str:
    """Classify a device into one of DEVICE_TYPES.

    Rules are evaluated in order; first match wins.
    All string matching is case-insensitive.
    """
    # Normalize inputs
    vendor_lower = vendor.lower() if vendor else ""
    os_name_lower = os_name.lower() if os_name else ""
    os_type_lower = os_type.lower() if os_type else ""
    mac_lower = mac.lower() if mac else ""

    ports = set(open_ports)
    services_set = {s.lower() for s in services if s}
    hostnames_set = {h.lower() for h in hostnames if h}
    hint_set = {h.lower() for h in hints if h}

    # Rule 1: VM
    if mac_lower:
        for prefix in VM_MAC_PREFIXES:
            if mac_lower.startswith(prefix):
                return "vm"
    if vendor_lower:
        for kw in VM_VENDOR_KEYWORDS:
            if kw in vendor_lower:
                return "vm"

    # Rule 2: os_type mapping
    if os_type_lower:
        mapped = OS_TYPE_MAP.get(os_type_lower)
        if mapped:
            return mapped

    # Rule 2b: discovery hints that name the kind of device, then words in its name
    for token, device_type in STRONG_HINTS:
        if token in hint_set:
            return device_type
    name_tokens = {t for h in hostnames_set for t in re.split(r"[^a-z0-9]+", h.split(".")[0]) if t}  # first label only: the domain says nothing
    for device_type, words in HOSTNAME_TOKENS:
        if any(_token_matches(t, w) for t in name_tokens for w in words):
            return device_type

    # Rule 3: Vendor keywords
    if vendor_lower:
        # NAS vendors
        for kw in VENDOR_NAS_KEYWORDS:
            if kw in vendor_lower:
                return "nas"

        # Camera vendors
        for kw in VENDOR_CAMERA_KEYWORDS:
            if kw in vendor_lower:
                return "camera"

        # Printer vendors (with printer ports)
        for kw in VENDOR_PRINTER_KEYWORDS:
            if kw in vendor_lower:
                if ports & PRINTER_PORTS:
                    return "printer"

        # IoT vendors
        for kw in VENDOR_IOT_KEYWORDS:
            if kw in vendor_lower:
                return "iot"

        # Router/AP/Switch vendors
        for kw in VENDOR_ROUTER_KEYWORDS:
            if kw in vendor_lower:
                # Check hostname tokens
                hostname_tokens = set()
                for h in hostnames_set:
                    tokens = re.split(r'[^a-z0-9]+', h)
                    hostname_tokens.update(t for t in tokens if t)

                # Router if hostname contains router/gw/gateway or ports include 53
                if any(t in ("router", "gw", "gateway") for t in hostname_tokens) or 53 in ports:
                    return "router"

                # AP if hostname contains "ap" as a token or wifi/wlan/unifi
                if "ap" in hostname_tokens or any(t in ("wifi", "wlan", "unifi") for t in hostname_tokens):
                    return "ap"

                # Switch if hostname contains sw/switch
                if any(t in ("sw", "switch") for t in hostname_tokens):
                    return "switch"

                # Default to router
                return "router"

        # Phone vendors (when no ports open)
        for kw in VENDOR_PHONE_KEYWORDS:
            if kw in vendor_lower:
                if not ports:
                    return "phone"

    # Rule 4: Port rules
    if ports & PRINTER_PORTS:
        return "printer"

    if ports & CAMERA_PORTS:
        return "camera"

    if ports & NAS_PORTS or any("nas" in h for h in hostnames_set):
        return "nas"

    if 53 in ports and 67 in ports:
        return "router"

    # Rule 5: OS name rules
    if os_name_lower:
        # Windows
        if "windows" in os_name_lower:
            if "server" in os_name_lower and ports & WINDOWS_SERVER_PORTS:
                return "server"
            return "pc"

        # Android / iOS
        if "android" in os_name_lower or "ios" in os_name_lower or "iphone" in os_name_lower:
            return "phone"

        # Linux / BSD
        if "linux" in os_name_lower or "bsd" in os_name_lower:
            if ports & LINUX_SERVER_PORTS:
                return "server"
            return "pc"

        # macOS
        if "mac os" in os_name_lower or "macos" in os_name_lower:
            return "pc"

    # Rule 5b: weak discovery hints
    for token, device_type in WEAK_HINTS:
        if token in hint_set:
            return device_type

    # Rule 6: General server ports
    if ports & SERVER_PORTS:
        return "server"

    # Rule 7: Unknown
    return "unknown"