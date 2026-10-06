Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
1. Hostname tokens are produced with h.split() (whitespace). They must be produced with re.split(r'[^a-z0-9]+', h.lower()) and empty tokens dropped, so 'unifi-ap-lobby' gives tokens unifi, ap, lobby and 'sw-core' gives sw, core. 2. The vendor keyword rule for IoT is missing: vendor containing any of espressif, tuya, sonoff, shelly returns 'iot' (place it with the other vendor rules, before the router/AP/switch vendors). 3. Windows rule: a Windows os_name returns 'server' when 'server' appears in os_name (lowercase) AND any of ports 3389, 445, 1433, 80, 443 is open; otherwise 'pc'. Do not use hostnames for that decision.

CURRENT FILE:
"""Pure device classification logic for Netlens."""

from __future__ import annotations

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

# Rule 4: Port-based rules
CAMERA_PORTS: frozenset[int] = frozenset({554, 8554})
NAS_PORTS: frozenset[int] = frozenset({5000, 5001, 2049, 548})
ROUTER_PORTS: frozenset[int] = frozenset({53, 67})

# Rule 5: OS name rules
WINDOWS_SERVER_PORTS: frozenset[int] = frozenset({3389, 445, 1433, 80, 443})
LINUX_SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 3306, 5432, 8080, 8006})

# Rule 6: General server ports
SERVER_PORTS: frozenset[int] = frozenset({22, 80, 443, 8080, 3306})


def classify_device(
    *,
    vendor: str | None = None,
    os_name: str | None = None,
    os_type: str | None = None,
    open_ports: Iterable[int] = (),
    services: Iterable[str] = (),
    hostnames: Iterable[str] = (),
    mac: str | None = None,
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

        # Router/AP/Switch vendors
        for kw in VENDOR_ROUTER_KEYWORDS:
            if kw in vendor_lower:
                # Check hostname tokens
                hostname_tokens = set()
                for h in hostnames_set:
                    hostname_tokens.update(h.split())

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
            if ports & WINDOWS_SERVER_PORTS and any("server" in h for h in hostnames_set):
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

    # Rule 6: General server ports
    if ports & SERVER_PORTS:
        return "server"

    # Rule 7: Unknown
    return "unknown"