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
    "tablet",
    "tv",
    "speaker",
    "console",
    "appliance",
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
    "00:16:3e",  # Xen / LXD
    "10:66:6a",  # Incus
    "02:42:",    # Docker
    "00:1c:42",  # Parallels
    "00:05:69",  # VMware
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
    "media device": "tv",
    "game console": "console",
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
    "asustor",
    "terramaster",
)

VENDOR_CAMERA_KEYWORDS: tuple[str, ...] = (
    "hikvision",
    "dahua",
    "axis communications",
    "reolink",
    "amcrest",
    "vimtag",
    "foscam",
    "wyze",
    "arlo",
    "uniview",
    "lorex",
    "annke",
)

VENDOR_TV_KEYWORDS: tuple[str, ...] = ("silicondust", "roku", "vizio", "hisense")
VENDOR_SPEAKER_KEYWORDS: tuple[str, ...] = ("sonos", "bose")
VENDOR_CONSOLE_KEYWORDS: tuple[str, ...] = ("nintendo", "sony interactive")
VENDOR_APPLIANCE_KEYWORDS: tuple[str, ...] = ("irobot", "roborock", "dyson", "miele", "ecovacs")

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
    ("tablet", frozenset({"ipad", "tablet", "tab", "kindle"})),
    ("phone", frozenset({"iphone", "android", "galaxy", "pixel", "oneplus", "redmi", "huawei-phone"})),
    ("camera", frozenset({"cam", "camera", "ipcam", "doorbell", "reolink", "wyze"})),
    ("printer", frozenset({"printer", "laserjet", "officejet", "deskjet", "pixma", "envy"})),
    ("tv", frozenset({"tv", "chromecast", "roku", "firetv", "appletv", "bravia", "webos", "tizen", "hdhomerun", "shield"})),
    ("speaker", frozenset({"sonos", "homepod", "alexa", "soundbar", "speaker", "echo"})),
    ("console", frozenset({"playstation", "ps4", "ps5", "xbox", "nintendo", "steamdeck"})),
    ("appliance", frozenset({"roomba", "roborock", "dyson", "miele", "thermostat", "dishwasher", "washer", "dryer", "fridge"})),
    ("iot", frozenset({"shelly", "tasmota", "esp", "esp32", "esp8266", "esphome", "sonoff", "tuya", "wled", "hue"})),
    ("nas", frozenset({"nas", "synology", "qnap", "truenas", "diskstation"})),
    ("server", frozenset({"pve", "proxmox", "esxi", "docker", "srv", "server", "homeassistant", "pihole"})),
    ("pc", frozenset({"desktop", "laptop", "macbook", "imac", "thinkpad", "workstation", "pc"})),
)

# Words in nmap's name for the operating system / device that say what the device is (nmap sometimes names the product:
# "Vimtag CP3 PTZ camera", "Silicondust HDHomeRun set top box").
OS_NAME_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("camera", ("camera", "webcam", "ptz", "ipcam", "nvr", "dvr")),
    ("printer", ("printer", "laserjet", "officejet", "deskjet", "pixma")),
    ("tv", ("tvos", "roku", "webos", "tizen", "android tv", "fire os", "hdhomerun", "silicondust", "set top box", "smart tv", "apple tv")),
    ("console", ("playstation", "xbox", "nintendo")),
    ("nas", ("synology", "diskstation", "readynas", "qnap", "truenas", "freenas")),
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


# How much each kind of evidence counts. The strongest evidence decides; on a tie the one found first (above) wins.
W_VM = 100
W_STRONG_HINT = 95
W_NAME_WORD = 85
W_OS_CLASS = 75        # nmap's device class of the matched operating system ("printer", "webcam", ...)
W_OS_NAME_WORD = 75
W_VENDOR_SPECIFIC = 70  # a manufacturer that only makes one kind of device
W_VENDOR_ROUTER = 65
W_OS_CLASS_PHONE = 60   # many IoT devices run Android: a "phone" class is weak
W_PORT_CAMERA = 62
W_PORT_PRINTER = 60
W_PORT_NAS = 58
W_OS_FAMILY = 55
W_VENDOR_PHONE = 55
W_PORT_ROUTER = 55
W_OS_CLASS_VAGUE = 40   # "specialized", "pda"...
W_WEAK_HINT = 40
W_SERVER_PORT = 30


def classify_evidence(
    *,
    vendor: str | None = None,
    os_name: str | None = None,
    os_type: str | None = None,
    open_ports: Iterable[int] = (),
    services: Iterable[str] = (),
    hostnames: Iterable[str] = (),
    mac: str | None = None,
    hints: Iterable[str] = (),
) -> list[tuple[str, float, str]]:
    """Every clue about what the device is, as (type, weight, why), strongest first.

    Instead of "first rule that matches wins", the clues are weighed: a printer's name beats nmap's guess that it
    runs Android, a camera's OS name beats its open SSH port. All string matching is case-insensitive.
    """
    vendor_lower = vendor.lower() if vendor else ""
    os_name_lower = os_name.lower() if os_name else ""
    os_type_lower = os_type.lower() if os_type else ""
    mac_lower = mac.lower() if mac else ""
    ports = set(open_ports)
    hostnames_set = {h.lower() for h in hostnames if h}
    hint_set = {h.lower() for h in hints if h}
    found: list[tuple[str, float, str]] = []

    def add(device_type: str, weight: float, why: str) -> None:
        found.append((device_type, weight, why))

    # Virtual machines and containers: by MAC prefix or vendor name
    for prefix in VM_MAC_PREFIXES:
        if mac_lower.startswith(prefix):
            add("vm", W_VM, f"MAC prefix {prefix}")
            break
    for kw in VM_VENDOR_KEYWORDS:
        if kw in vendor_lower:
            add("vm", W_VM, f"vendor {kw}")
            break

    # Discovery hints that name the kind of device outright
    for token, device_type in STRONG_HINTS:
        if token in hint_set:
            add(device_type, W_STRONG_HINT, f"announces {token}")

    # Words in the device's name
    name_tokens = {t for h in hostnames_set for t in re.split(r"[^a-z0-9]+", h.split(".")[0]) if t}  # first label only: the domain says nothing
    for index, (device_type, words) in enumerate(HOSTNAME_TOKENS):
        word = next((w for t in sorted(name_tokens) for w in sorted(words) if _token_matches(t, w)), None)
        if word:
            add(device_type, W_NAME_WORD - index * 0.01, f"name contains {word}")

    # nmap's class of the matched OS, and product words in its name
    if os_type_lower:
        mapped = OS_TYPE_MAP.get(os_type_lower)
        if mapped:
            weight = W_OS_CLASS_PHONE if mapped == "phone" else W_OS_CLASS_VAGUE if os_type_lower in ("specialized", "power-device", "pda", "terminal") else W_OS_CLASS
            add(mapped, weight, f"nmap class {os_type_lower}")
    for device_type, words in OS_NAME_WORDS:
        word = next((w for w in words if w in os_name_lower), None)
        if word:
            add(device_type, W_OS_NAME_WORD, f"OS name says {word}")

    # Manufacturer
    if vendor_lower:
        for group, device_type in (
            (VENDOR_NAS_KEYWORDS, "nas"), (VENDOR_CAMERA_KEYWORDS, "camera"), (VENDOR_TV_KEYWORDS, "tv"), (VENDOR_SPEAKER_KEYWORDS, "speaker"),
            (VENDOR_CONSOLE_KEYWORDS, "console"), (VENDOR_APPLIANCE_KEYWORDS, "appliance"), (VENDOR_IOT_KEYWORDS, "iot"),
        ):
            kw = next((k for k in group if k in vendor_lower), None)
            if kw:
                add(device_type, W_VENDOR_SPECIFIC, f"vendor {kw}")
        kw = next((k for k in VENDOR_PRINTER_KEYWORDS if k in vendor_lower), None)
        if kw and ports & PRINTER_PORTS:
            add("printer", W_VENDOR_SPECIFIC, f"vendor {kw} with a printer port")
        kw = next((k for k in VENDOR_ROUTER_KEYWORDS if k in vendor_lower), None)
        if kw:
            tokens = {t for h in hostnames_set for t in re.split(r"[^a-z0-9]+", h) if t}
            if any(t in ("router", "gw", "gateway") for t in tokens) or 53 in ports:
                add("router", W_VENDOR_ROUTER, f"network vendor {kw}")
            elif "ap" in tokens or any(t in ("wifi", "wlan", "unifi") for t in tokens):
                add("ap", W_VENDOR_ROUTER, f"network vendor {kw}")
            elif any(t in ("sw", "switch") for t in tokens):
                add("switch", W_VENDOR_ROUTER, f"network vendor {kw}")
            else:
                add("router", W_VENDOR_ROUTER, f"network vendor {kw}")
        kw = next((k for k in VENDOR_PHONE_KEYWORDS if k in vendor_lower), None)
        if kw and not ports:
            add("phone", W_VENDOR_PHONE, f"vendor {kw}, nothing listening")

    # Open ports
    if ports & PRINTER_PORTS:
        add("printer", W_PORT_PRINTER, "printer port open")
    if ports & CAMERA_PORTS:
        add("camera", W_PORT_CAMERA, "video stream port open")
    if ports & NAS_PORTS or any("nas" in h for h in hostnames_set):
        add("nas", W_PORT_NAS, "file sharing port or nas in the name")
    if 53 in ports and 67 in ports:
        add("router", W_PORT_ROUTER, "DNS and DHCP ports open")

    # Operating system family
    if os_name_lower:
        if "windows" in os_name_lower:
            server = "server" in os_name_lower and bool(ports & WINDOWS_SERVER_PORTS)
            add("server" if server else "pc", W_OS_FAMILY, "Windows")
        elif "cisco" not in os_name_lower and re.search(r"\b(android|iphone|i?pad?os|ios)\b", os_name_lower):
            add("phone", W_OS_FAMILY - 3, "Android / iOS")
        elif "linux" in os_name_lower or "bsd" in os_name_lower:
            add("server" if ports & LINUX_SERVER_PORTS else "pc", W_SERVER_PORT + 15 if ports & LINUX_SERVER_PORTS else W_SERVER_PORT, "Linux / BSD")
        elif "mac os" in os_name_lower or "macos" in os_name_lower:
            add("pc", W_OS_FAMILY - 5, "macOS")

    # Weak discovery hints and general server ports
    for token, device_type in WEAK_HINTS:
        if token in hint_set:
            add(device_type, W_WEAK_HINT, f"announces {token}")
    if ports & SERVER_PORTS:
        add("server", W_SERVER_PORT, "web / ssh / database port open")

    return sorted(found, key=lambda e: -e[1])  # stable: on a tie the clue found first stays first


def classify_device(**kwargs) -> str:
    """The type of a device (one of DEVICE_TYPES): the strongest clue from classify_evidence(), or "unknown"."""
    evidence = classify_evidence(**kwargs)
    return evidence[0][0] if evidence else "unknown"
