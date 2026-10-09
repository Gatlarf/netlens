"""Operating system hints from what a device says when it asks for an address (DHCP), and from router-reported text."""

from __future__ import annotations

import re

# DHCP option 60 (vendor class identifier): many stacks announce themselves
_CLASS_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"^MSFT 5\.0", re.I), "Windows"),
    (re.compile(r"^android-dhcp-(\d+(\.\d+)?)", re.I), "Android"),
    (re.compile(r"^dhcpcd[-\d. ]*.*linux", re.I), "Linux"),
    (re.compile(r"^udhcp", re.I), "Linux (BusyBox)"),
    (re.compile(r"^(ubuntu|debian|fedora|centos|raspbian|arch)", re.I), "Linux"),
)

# DHCP option 55 (parameter request list): the order in which a stack asks for things is quite telling.
# (prefix of the list, the OS it points to); the first match wins.
_PARAM_RULES: tuple[tuple[tuple[int, ...], str], ...] = (
    ((1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252), "Windows"),     # Windows 8 - 11
    ((1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43), "Windows"),               # Windows Vista / 7
    ((1, 3, 6, 15, 26, 28, 51, 58, 59, 43), "Android"),                         # Android 8+
    ((1, 3, 6, 15, 26, 28, 51, 58, 59), "Android"),
    ((1, 33, 3, 6, 15, 28, 51, 58, 119), "Android"),                            # Android 5 - 7
    ((1, 121, 3, 6, 15, 119, 252), "Apple device"),                             # iOS / macOS
    ((1, 3, 6, 15, 119, 78, 79, 95, 252), "Apple device"),
    ((1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42), "Linux"),              # ISC dhclient
    ((1, 3, 6, 12, 15, 26, 28, 42, 119, 121), "Linux"),                         # systemd-networkd / NetworkManager
)


def os_from_dhcp_class(text: str | None) -> str | None:
    """"MSFT 5.0" -> "Windows", "android-dhcp-13" -> "Android 13", ...; None when the text says nothing about the OS."""
    value = (text or "").strip()
    for pattern, name in _CLASS_RULES:
        match = pattern.match(value)
        if match:
            if name == "Android" and match.group(1):
                return f"Android {match.group(1)}"
            return name
    return None


def os_from_dhcp_params(params: list[int] | tuple[int, ...]) -> str | None:
    """The OS a DHCP parameter request list points to, or None."""
    sequence = tuple(params)
    for signature, name in _PARAM_RULES:
        if sequence[: len(signature)] == signature:
            return name
    return None
