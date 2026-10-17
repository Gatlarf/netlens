"""Display categories of plugins: how the plugin lists (Plugin store, Plugins, the Settings menu) are grouped.

A category is only for showing; the plugin's *kind* (hypervisor, topology, dns, proxy) is the technical contract. An entry of the plugin index may
name its category; without one (or with an unknown one) it falls back to the default of its kind.
"""

from __future__ import annotations

CATEGORIES = [   # (id, label, short label for the narrow Settings menu)
    ("virtualization", "Virtualization & containers", "Virtualization"),
    ("network", "Network devices", "Network devices"),
    ("dns", "DNS", "DNS"),
    ("backup", "Backups", "Backups"),
    ("proxy", "Reverse proxies", "Reverse proxies"),
    ("smarthome", "Smart home", "Smart home"),
    ("storage", "Storage & NAS", "Storage & NAS"),
    ("documentation", "Documentation", "Documentation"),
]
IDS = tuple(c for c, _, _ in CATEGORIES)
KIND_DEFAULT = {"hypervisor": "virtualization", "topology": "network", "dns": "dns", "proxy": "proxy", "backup": "backup", "inventory": "smarthome"}


def category_of(kind: str | None, named: object = None) -> str:
    """The category to show: the one the index entry names if it is known, else the default of the kind."""
    if isinstance(named, str) and named in IDS:
        return named
    return KIND_DEFAULT.get(kind or "", "network")


def listing() -> list[dict]:
    return [{"id": c, "label": label, "short": short} for c, label, short in CATEGORIES]
