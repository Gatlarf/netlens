"""Who made a device, from its MAC address.

Sources, in this order: the vendor nmap printed, the IEEE registry (a compact copy ships with Netlens and is refreshed from the IEEE
website now and then), and a table of the MAC prefixes of virtual machines and containers. Addresses with the "locally administered"
bit set are not assigned to a manufacturer at all: phones use them as private Wi-Fi addresses, hypervisors for their guests.
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import re
import threading
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

BUNDLED = Path(__file__).resolve().parent.parent / "data" / "oui.tsv.gz"
OVERRIDE_NAME = "oui.tsv.gz"  # in the data directory: a newer copy downloaded from IEEE wins over the bundled one
SOURCES = (
    "https://standards-oui.ieee.org/oui/oui.csv",     # MA-L, 24-bit prefixes
    "https://standards-oui.ieee.org/oui28/mam.csv",   # MA-M, 28-bit
    "https://standards-oui.ieee.org/oui36/oui36.csv", # MA-S, 36-bit
)
MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)

# Prefixes of virtual machines and containers (checked before the locally administered bit, because several are locally administered).
VIRTUAL_PREFIXES: dict[str, str] = {
    "52:54:00": "QEMU/KVM (virtual)",
    "bc:24:11": "Proxmox (virtual)",
    "00:16:3e": "Xen / LXD (virtual)",
    "10:66:6a": "Incus (virtual)",
    "02:42": "Docker (virtual)",
    "00:50:56": "VMware (virtual)",
    "00:0c:29": "VMware (virtual)",
    "00:05:69": "VMware (virtual)",
    "08:00:27": "VirtualBox (virtual)",
    "00:15:5d": "Microsoft Hyper-V (virtual)",
    "00:1c:42": "Parallels (virtual)",
}

_lock = threading.Lock()
_table: dict[str, str] | None = None
_data_dir: Path | None = None


def configure(data_dir: str | os.PathLike | None) -> None:
    """Tell the module where a refreshed copy of the registry lives (the data directory) and reload."""
    global _data_dir, _table
    with _lock:
        _data_dir = Path(data_dir) if data_dir else None
        _table = None


def _read(path: Path) -> dict[str, str]:
    table: dict[str, str] = {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            prefix, _, name = line.rstrip("\n").partition("\t")
            if prefix and name:
                table[prefix] = name
    return table


def _load() -> dict[str, str]:
    global _table
    with _lock:
        if _table is None:
            candidates = ([_data_dir / OVERRIDE_NAME] if _data_dir else []) + [BUNDLED]
            for path in candidates:
                try:
                    _table = _read(path)
                    break
                except (OSError, EOFError, ValueError):
                    log.warning("could not read the vendor table %s", path)
            else:
                _table = {}
        return _table


def normalize(mac: str | None) -> str | None:
    if not mac or not MAC_RE.match(mac.strip()):
        return None
    return mac.strip().lower().replace("-", ":")


def virtual_vendor(mac: str | None) -> str | None:
    mac = normalize(mac)
    if mac:
        for prefix, label in VIRTUAL_PREFIXES.items():
            if mac.startswith(prefix + ":") or mac == prefix:
                return label
    return None


def mac_kind(mac: str | None) -> str | None:
    """"virtual" (a known hypervisor / container prefix), "randomized" (locally administered, so no manufacturer) or "universal"."""
    mac = normalize(mac)
    if mac is None:
        return None
    if virtual_vendor(mac):
        return "virtual"
    return "randomized" if int(mac[1], 16) & 0x2 else "universal"


def lookup(mac: str | None) -> str | None:
    """The manufacturer in the IEEE registry (the longest matching prefix: 36, 28 or 24 bits), or None."""
    mac = normalize(mac)
    if mac is None or int(mac[1], 16) & 0x2:  # a locally administered address was not assigned to anybody
        return None
    digits = mac.replace(":", "").upper()
    table = _load()
    for length in (9, 7, 6):
        name = table.get(digits[:length])
        if name:
            return name
    return None


def resolve(mac: str | None, scanned: str | None = None) -> str | None:
    """The vendor to store: what nmap found, else the IEEE registry, else the label of a virtual machine prefix."""
    return scanned or lookup(mac) or virtual_vendor(mac)


def info() -> dict:
    table = _load()
    source = "bundled copy"
    if _data_dir and (_data_dir / OVERRIDE_NAME).exists():
        source = "downloaded " + __import__("datetime").datetime.fromtimestamp((_data_dir / OVERRIDE_NAME).stat().st_mtime).strftime("%Y-%m-%d")
    return {"entries": len(table), "source": source}


def refresh(data_dir: str | os.PathLike, getter=None, minimum: int = 30000) -> int:
    """Download the registry from IEEE and keep a compact copy in the data directory. Returns the number of entries; raises OSError/ValueError."""
    import csv

    getter = getter or _http_get
    rows: dict[str, str] = {}
    for url in SOURCES:
        text = getter(url).decode("utf-8", "replace")
        if not text.lstrip().lower().startswith("registry"):
            raise ValueError("unexpected answer from the IEEE website")
        for r in csv.reader(io.StringIO(text, newline="")):
            if len(r) >= 3 and r[0] != "Registry" and r[1].strip() and r[2].strip():
                rows[r[1].strip().upper()] = " ".join(r[2].split())
    if len(rows) < minimum:
        raise ValueError(f"the registry looks incomplete ({len(rows)} entries)")
    target = Path(data_dir) / OVERRIDE_NAME
    temp = target.with_suffix(".tmp")
    with gzip.open(temp, "wb", compresslevel=9) as out:
        out.write("".join(f"{k}\t{v}\n" for k, v in sorted(rows.items())).encode("utf-8"))
    os.replace(temp, target)
    configure(data_dir)
    return len(rows)


def _http_get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "Netlens"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(20_000_000)
