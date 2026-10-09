import re
import json
from dataclasses import dataclass, asdict, fields, replace
from typing import Any

PRESETS: dict[str, dict] = {
    "default": {},
    "fast": {"timing": 4, "deep_top_ports": 200, "deep_version": "light", "quick_host_timeout": 60, "deep_host_timeout": 600},
    "fastest": {"timing": 4, "quick_top_ports": 50, "deep_top_ports": 100, "deep_version": "off", "deep_os": False, "skip_dns": True, "quick_host_timeout": 60, "deep_host_timeout": 120},
}


@dataclass
class ScanOptions:
    timing: int = 3
    quick_mode: str = "ports"
    quick_top_ports: int = 100
    quick_ports: str = ""
    deep_top_ports: int = 1000
    deep_ports: str = ""
    deep_version: str = "full"
    deep_os: bool = True
    deep_traceroute: bool = True
    deep_scripts: bool = False      # extra nmap scripts that read names/OS/products from web pages, certificates, SMB, NetBIOS, UPnP
    skip_dns: bool = False
    quick_host_timeout: int = 120   # seconds nmap may spend on one host in a quick scan; 0 = no limit
    deep_host_timeout: int = 900    # same for a deep scan (stops one slow host from holding the scan for an hour)


def normalize_ports(spec: str) -> str:
    if not spec:
        return ""
    items = [item.strip() for item in spec.split(",")]
    if any(item == "" for item in items):
        raise ValueError("empty item in port list")
    cleaned: list[str] = []
    for item in items:
        if not re.fullmatch(r"\d+|\d+-\d+", item):
            raise ValueError(f"'{item}' is not a valid port or range")
        if "-" in item:
            a_str, b_str = item.split("-")
            a = int(a_str)
            b = int(b_str)
            if not (1 <= a <= 65535):
                raise ValueError(f"port out of range (1-65535): {a}")
            if not (1 <= b <= 65535):
                raise ValueError(f"port out of range (1-65535): {b}")
            if a > b:
                raise ValueError(f"range start is after its end: {item}")
            cleaned.append(f"{a}-{b}")
        else:
            p = int(item)
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range (1-65535): {p}")
            cleaned.append(str(p))
    result = ",".join(cleaned)
    if len(result) > 200:
        raise ValueError("port list is too long")
    return result


def _check_host_timeout(key: str, value) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key}: must be 0 or between 10 and 86400")
    if value != 0 and not (10 <= value <= 86400):
        raise ValueError(f"{key}: must be 0 or between 10 and 86400")
    return value


def options_from_dict(data: dict, base: ScanOptions | None = None) -> ScanOptions:
    opts = base if base is not None else ScanOptions()
    field_names = {f.name for f in fields(opts)}
    data = dict(data)
    if "host_timeout" in data:  # older settings had one timeout for both kinds of scan
        legacy = data.pop("host_timeout")
        data.setdefault("quick_host_timeout", legacy)
        data.setdefault("deep_host_timeout", legacy)
    for key, value in data.items():
        if key not in field_names:
            raise ValueError(f"unknown setting: {key}")
        if key == "timing":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{key}: must be a whole number between 2 and 5")
            if not (2 <= value <= 5):
                raise ValueError(f"{key}: must be a whole number between 2 and 5")
            opts = replace(opts, timing=value)
        elif key == "quick_mode":
            if not isinstance(value, str):
                raise ValueError(f"{key}: must be one of: ports, discovery")
            if value not in ("ports", "discovery"):
                raise ValueError(f"{key}: must be one of: ports, discovery")
            opts = replace(opts, quick_mode=value)
        elif key == "quick_top_ports":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{key}: must be a whole number between 1 and 10000")
            if not (1 <= value <= 10000):
                raise ValueError(f"{key}: must be a whole number between 1 and 10000")
            opts = replace(opts, quick_top_ports=value)
        elif key == "quick_ports":
            if not isinstance(value, str):
                raise ValueError(f"{key}: must be a string")
            try:
                cleaned = normalize_ports(value)
            except ValueError as e:
                raise ValueError(f"{key}: {e}")
            opts = replace(opts, quick_ports=cleaned)
        elif key == "deep_top_ports":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{key}: must be a whole number between 1 and 10000")
            if not (1 <= value <= 10000):
                raise ValueError(f"{key}: must be a whole number between 1 and 10000")
            opts = replace(opts, deep_top_ports=value)
        elif key == "deep_ports":
            if not isinstance(value, str):
                raise ValueError(f"{key}: must be a string")
            try:
                cleaned = normalize_ports(value)
            except ValueError as e:
                raise ValueError(f"{key}: {e}")
            opts = replace(opts, deep_ports=cleaned)
        elif key == "deep_version":
            if not isinstance(value, str):
                raise ValueError(f"{key}: must be one of: full, light, off")
            if value not in ("full", "light", "off"):
                raise ValueError(f"{key}: must be one of: full, light, off")
            opts = replace(opts, deep_version=value)
        elif key == "deep_os":
            if not isinstance(value, bool):
                raise ValueError(f"{key}: must be true or false")
            opts = replace(opts, deep_os=value)
        elif key == "deep_traceroute":
            if not isinstance(value, bool):
                raise ValueError(f"{key}: must be true or false")
            opts = replace(opts, deep_traceroute=value)
        elif key == "deep_scripts":
            if not isinstance(value, bool):
                raise ValueError(f"{key}: must be true or false")
            opts = replace(opts, deep_scripts=value)
        elif key == "skip_dns":
            if not isinstance(value, bool):
                raise ValueError(f"{key}: must be true or false")
            opts = replace(opts, skip_dns=value)
        elif key in ("quick_host_timeout", "deep_host_timeout"):
            opts = replace(opts, **{key: _check_host_timeout(key, value)})
    return opts


def options_to_dict(opts: ScanOptions) -> dict:
    return asdict(opts)


def options_from_json(text: str | None) -> ScanOptions:
    if text is None:
        return ScanOptions()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ScanOptions()
    if not isinstance(data, dict):
        return ScanOptions()
    try:
        return options_from_dict(data)
    except ValueError:
        return ScanOptions()


def preset_dict(name: str) -> dict:
    return options_to_dict(options_from_dict(PRESETS[name]))


# Read-only scripts from nmap's "safe" category that tell what a device is (see app/scanner/nse.py for how the output is used)
IDENTIFY_SCRIPTS = "http-title,ssl-cert,nbstat,smb-os-discovery,upnp-info,banner"

FULL_SCAN_HOST_TIMEOUT = 1800  # seconds: a full scan of one host may take a while, but not forever


def option_args(kind: str, opts: ScanOptions) -> list[str]:
    if kind not in ("quick", "deep", "full", "gentle"):
        raise ValueError(f"unknown kind: {kind}")
    if kind == "gentle":
        # Devices marked "gentle" (a TV asks its owner for permission when something connects to its remote-control port):
        # only find out which ports are open. No service detection, scripts, OS detection or traceroute.
        args = [f"-T{opts.timing}"]
        if opts.deep_ports:
            args.extend(["-p", opts.deep_ports])
        else:
            args.extend(["--top-ports", str(opts.deep_top_ports)])
        if opts.skip_dns:
            args.append("-n")
        if opts.deep_host_timeout > 0:
            args.extend(["--host-timeout", f"{opts.deep_host_timeout}s"])
        return args
    if kind == "full":
        # Everything about ONE host: all 65535 TCP ports, service versions, OS and the route to it.
        # Aggressive timing is fine for a single host; the reverse-DNS preference is respected.
        args = [f"-T{max(4, opts.timing)}", "-p-", "-sV", "-O", "--osscan-guess", "--traceroute"]
        if opts.deep_scripts:
            args.extend(["--script", IDENTIFY_SCRIPTS, "--script-timeout", "15s"])
        if opts.skip_dns:
            args.append("-n")
        args.extend(["--host-timeout", f"{FULL_SCAN_HOST_TIMEOUT}s"])
        return args
    args: list[str] = []
    args.append(f"-T{opts.timing}")
    if kind == "quick":
        if opts.quick_mode == "discovery":
            args.append("-sn")
        else:
            if opts.quick_ports:
                args.extend(["-p", opts.quick_ports])
            else:
                args.extend(["--top-ports", str(opts.quick_top_ports)])
        if opts.skip_dns:
            args.append("-n")
        if opts.quick_host_timeout > 0:
            args.extend(["--host-timeout", f"{opts.quick_host_timeout}s"])
    else:
        if opts.deep_version == "full":
            args.append("-sV")
        elif opts.deep_version == "light":
            args.extend(["-sV", "--version-light"])
        if opts.deep_os:
            args.extend(["-O", "--osscan-guess"])
        if opts.deep_traceroute:
            args.append("--traceroute")
        if opts.deep_scripts:
            args.extend(["--script", IDENTIFY_SCRIPTS, "--script-timeout", "15s"])
        if opts.deep_ports:
            args.extend(["-p", opts.deep_ports])
        else:
            args.extend(["--top-ports", str(opts.deep_top_ports)])
        if opts.skip_dns:
            args.append("-n")
        if opts.deep_host_timeout > 0:
            args.extend(["--host-timeout", f"{opts.deep_host_timeout}s"])
    return args


def command_preview(kind: str, opts: ScanOptions) -> str:
    target = "<host>" if kind == "full" else "<ranges>"
    return "nmap " + " ".join(option_args(kind, opts)) + f" -oX - {target}"