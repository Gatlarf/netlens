import re
import json
from dataclasses import dataclass, asdict, fields, replace
from typing import Any

PRESETS: dict[str, dict] = {
    "default": {},
    "fast": {"timing": 4, "deep_top_ports": 200, "deep_version": "light"},
    "fastest": {"timing": 4, "quick_top_ports": 50, "deep_top_ports": 100, "deep_version": "off", "deep_os": False, "skip_dns": True, "host_timeout": 120},
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
    skip_dns: bool = False
    host_timeout: int = 0


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


def options_from_dict(data: dict, base: ScanOptions | None = None) -> ScanOptions:
    opts = base if base is not None else ScanOptions()
    field_names = {f.name for f in fields(opts)}
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
        elif key == "skip_dns":
            if not isinstance(value, bool):
                raise ValueError(f"{key}: must be true or false")
            opts = replace(opts, skip_dns=value)
        elif key == "host_timeout":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{key}: must be 0 or between 10 and 86400")
            if value != 0 and not (10 <= value <= 86400):
                raise ValueError(f"{key}: must be 0 or between 10 and 86400")
            opts = replace(opts, host_timeout=value)
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


def option_args(kind: str, opts: ScanOptions) -> list[str]:
    if kind not in ("quick", "deep"):
        raise ValueError(f"unknown kind: {kind}")
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
        if opts.host_timeout > 0:
            args.extend(["--host-timeout", f"{opts.host_timeout}s"])
    else:
        if opts.deep_version == "full":
            args.append("-sV")
        elif opts.deep_version == "light":
            args.extend(["-sV", "--version-light"])
        if opts.deep_os:
            args.extend(["-O", "--osscan-guess"])
        if opts.deep_traceroute:
            args.append("--traceroute")
        if opts.deep_ports:
            args.extend(["-p", opts.deep_ports])
        else:
            args.extend(["--top-ports", str(opts.deep_top_ports)])
        if opts.skip_dns:
            args.append("-n")
        if opts.host_timeout > 0:
            args.extend(["--host-timeout", f"{opts.host_timeout}s"])
    return args


def command_preview(kind: str, opts: ScanOptions) -> str:
    return "nmap " + " ".join(option_args(kind, opts)) + " -oX - <ranges>"