
TASK: write app/scanner/options.py (full file, under 190 lines). Imports allowed: re, json, dataclasses (dataclass, asdict, fields, replace).

Scan options that decide the nmap command line. The DEFAULTS must reproduce today's behavior exactly.

@dataclass
class ScanOptions:   # all fields have defaults
    timing: int = 3                 # nmap -T template, allowed 2..5
    quick_mode: str = "ports"       # "ports" or "discovery" (discovery = host discovery only, nmap -sn)
    quick_top_ports: int = 100      # allowed 1..10000
    quick_ports: str = ""           # custom port spec; when non-empty it replaces quick_top_ports
    deep_top_ports: int = 1000      # allowed 1..10000
    deep_ports: str = ""            # custom port spec; replaces deep_top_ports when non-empty
    deep_version: str = "full"      # "full" (-sV), "light" (-sV --version-light) or "off"
    deep_os: bool = True            # OS detection
    deep_traceroute: bool = True
    skip_dns: bool = False          # nmap -n (no reverse DNS)
    host_timeout: int = 0           # seconds; 0 = no limit, otherwise allowed 10..86400

PRESETS: dict[str, dict] = {
    "default": {},
    "fast": {"timing": 4, "deep_top_ports": 200, "deep_version": "light"},
    "fastest": {"timing": 4, "quick_top_ports": 50, "deep_top_ports": 100, "deep_version": "off", "deep_os": False, "skip_dns": True, "host_timeout": 120},
}

def normalize_ports(spec: str) -> str
  - Validates an nmap port specification made of comma separated items, each a single port or a range "a-b" with 1 <= a <= b <= 65535 (ports are decimal integers). Whitespace around items is stripped; empty string returns "". Returns the cleaned spec joined by "," without spaces. Raise ValueError with a readable message: "empty item in port list", "'x' is not a valid port or range", "port out of range (1-65535): 70000", "range start is after its end: 90-80". Maximum length of the cleaned spec is 200 characters (ValueError("port list is too long")). Only digits, commas, hyphens and whitespace are accepted (anything else -> the "is not a valid port or range" error naming the item).

def options_from_dict(data: dict, base: ScanOptions | None = None) -> ScanOptions
  - Start from `base` (default: ScanOptions()) and apply every key present in `data`; return a NEW ScanOptions. Unknown key -> ValueError(f"unknown setting: {key}"). Type/range problems -> ValueError(f"{key}: {reason}") with reasons like "must be one of: ports, discovery", "must be a whole number between 2 and 5", "must be true or false". bool is not accepted where an int is expected and ints are not accepted where a bool is expected. quick_ports/deep_ports go through normalize_ports (their errors are prefixed with the key the same way). host_timeout must be 0 or between 10 and 86400. Strings for enumerations must match exactly.

def options_to_dict(opts: ScanOptions) -> dict   # asdict

def options_from_json(text: str | None) -> ScanOptions
  - Tolerant loader for the database: None, empty, invalid JSON, a non-dict, or ANY validation error -> ScanOptions() (the defaults). Never raises.

def preset_dict(name: str) -> dict   # full options dict for a preset: options_to_dict(options_from_dict(PRESETS[name])); KeyError for an unknown name

def option_args(kind: str, opts: ScanOptions) -> list[str]
  - The nmap arguments (WITHOUT targets and WITHOUT "-oX -") for kind "quick" or "deep" (ValueError for other kinds). Exact order:
    quick: ["-T<timing>"], then if quick_mode == "discovery": ["-sn"]; else ports: ["-p", quick_ports] when quick_ports is non-empty else ["--top-ports", str(quick_top_ports)]; then ["-n"] if skip_dns; then ["--host-timeout", f"{host_timeout}s"] if host_timeout > 0.
    deep: ["-T<timing>"], then version: "full" -> ["-sV"], "light" -> ["-sV", "--version-light"], "off" -> nothing; then if deep_os: ["-O", "--osscan-guess"]; then if deep_traceroute: ["--traceroute"]; then ports: ["-p", deep_ports] when non-empty else ["--top-ports", str(deep_top_ports)]; then ["-n"] if skip_dns; then ["--host-timeout", f"{host_timeout}s"] if host_timeout > 0.
  - With default options: quick -> ["-T3", "--top-ports", "100"]; deep -> ["-T3", "-sV", "-O", "--osscan-guess", "--traceroute", "--top-ports", "1000"].

def command_preview(kind: str, opts: ScanOptions) -> str
  - "nmap " + " ".join(option_args(kind, opts)) + " -oX - <ranges>"
