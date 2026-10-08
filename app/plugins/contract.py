"""The plugin contract: what a plugin manifest and a plugin's output must look like.

A plugin only fetches data; Netlens matches it to devices, writes the links and shows them. Everything a plugin
returns is validated here, with messages that tell the plugin author exactly what is wrong.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

API_VERSION = 1
KINDS = ("hypervisor", "topology")
FIELD_TYPES = ("text", "password", "bool", "number", "select")
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]+)?$")
TOPOLOGY_ROLES = ("gateway", "switch", "ap", "node")
MEDIA = ("wired", "wifi", "unknown")
MAX_ITEMS = 5000
MAX_TIMEOUT = 600
DEFAULT_TIMEOUT = 60


class ContractError(ValueError):
    """The manifest or the output does not follow the contract."""


# ----------------------------------------------------------------------------- small helpers
def _fail(path: str, message: str):
    raise ContractError(f"{path}: {message}")


def _text(value: Any, path: str, *, required: bool = False, max_len: int = 200, default: str = "") -> str:
    if value is None:
        if required:
            _fail(path, "is required")
        return default
    if not isinstance(value, str):
        _fail(path, f"must be text, got {type(value).__name__}")
    value = value.strip()
    if required and not value:
        _fail(path, "must not be empty")
    if len(value) > max_len:
        _fail(path, f"is too long (max {max_len} characters)")
    return value


def _mac(value: Any, path: str, *, required: bool = False) -> str | None:
    if value in (None, ""):
        if required:
            _fail(path, "is required")
        return None
    if not isinstance(value, str) or not MAC_RE.match(value.strip()):
        _fail(path, f"is not a MAC address ({value!r}); use aa:bb:cc:dd:ee:ff")
    return value.strip().lower().replace("-", ":")


def _ipv4(value: Any, path: str) -> str | None:
    if value in (None, ""):
        return None
    try:
        addr = ipaddress.ip_address(str(value).split("/")[0].strip())
    except ValueError:
        _fail(path, f"is not an IP address ({value!r})")
    if addr.version != 4:
        _fail(path, f"must be an IPv4 address ({value!r})")
    return str(addr)


def _optional_number(value: Any, path: str, low: float, high: float, *, integer: bool = False):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(path, f"must be a number, got {value!r}")
    if not low <= value <= high:
        _fail(path, f"must be between {low} and {high}, got {value}")
    return int(value) if integer else float(value)


def _list(value: Any, path: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        _fail(path, f"must be a list, got {type(value).__name__}")
    if len(value) > MAX_ITEMS:
        _fail(path, f"has too many entries (max {MAX_ITEMS})")
    return value


def _dict(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        _fail(path, f"must be an object, got {type(value).__name__}")
    return value


def _id(value: Any, path: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        _fail(path, "is required (text or number)")
    text = str(value).strip()
    if not text:
        _fail(path, "must not be empty")
    if len(text) > 100:
        _fail(path, "is too long")
    return text


# ----------------------------------------------------------------------------- manifest
def validate_manifest(data: Any) -> dict:
    """Check plugin.json and return it in normalised form."""
    data = _dict(data, "plugin.json")
    plugin_id = _text(data.get("id"), "id", required=True, max_len=31)
    if not ID_RE.match(plugin_id):
        _fail("id", "must be 2-31 characters: lowercase letters, digits, '-' or '_', starting with a letter")
    api = data.get("api_version")
    if api != API_VERSION:
        _fail("api_version", f"must be {API_VERSION} (this Netlens supports plugin API version {API_VERSION}), got {api!r}")
    kind = data.get("kind")
    if kind not in KINDS:
        _fail("kind", f"must be one of {', '.join(KINDS)}, got {kind!r}")
    version = _text(data.get("version"), "version", required=True, max_len=40)
    if not VERSION_RE.match(version):
        _fail("version", f"must look like 1.0.0, got {version!r}")
    timeout = data.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 5 <= timeout <= MAX_TIMEOUT:
        _fail("timeout", f"must be a whole number of seconds between 5 and {MAX_TIMEOUT}")

    fields = []
    seen = set()
    for i, raw in enumerate(_list(data.get("config", []), "config")):
        path = f"config[{i}]"
        raw = _dict(raw, path)
        key = _text(raw.get("key"), f"{path}.key", required=True, max_len=32)
        if not KEY_RE.match(key):
            _fail(f"{path}.key", "must be lowercase letters, digits or '_', starting with a letter")
        if key in seen:
            _fail(f"{path}.key", f"{key!r} is used twice")
        seen.add(key)
        ftype = raw.get("type", "text")
        if ftype not in FIELD_TYPES:
            _fail(f"{path}.type", f"must be one of {', '.join(FIELD_TYPES)}, got {ftype!r}")
        field = {
            "key": key,
            "type": ftype,
            "label": _text(raw.get("label"), f"{path}.label", max_len=100, default=key),
            "help": _text(raw.get("help"), f"{path}.help", max_len=500),
            "placeholder": _text(raw.get("placeholder"), f"{path}.placeholder", max_len=100),
            "section": _text(raw.get("section"), f"{path}.section", max_len=100),
            "required": bool(raw.get("required", False)),
            "secret": ftype == "password",
        }
        default = raw.get("default")
        if ftype == "bool":
            if default is not None and not isinstance(default, bool):
                _fail(f"{path}.default", "must be true or false")
            field["default"] = bool(default) if default is not None else False
        elif ftype == "number":
            if default is not None and (isinstance(default, bool) or not isinstance(default, (int, float))):
                _fail(f"{path}.default", "must be a number")
            field["default"] = default
            for bound in ("min", "max"):
                if raw.get(bound) is not None:
                    if isinstance(raw[bound], bool) or not isinstance(raw[bound], (int, float)):
                        _fail(f"{path}.{bound}", "must be a number")
                    field[bound] = raw[bound]
        elif ftype == "select":
            options = []
            for j, opt in enumerate(_list(raw.get("options"), f"{path}.options")):
                if isinstance(opt, str):
                    opt = {"value": opt, "label": opt}
                opt = _dict(opt, f"{path}.options[{j}]")
                value = _text(opt.get("value"), f"{path}.options[{j}].value", required=True)
                options.append({"value": value, "label": _text(opt.get("label"), f"{path}.options[{j}].label", default=value)})
            if not options:
                _fail(f"{path}.options", "a select needs at least one option")
            field["options"] = options
            field["default"] = _text(default, f"{path}.default", default=options[0]["value"])
            if field["default"] not in [o["value"] for o in options]:
                _fail(f"{path}.default", "is not one of the options")
        else:
            field["default"] = _text(default, f"{path}.default", max_len=500) if ftype == "text" else ""
        fields.append(field)

    return {
        "id": plugin_id,
        "name": _text(data.get("name"), "name", required=True, max_len=60),
        "version": version,
        "api_version": API_VERSION,
        "kind": kind,
        "description": _text(data.get("description"), "description", max_len=500),
        "author": _text(data.get("author"), "author", max_len=100),
        "homepage": _text(data.get("homepage"), "homepage", max_len=200),
        "timeout": timeout,
        "config": fields,
    }


def default_config(manifest: dict) -> dict:
    return {f["key"]: f["default"] for f in manifest["config"]}


def clean_config(manifest: dict, values: dict) -> dict:
    """Keep only the manifest's fields, coerced to their types (unknown keys are dropped)."""
    out = {}
    for f in manifest["config"]:
        key = f["key"]
        value = values.get(key, f["default"])
        if f["type"] == "bool":
            value = bool(value)
        elif f["type"] == "number":
            if value in (None, ""):
                value = f["default"]
            elif isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ContractError(f"{f['label']}: must be a number")
            if value is not None:
                if "min" in f and value < f["min"]:
                    raise ContractError(f"{f['label']}: must be at least {f['min']}")
                if "max" in f and value > f["max"]:
                    raise ContractError(f"{f['label']}: must be at most {f['max']}")
        elif f["type"] == "select":
            if value not in [o["value"] for o in f["options"]]:
                raise ContractError(f"{f['label']}: pick one of the listed options")
        else:
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise ContractError(f"{f['label']}: must be text")
            value = value.strip()
            if len(value) > 1000:
                raise ContractError(f"{f['label']}: is too long")
        out[key] = value
    return out


def missing_required(manifest: dict, config: dict) -> list[str]:
    return [f["label"] for f in manifest["config"] if f["required"] and f["type"] != "bool" and config.get(f["key"]) in (None, "")]


# ----------------------------------------------------------------------------- outputs
def validate_output(kind: str, data: Any) -> dict:
    if kind == "hypervisor":
        return _hypervisor(data)
    if kind == "topology":
        return _topology(data)
    raise ContractError(f"unknown plugin kind {kind!r}")


def _hypervisor(data: Any) -> dict:
    data = _dict(data, "output")
    hosts, host_ids = [], set()
    for i, raw in enumerate(_list(data.get("hosts"), "hosts")):
        path = f"hosts[{i}]"
        raw = _dict(raw, path)
        host_id = _id(raw.get("id"), f"{path}.id")
        if host_id in host_ids:
            _fail(f"{path}.id", f"{host_id!r} is used twice")
        host_ids.add(host_id)
        hosts.append({
            "id": host_id,
            "name": _text(raw.get("name"), f"{path}.name", default=host_id),
            "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
            "mac": _mac(raw.get("mac"), f"{path}.mac"),
            "online": bool(raw.get("online", True)),
        })
    guests, guest_ids = [], set()
    for i, raw in enumerate(_list(data.get("guests"), "guests")):
        path = f"guests[{i}]"
        raw = _dict(raw, path)
        guest_id = _id(raw.get("id"), f"{path}.id")
        if guest_id in guest_ids:
            _fail(f"{path}.id", f"{guest_id!r} is used twice")
        guest_ids.add(guest_id)
        host_id = raw.get("host_id")
        host_id = _id(host_id, f"{path}.host_id") if host_id not in (None, "") else None
        if host_id is not None and host_id not in host_ids:
            _fail(f"{path}.host_id", f"{host_id!r} is not the id of any entry in hosts")
        guests.append({
            "id": guest_id,
            "name": _text(raw.get("name"), f"{path}.name", default=guest_id),
            "kind": _text(raw.get("kind"), f"{path}.kind", max_len=30, default="vm"),
            "host_id": host_id,
            "status": _text(raw.get("status"), f"{path}.status", max_len=30, default="unknown"),
            "macs": [_mac(m, f"{path}.macs[{j}]", required=True) for j, m in enumerate(_list(raw.get("macs"), f"{path}.macs"))],
            "ips": [_ipv4(a, f"{path}.ips[{j}]") for j, a in enumerate(_list(raw.get("ips"), f"{path}.ips"))],
        })
    return {"hosts": hosts, "guests": guests}


def _topology(data: Any) -> dict:
    data = _dict(data, "output")
    nodes, node_macs = [], set()
    for i, raw in enumerate(_list(data.get("nodes"), "nodes")):
        path = f"nodes[{i}]"
        raw = _dict(raw, path)
        mac = _mac(raw.get("mac"), f"{path}.mac", required=True)
        if mac in node_macs:
            _fail(f"{path}.mac", f"{mac} is used twice")
        node_macs.add(mac)
        role = raw.get("role", "node")
        if role not in TOPOLOGY_ROLES:
            _fail(f"{path}.role", f"must be one of {', '.join(TOPOLOGY_ROLES)}, got {role!r}")
        extra = [_mac(m, f"{path}.macs[{j}]", required=True) for j, m in enumerate(_list(raw.get("macs"), f"{path}.macs"))]
        nodes.append({
            "mac": mac,
            "macs": sorted({mac, *extra}),
            "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
            "name": _text(raw.get("name"), f"{path}.name", default=mac),
            "model": _text(raw.get("model"), f"{path}.model", max_len=100),
            "role": role,
            "parent_mac": _mac(raw.get("parent_mac"), f"{path}.parent_mac"),
        })
    known = {m for n in nodes for m in n["macs"]}
    for i, n in enumerate(nodes):
        if n["parent_mac"] is not None and n["parent_mac"] not in known:
            _fail(f"nodes[{i}].parent_mac", f"{n['parent_mac']} is not the MAC of any entry in nodes")
    if sum(1 for n in nodes if n["role"] == "gateway") > 1:
        _fail("nodes", "at most one node can have the role 'gateway'")
    clients = []
    for i, raw in enumerate(_list(data.get("clients"), "clients")):
        path = f"clients[{i}]"
        raw = _dict(raw, path)
        node_mac = _mac(raw.get("node_mac"), f"{path}.node_mac")
        if node_mac is not None and node_mac not in known:
            _fail(f"{path}.node_mac", f"{node_mac} is not the MAC of any entry in nodes")
        medium = raw.get("medium", "unknown")
        if medium not in MEDIA:
            _fail(f"{path}.medium", f"must be one of {', '.join(MEDIA)}, got {medium!r}")
        clients.append({
            "mac": _mac(raw.get("mac"), f"{path}.mac", required=True),
            "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
            "name": _text(raw.get("name"), f"{path}.name") or None,
            "node_mac": node_mac,
            "medium": medium,
            "band": _text(raw.get("band"), f"{path}.band", max_len=20) or None,
            "rssi": _optional_number(raw.get("rssi"), f"{path}.rssi", -127, 0, integer=True),
            "tx_mbps": _optional_number(raw.get("tx_mbps"), f"{path}.tx_mbps", 0, 100000),
            "rx_mbps": _optional_number(raw.get("rx_mbps"), f"{path}.rx_mbps", 0, 100000),
        })
    return {"nodes": nodes, "clients": clients}
