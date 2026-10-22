"""The plugin contract: what a plugin manifest and a plugin's output must look like.

A plugin only fetches data; Netlens matches it to devices, writes the links and shows them. Everything a plugin
returns is validated here, with messages that tell the plugin author exactly what is wrong.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

API_VERSION = 1
KINDS = ("hypervisor", "topology", "dns", "proxy", "backup", "inventory", "vulnerability")
DNS_CAPABILITIES = ("marker", "delete")   # what a DNS plugin can do besides adding and updating records
DNS_TYPES = ("A", "AAAA", "PTR", "CNAME")
MAX_DNS_RECORDS = 50000
FIELD_TYPES = ("text", "password", "bool", "number", "select", "servers")
MAX_SERVERS = 20
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


POWER_ACTIONS = ("reset", "reboot", "shutdown", "start")


def _power(value: Any, kind: str) -> list[str]:
    """A hypervisor plugin that has power(config, {"guest": ..., "action": ...}) lists what it can do to a guest: `reset` (the hard
    reset button), `reboot` (a clean restart), `shutdown` (a clean power off) and `start`."""
    if value is None:
        return []
    if kind != "hypervisor":
        _fail("power", "only a hypervisor plugin has power actions")
    items = _list(value, "power")
    for item in items:
        if item not in POWER_ACTIONS:
            _fail("power", f"{item!r} is not one of {', '.join(POWER_ACTIONS)}")
    return [a for a in POWER_ACTIONS if a in items]


def _capabilities(value: Any, kind: str) -> list[str]:
    """DNS plugins say what the server can do: `marker` (a comment on each record, so Netlens can tell its own records
    from others) and `delete` (it can remove records)."""
    if value is None:
        return []
    if kind != "dns":
        _fail("capabilities", "only a dns plugin has capabilities")
    items = _list(value, "capabilities")
    for item in items:
        if item not in DNS_CAPABILITIES:
            _fail("capabilities", f"{item!r} is not one of {', '.join(DNS_CAPABILITIES)}")
    return sorted(set(items))


# ----------------------------------------------------------------------------- server lists
def _server_columns(value: Any, path: str) -> list[dict]:
    """The columns of a `servers` field: each row is one server. The first column is the address (`host`)."""
    columns, seen = [], set()
    for j, raw in enumerate(_list(value, f"{path}.columns")):
        cpath = f"{path}.columns[{j}]"
        raw = _dict(raw, cpath)
        key = _text(raw.get("key"), f"{cpath}.key", required=True, max_len=32)
        if not KEY_RE.match(key) or key == "id":
            _fail(f"{cpath}.key", "must be lowercase letters, digits or '_', starting with a letter (and not 'id')")
        if key in seen:
            _fail(f"{cpath}.key", f"{key!r} is used twice")
        seen.add(key)
        ctype = raw.get("type", "text")
        if ctype not in ("text", "password"):
            _fail(f"{cpath}.type", "must be text or password")
        columns.append({
            "key": key, "type": ctype, "secret": ctype == "password",
            "label": _text(raw.get("label"), f"{cpath}.label", max_len=60, default=key),
            "placeholder": _text(raw.get("placeholder"), f"{cpath}.placeholder", max_len=100),
            "help": _text(raw.get("help"), f"{cpath}.help", max_len=300),
            "required": bool(raw.get("required", False)),
            "optional": bool(raw.get("optional", False)),      # shown under "more" in the row
        })
    if not columns:
        _fail(f"{path}.columns", "a servers field needs at least one column")
    if columns[0]["key"] != "host":
        _fail(f"{path}.columns[0].key", "the first column must be 'host' (the address of the server)")
    return columns


def _server_legacy(value: Any, columns: list[dict], path: str) -> dict | None:
    """How an older version stored the same servers (separate settings), so existing setups carry over."""
    if value is None:
        return None
    value = _dict(value, f"{path}.legacy")
    mapping = _dict(value.get("map"), f"{path}.legacy.map")
    keys = {c["key"] for c in columns}
    for column, old in mapping.items():
        if column not in keys or not isinstance(old, str) or not KEY_RE.match(old):
            _fail(f"{path}.legacy.map", "maps column names to the key of an older setting")
    out = {"map": dict(mapping), "split": value["split"] if isinstance(value.get("split"), str) else ""}
    pair = value.get("pair")
    if pair is not None:
        pair = _dict(pair, f"{path}.legacy.pair")
        if pair.get("column") not in keys:
            _fail(f"{path}.legacy.pair.column", "is not a column")
        out["pair"] = {"sep": _text(pair.get("sep"), f"{path}.legacy.pair.sep", required=True, max_len=3), "column": pair["column"]}
    return out


def migrate_servers(field: dict, saved: dict) -> list[dict]:
    """Rows built from the settings an older plugin version saved (empty when there is nothing to carry over)."""
    legacy = field.get("legacy")
    if not legacy:
        return []
    split = legacy.get("split") or ""      # any value: the old text was split on commas and white space
    columns = {}
    for column, old in legacy["map"].items():
        raw = saved.get(old)
        if not isinstance(raw, str) or not raw.strip():
            columns[column] = []
        elif split:
            columns[column] = [x.strip() for x in re.split(r"[,\s]+", raw.strip()) if x.strip()]
        else:
            columns[column] = [raw.strip()]
    hosts = columns.get("host") or []
    rows = []
    for i, host in enumerate(hosts):
        row = {"id": f"s{i + 1}", "host": host}
        pair = legacy.get("pair")
        if pair and pair["sep"] in host:
            row["host"], row[pair["column"]] = [x.strip() for x in host.split(pair["sep"], 1)]
        for column, values in columns.items():
            if column != "host" and values:
                row[column] = values[i] if i < len(values) else values[0]      # one value for all servers is allowed
        rows.append(row)
    return rows


def clean_servers(field: dict, rows: Any, current: list | None = None) -> list[dict]:
    """Normalise the rows of a servers field. A secret left empty in a row keeps the saved one of the row with the same id."""
    if rows in (None, ""):
        rows = []
    if not isinstance(rows, list):
        raise ContractError(f"{field['label']}: must be a list of servers")
    if len(rows) > MAX_SERVERS:
        raise ContractError(f"{field['label']}: at most {MAX_SERVERS} servers")
    saved = {r.get("id"): r for r in (current or []) if isinstance(r, dict)}
    out, ids = [], set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ContractError(f"{field['label']}: every server must be an object")
        old = saved.get(raw.get("id"), {})
        row = {}
        for col in field["columns"]:
            value = raw.get(col["key"])
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise ContractError(f"{field['label']}: {col['label']} must be text")
            value = value.strip()
            if col["secret"] and not value:
                value = old.get(col["key"], "") if isinstance(old.get(col["key"]), str) else ""
            if len(value) > 1000:
                raise ContractError(f"{field['label']}: {col['label']} is too long")
            row[col["key"]] = value
        if not any(row.values()):
            continue                      # an empty line is not a server
        rid = str(raw.get("id") or "")[:20]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,20}", rid) or rid in ids:
            n = len(out) + 1
            while f"s{n}" in ids:
                n += 1
            rid = f"s{n}"
        ids.add(rid)
        out.append({"id": rid, **row})
    return out


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
        elif ftype == "servers":
            field["default"] = []
            field["columns"] = _server_columns(raw.get("columns"), path)
            field["legacy"] = _server_legacy(raw.get("legacy"), field["columns"], path)
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
        "diagnose": bool(data.get("diagnose", False)),  # the plugin has diagnose(config): a report for its author
        "capabilities": _capabilities(data.get("capabilities"), kind),
        "power": _power(data.get("power"), kind),
        "info": _info(data.get("info")),
        "dashboard": _dashboard(data.get("dashboard")),
        "config": fields,
    }


def _dashboard(raw: Any) -> list[dict]:
    from app.plugin_cards import validate_cards       # the cards a plugin offers for the dashboard

    return validate_cards(raw)


def _info(raw: Any) -> dict | None:
    """An optional collapsed box on the plugin's settings page: a title, a short text and a code block to copy (for example the
    docker-compose lines the plugin needs on the other side)."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        _fail("info", "must be an object")
    return {"title": _text(raw.get("title"), "info.title", required=True, max_len=80),
            "text": _text(raw.get("text"), "info.text", max_len=800),
            "code": _text(raw.get("code"), "info.code", max_len=4000)}


def default_config(manifest: dict) -> dict:
    return {f["key"]: f["default"] for f in manifest["config"]}


def clean_config(manifest: dict, values: dict, current: dict | None = None) -> dict:
    """Keep only the manifest's fields, coerced to their types (unknown keys are dropped)."""
    out = {}
    for f in manifest["config"]:
        key = f["key"]
        value = values.get(key, f["default"])
        if f["type"] == "servers":
            out[key] = clean_servers(f, value if key in values else [], current.get(key) if current else None)
            continue
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
    out = []
    for f in manifest["config"]:
        if f["type"] == "servers":
            rows = config.get(f["key"]) or []
            if f["required"] and not rows:
                out.append(f["label"])
            for i, row in enumerate(rows, 1):
                out += [f"{f['label']} {i}: {c['label']}" for c in f["columns"] if c["required"] and not row.get(c["key"])]
        elif f["required"] and f["type"] != "bool" and config.get(f["key"]) in (None, ""):
            out.append(f["label"])
    return out


# ----------------------------------------------------------------------------- outputs
def _client_type(value: Any, path: str) -> str | None:
    """A device type from Netlens' own list; a type this version does not know is ignored rather than refused."""
    from app.scanner.classify import DEVICE_TYPES

    if value is None or value == "":
        return None
    if not isinstance(value, str):
        _fail(path, f"must be text, got {type(value).__name__}")
    return value if value in DEVICE_TYPES and value != "unknown" else None


def validate_output(kind: str, data: Any) -> dict:
    if kind == "hypervisor":
        return _hypervisor(data)
    if kind == "topology":
        return _topology(data)
    if kind == "dns":
        return _dns(data)
    if kind == "proxy":
        return _proxy(data)
    if kind == "backup":
        return _backup(data)
    if kind == "inventory":
        return _inventory(data)
    if kind == "vulnerability":
        return _vulnerability(data)
    raise ContractError(f"unknown plugin kind {kind!r}")


def _dns_name(value: Any, path: str) -> str:
    name = _text(value, path, required=True, max_len=253).strip().rstrip(".").lower()
    if not name:
        _fail(path, "is empty")
    return name


def _dns(data: Any) -> dict:
    """A DNS plugin's snapshot of what the server has: its zones and the records in them."""
    data = _dict(data, "output")
    zones, seen = [], set()
    for i, raw in enumerate(_list(data.get("zones"), "zones")):
        raw = _dict(raw, f"zones[{i}]")
        name = _dns_name(raw.get("name"), f"zones[{i}].name")
        if name in seen:
            _fail(f"zones[{i}].name", f"{name} is listed twice")
        seen.add(name)
        kind = raw.get("kind", "forward")
        if kind not in ("forward", "reverse"):
            _fail(f"zones[{i}].kind", "must be forward or reverse")
        zones.append({"name": name, "kind": kind, "writable": bool(raw.get("writable", False))})
    records = []
    raw_records = _list(data.get("records"), "records")
    if len(raw_records) > MAX_DNS_RECORDS:
        _fail("records", f"at most {MAX_DNS_RECORDS} records")
    for i, raw in enumerate(raw_records):
        raw = _dict(raw, f"records[{i}]")
        zone = _dns_name(raw.get("zone"), f"records[{i}].zone")
        if zone not in seen:
            _fail(f"records[{i}].zone", f"{zone} is not one of the zones")
        rtype = _text(raw.get("type"), f"records[{i}].type", required=True, max_len=10).upper()
        ttl = raw.get("ttl")
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0):
            _fail(f"records[{i}].ttl", "must be a whole number of seconds")
        records.append({
            "zone": zone,
            "name": _dns_name(raw.get("name"), f"records[{i}].name"),
            "type": rtype,
            "value": _text(raw.get("value"), f"records[{i}].value", max_len=500).strip().rstrip(".").lower() if rtype in ("PTR", "CNAME") else _text(raw.get("value"), f"records[{i}].value", max_len=500).strip(),
            "ttl": ttl,
            "managed": bool(raw.get("managed", False)),
            "comment": _text(raw.get("comment"), f"records[{i}].comment", max_len=200),
        })
    return {"zones": zones, "records": records, "server": _text(data.get("server"), "server", max_len=100) or None}


def validate_dns_results(data: Any, expected_ids: list[str]) -> list[dict]:
    """What a DNS plugin answers to apply(): one result per change it was given."""
    items = _list(data, "results")
    out, seen = [], set()
    for i, raw in enumerate(items):
        raw = _dict(raw, f"results[{i}]")
        cid = _text(raw.get("id"), f"results[{i}].id", required=True, max_len=100)
        if cid not in expected_ids:
            _fail(f"results[{i}].id", f"{cid!r} was not asked for")
        if cid in seen:
            _fail(f"results[{i}].id", f"{cid!r} is answered twice")
        seen.add(cid)
        out.append({"id": cid, "ok": bool(raw.get("ok")), "error": _text(raw.get("error"), f"results[{i}].error", max_len=300) or None})
    for cid in expected_ids:
        if cid not in seen:
            out.append({"id": cid, "ok": False, "error": "the plugin gave no answer for this change"})
    return out


MAX_DETAIL_PORTS = 100
DETAIL_TEXT_KEYS = ("image", "image_created", "image_digest", "project", "service", "health", "started", "network", "network_driver", "os", "tags", "version")


def _guest_details(value: Any, path: str) -> dict:
    """Optional extras about a guest (a container's image, health, published ports ...). Only these keys are kept."""
    if value is None:
        return {}
    value = _dict(value, path)
    out: dict[str, Any] = {}
    for key in DETAIL_TEXT_KEYS:
        if value.get(key) not in (None, ""):
            out[key] = _text(value.get(key), f"{path}.{key}", max_len=200)
    for key in ("restarts", "exit_code"):
        number = _optional_number(value.get(key), f"{path}.{key}", 0, 1_000_000, integer=True) if key == "restarts" else _optional_number(value.get(key), f"{path}.{key}", -1000, 1000, integer=True)
        if number is not None:
            out[key] = number
    for key, high in (("cpus", 4096), ("memory_mb", 100_000_000), ("disk_gb", 100_000_000)):
        number = _optional_number(value.get(key), f"{path}.{key}", 0, high, integer=True)
        if number is not None:
            out[key] = number
    for key in ("exposed", "restarting", "update_available", "autostart"):
        if key in value:
            out[key] = bool(value[key])
    ports = []
    for j, raw in enumerate(_list(value.get("ports"), f"{path}.ports")[:MAX_DETAIL_PORTS]):
        raw = _dict(raw, f"{path}.ports[{j}]")
        proto = _text(raw.get("proto"), f"{path}.ports[{j}].proto", max_len=5, default="tcp").lower()
        ports.append({
            "container_port": _optional_number(raw.get("container_port"), f"{path}.ports[{j}].container_port", 0, 65535, integer=True),
            "host_port": _optional_number(raw.get("host_port"), f"{path}.ports[{j}].host_port", 0, 65535, integer=True),
            "proto": proto if proto in ("tcp", "udp", "sctp") else "tcp",
            "bind": _text(raw.get("bind"), f"{path}.ports[{j}].bind", max_len=45),
        })
    if ports:
        out["ports"] = ports
    return out


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
            "details": _guest_details(raw.get("details"), f"{path}.details"),
        })
    return {"hosts": hosts, "guests": guests}


SITE_TYPES = ("proxy", "redirect", "stream", "dead")
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HOST_NAME_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$")


def _stamp(value: Any, path: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not STAMP_RE.match(value):
        _fail(path, f"must look like 2026-12-31T23:59:59Z (UTC), got {value!r}")
    return value


def _proxy(data: Any) -> dict:
    """A reverse proxy plugin: the proxies themselves and the sites they publish (domain -> upstream)."""
    data = _dict(data, "output")
    proxies, proxy_ids = [], set()
    for i, raw in enumerate(_list(data.get("proxies"), "proxies")):
        path = f"proxies[{i}]"
        raw = _dict(raw, path)
        proxy_id = _id(raw.get("id"), f"{path}.id")
        if proxy_id in proxy_ids:
            _fail(f"{path}.id", f"{proxy_id!r} is used twice")
        proxy_ids.add(proxy_id)
        proxies.append({
            "id": proxy_id,
            "name": _text(raw.get("name"), f"{path}.name", default=proxy_id),
            "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
            "version": _text(raw.get("version"), f"{path}.version", max_len=40),
            "online": bool(raw.get("online", True)),
            "warnings": [_text(w, f"{path}.warnings[{j}]", required=True, max_len=300) for j, w in enumerate(_list(raw.get("warnings"), f"{path}.warnings")[:10])],
        })
    certificates = []
    for i, raw in enumerate(_list(data.get("certificates"), "certificates")):
        path = f"certificates[{i}]"
        raw = _dict(raw, path)
        certificates.append({
            "id": _id(raw.get("id"), f"{path}.id"),
            "proxy_id": _id(raw.get("proxy_id"), f"{path}.proxy_id") if raw.get("proxy_id") not in (None, "") else None,
            "name": _text(raw.get("name"), f"{path}.name", max_len=200),
            "provider": _text(raw.get("provider"), f"{path}.provider", max_len=40),
            "domains": [_text(d, f"{path}.domains[{j}]", required=True, max_len=253) for j, d in enumerate(_list(raw.get("domains"), f"{path}.domains")[:100])],
            "expires": _stamp(raw.get("expires"), f"{path}.expires"),
            "in_use": bool(raw.get("in_use", False)),
        })
    sites, site_ids = [], set()
    for i, raw in enumerate(_list(data.get("sites"), "sites")):
        path = f"sites[{i}]"
        raw = _dict(raw, path)
        site_id = _id(raw.get("id"), f"{path}.id")
        if site_id in site_ids:
            _fail(f"{path}.id", f"{site_id!r} is used twice")
        site_ids.add(site_id)
        proxy_id = _id(raw.get("proxy_id"), f"{path}.proxy_id")
        if proxy_id not in proxy_ids:
            _fail(f"{path}.proxy_id", f"{proxy_id!r} is not the id of any entry in proxies")
        kind = raw.get("type", "proxy")
        if kind not in SITE_TYPES:
            _fail(f"{path}.type", f"must be one of {', '.join(SITE_TYPES)}, got {kind!r}")
        scheme = _text(raw.get("scheme"), f"{path}.scheme", max_len=5, default="http").lower()
        host = _text(raw.get("forward_host"), f"{path}.forward_host", max_len=253)
        if host and not HOST_NAME_RE.match(host):
            _fail(f"{path}.forward_host", f"is not a host name or address ({host!r})")
        sites.append({
            "id": site_id,
            "proxy_id": proxy_id,
            "type": kind,
            "name": _text(raw.get("name"), f"{path}.name", max_len=200),
            "domains": [_text(d, f"{path}.domains[{j}]", required=True, max_len=253).lower() for j, d in enumerate(_list(raw.get("domains"), f"{path}.domains")[:100])],
            "enabled": bool(raw.get("enabled", True)),
            "scheme": scheme if scheme in ("http", "https") else "http",
            "forward_host": host,
            "forward_port": _optional_number(raw.get("forward_port"), f"{path}.forward_port", 1, 65535, integer=True),
            "forward_ips": [a for a in (_ipv4(x, f"{path}.forward_ips[{j}]") for j, x in enumerate(_list(raw.get("forward_ips"), f"{path}.forward_ips")[:10])) if a],
            "incoming_port": _optional_number(raw.get("incoming_port"), f"{path}.incoming_port", 1, 65535, integer=True),
            "ssl": bool(raw.get("ssl", False)),
            "ssl_forced": bool(raw.get("ssl_forced", False)),
            "websockets": bool(raw.get("websockets", False)),
            "certificate_id": _id(raw.get("certificate_id"), f"{path}.certificate_id") if raw.get("certificate_id") not in (None, "") else None,
            "cert_name": _text(raw.get("cert_name"), f"{path}.cert_name", max_len=200),
            "cert_provider": _text(raw.get("cert_provider"), f"{path}.cert_provider", max_len=40),
            "cert_expires": _stamp(raw.get("cert_expires"), f"{path}.cert_expires"),
            "access_list": _text(raw.get("access_list"), f"{path}.access_list", max_len=200),
            "redirect_to": _text(raw.get("redirect_to"), f"{path}.redirect_to", max_len=300),
            "protocols": [p for p in (_text(x, f"{path}.protocols[{j}]", max_len=5).lower() for j, x in enumerate(_list(raw.get("protocols"), f"{path}.protocols")[:4])) if p in ("tcp", "udp")],
        })
    return {"proxies": proxies, "certificates": certificates, "sites": sites}


BACKUP_TYPES = ("vm", "ct", "host", "other")
BACKUP_STATES = ("ok", "warning", "failed", "unknown")
JOB_STATES = ("ok", "warning", "failed", "none")
PROBLEM_KINDS = ("backup", "prune", "gc", "verify", "sync", "other")


def _byte_count(value: Any, path: str) -> int | None:
    number = _optional_number(value, path, 0, 1e18, integer=True)
    return None if number is None else int(number)


def _choice(value: Any, path: str, allowed: tuple[str, ...], default: str) -> str:
    value = default if value in (None, "") else value
    if value not in allowed:
        _fail(path, f"must be one of {', '.join(allowed)}, got {value!r}")
    return value


def _backup(data: Any) -> dict:
    """A backup plugin's snapshot of a backup server (Proxmox Backup Server ...): the stores (disk usage and job results), what is backed up
    (one *target* per guest or host: last backup, number of copies, whether it was verified) and the recent problems."""
    data = _dict(data, "output")
    servers, server_ids = [], set()
    for i, raw in enumerate(_list(data.get("servers"), "servers")):
        path = f"servers[{i}]"
        raw = _dict(raw, path)
        server_id = _id(raw.get("id"), f"{path}.id")
        if server_id in server_ids:
            _fail(f"{path}.id", f"{server_id!r} is used twice")
        server_ids.add(server_id)
        servers.append({
            "id": server_id, "name": _text(raw.get("name"), f"{path}.name", default=server_id), "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
            "version": _text(raw.get("version"), f"{path}.version", max_len=40), "online": bool(raw.get("online", True)),
            "warnings": [_text(w, f"{path}.warnings[{j}]", required=True, max_len=300) for j, w in enumerate(_list(raw.get("warnings"), f"{path}.warnings")[:10])],
        })
    stores, store_ids = [], set()
    for i, raw in enumerate(_list(data.get("stores"), "stores")):
        path = f"stores[{i}]"
        raw = _dict(raw, path)
        store_id = _id(raw.get("id"), f"{path}.id")
        if store_id in store_ids:
            _fail(f"{path}.id", f"{store_id!r} is used twice")
        store_ids.add(store_id)
        server_id = _id(raw.get("server_id"), f"{path}.server_id")
        if server_id not in server_ids:
            _fail(f"{path}.server_id", f"{server_id!r} is not the id of any entry in servers")
        store = {"id": store_id, "server_id": server_id, "name": _text(raw.get("name"), f"{path}.name", default=store_id, max_len=100),
                 "total": _byte_count(raw.get("total"), f"{path}.total"), "used": _byte_count(raw.get("used"), f"{path}.used"), "avail": _byte_count(raw.get("avail"), f"{path}.avail"),
                 "full": _stamp(raw.get("full"), f"{path}.full")}
        for job in ("gc", "prune", "verify", "sync"):
            store[f"{job}_state"] = _choice(raw.get(f"{job}_state"), f"{path}.{job}_state", JOB_STATES, "none")
            store[f"{job}_at"] = _stamp(raw.get(f"{job}_at"), f"{path}.{job}_at")
        stores.append(store)
    targets, target_ids = [], set()
    if len(_list(data.get("targets"), "targets")) > MAX_ITEMS:
        _fail("targets", f"at most {MAX_ITEMS} targets")
    for i, raw in enumerate(_list(data.get("targets"), "targets")):
        path = f"targets[{i}]"
        raw = _dict(raw, path)
        target_id = _id(raw.get("id"), f"{path}.id")
        if target_id in target_ids:
            _fail(f"{path}.id", f"{target_id!r} is used twice")
        target_ids.add(target_id)
        server_id = _id(raw.get("server_id"), f"{path}.server_id")
        if server_id not in server_ids:
            _fail(f"{path}.server_id", f"{server_id!r} is not the id of any entry in servers")
        store_id = raw.get("store_id")
        store_id = _id(store_id, f"{path}.store_id") if store_id not in (None, "") else None
        if store_id is not None and store_id not in store_ids:
            _fail(f"{path}.store_id", f"{store_id!r} is not the id of any entry in stores")
        targets.append({
            "id": target_id, "server_id": server_id, "store_id": store_id, "type": _choice(raw.get("type"), f"{path}.type", BACKUP_TYPES, "other"),
            "backup_id": _text(raw.get("backup_id"), f"{path}.backup_id", required=True, max_len=100), "name": _text(raw.get("name"), f"{path}.name", max_len=200),
            "count": _byte_count(raw.get("count"), f"{path}.count") or 0, "last_backup": _stamp(raw.get("last_backup"), f"{path}.last_backup"),
            "last_state": _choice(raw.get("last_state"), f"{path}.last_state", BACKUP_STATES, "unknown"), "last_size": _byte_count(raw.get("last_size"), f"{path}.last_size"),
            "verify_state": _choice(raw.get("verify_state"), f"{path}.verify_state", JOB_STATES, "none"), "interval": _byte_count(raw.get("interval"), f"{path}.interval"),
            "protected": _byte_count(raw.get("protected"), f"{path}.protected") or 0,
        })
    problems, problem_ids = [], set()
    for i, raw in enumerate(_list(data.get("problems"), "problems")[:200]):
        path = f"problems[{i}]"
        raw = _dict(raw, path)
        problem_id = _id(raw.get("id"), f"{path}.id")
        if problem_id in problem_ids:
            continue
        problem_ids.add(problem_id)
        server_id = _id(raw.get("server_id"), f"{path}.server_id")
        if server_id not in server_ids:
            _fail(f"{path}.server_id", f"{server_id!r} is not the id of any entry in servers")
        target_id = raw.get("target_id")
        problems.append({"id": problem_id, "server_id": server_id, "kind": _choice(raw.get("kind"), f"{path}.kind", PROBLEM_KINDS, "other"),
                         "state": _choice(raw.get("state"), f"{path}.state", ("warning", "failed"), "failed"), "at": _stamp(raw.get("at"), f"{path}.at"),
                         "text": _text(raw.get("text"), f"{path}.text", max_len=300), "target_id": _id(target_id, f"{path}.target_id") if target_id not in (None, "") else None})
    return {"servers": servers, "stores": stores, "targets": targets, "problems": problems}


SEVERITIES = ("critical", "high", "medium", "low", "info")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,9}$", re.IGNORECASE)
MAX_FINDINGS = 20000


def _vulnerability(data: Any) -> dict:
    """A vulnerability plugin's snapshot of a scanner (Greenbone, Tenable, Rapid7 ...): the scanners, and the findings: what is wrong on which host.

    A finding names its host by address and/or MAC address (Netlens matches it to a device), a title, a severity (critical, high, medium, low, info),
    optionally CVE numbers, a score (0-10), the port, whether the vulnerability is known to be exploited, and a solution. Only open findings should be sent."""
    data = _dict(data, "output")
    servers, server_ids = [], set()
    for i, raw in enumerate(_list(data.get("servers"), "servers")):
        path = f"servers[{i}]"
        raw = _dict(raw, path)
        server_id = _id(raw.get("id"), f"{path}.id")
        if server_id in server_ids:
            _fail(f"{path}.id", f"{server_id!r} is used twice")
        server_ids.add(server_id)
        servers.append({"id": server_id, "name": _text(raw.get("name"), f"{path}.name", default=server_id), "version": _text(raw.get("version"), f"{path}.version", max_len=40),
                        "online": bool(raw.get("online", True)), "last_scan": _stamp(raw.get("last_scan"), f"{path}.last_scan"),
                        "warnings": [_text(w, f"{path}.warnings[{j}]", required=True, max_len=300) for j, w in enumerate(_list(raw.get("warnings"), f"{path}.warnings")[:10])]})
    raw_findings = data.get("findings")
    if raw_findings is not None and (not isinstance(raw_findings, list)):
        _fail("findings", "must be a list")
    if len(raw_findings or []) > MAX_FINDINGS:
        _fail("findings", f"at most {MAX_FINDINGS} findings (send the most serious ones)")
    findings, seen = [], set()
    for i, raw in enumerate(raw_findings or []):
        path = f"findings[{i}]"
        raw = _dict(raw, path)
        fid = _id(raw.get("id"), f"{path}.id")
        if fid in seen:
            continue
        seen.add(fid)
        server_id = _id(raw.get("server_id"), f"{path}.server_id")
        if server_id not in server_ids:
            _fail(f"{path}.server_id", f"{server_id!r} is not the id of any entry in servers")
        ip, mac = _ipv4(raw.get("host_ip"), f"{path}.host_ip"), _mac(raw.get("host_mac"), f"{path}.host_mac")
        if not ip and not mac:
            _fail(path, "needs host_ip or host_mac, so Netlens can tell which device it is about")
        cves = []
        for j, c in enumerate(_list(raw.get("cve"), f"{path}.cve")[:20]):
            c = _text(c, f"{path}.cve[{j}]", required=True, max_len=20).upper()
            if not CVE_RE.match(c):
                _fail(f"{path}.cve[{j}]", f"is not a CVE number like CVE-2024-12345, got {c!r}")
            cves.append(c)
        port = _optional_number(raw.get("port"), f"{path}.port", 0, 65535, integer=True)
        findings.append({
            "id": fid, "server_id": server_id, "host_ip": ip, "host_mac": mac, "host_name": _text(raw.get("host_name"), f"{path}.host_name", max_len=100),
            "title": _text(raw.get("title"), f"{path}.title", required=True, max_len=200), "cve": cves, "severity": _choice(raw.get("severity"), f"{path}.severity", SEVERITIES, "info"),
            "score": _optional_number(raw.get("score"), f"{path}.score", 0, 10), "port": None if port is None else int(port),
            "proto": _choice(raw.get("proto"), f"{path}.proto", ("tcp", "udp"), "tcp"), "first_seen": _stamp(raw.get("first_seen"), f"{path}.first_seen"),
            "last_seen": _stamp(raw.get("last_seen"), f"{path}.last_seen"), "exploited": bool(raw.get("exploited", False)),
            "solution": _text(raw.get("solution"), f"{path}.solution", max_len=500), "url": _text(raw.get("url"), f"{path}.url", max_len=300)})
    return {"servers": servers, "findings": findings}


def _inventory(data: Any) -> dict:
    """An inventory plugin's snapshot of a smart-home hub (Home Assistant ...): the devices it knows, with the details Netlens does not see on the network
    (manufacturer, model, area, firmware, protocol), whether each is available, its battery and the device it is paired through."""
    data = _dict(data, "output")
    servers, server_ids = [], set()
    for i, raw in enumerate(_list(data.get("servers"), "servers")):
        path = f"servers[{i}]"
        raw = _dict(raw, path)
        server_id = _id(raw.get("id"), f"{path}.id")
        if server_id in server_ids:
            _fail(f"{path}.id", f"{server_id!r} is used twice")
        server_ids.add(server_id)
        servers.append({"id": server_id, "name": _text(raw.get("name"), f"{path}.name", default=server_id), "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
                        "version": _text(raw.get("version"), f"{path}.version", max_len=40), "online": bool(raw.get("online", True)),
                        "warnings": [_text(w, f"{path}.warnings[{j}]", required=True, max_len=300) for j, w in enumerate(_list(raw.get("warnings"), f"{path}.warnings")[:10])]})
    devices, ids = [], set()
    raw_devices = _list(data.get("devices"), "devices")
    if len(raw_devices) > MAX_ITEMS:
        _fail("devices", f"at most {MAX_ITEMS} devices")
    for i, raw in enumerate(raw_devices):
        path = f"devices[{i}]"
        raw = _dict(raw, path)
        dev_id = _id(raw.get("id"), f"{path}.id")
        if dev_id in ids:
            _fail(f"{path}.id", f"{dev_id!r} is used twice")
        ids.add(dev_id)
        server_id = _id(raw.get("server_id"), f"{path}.server_id")
        if server_id not in server_ids:
            _fail(f"{path}.server_id", f"{server_id!r} is not the id of any entry in servers")
        via = raw.get("via_id")
        battery = _optional_number(raw.get("battery"), f"{path}.battery", 0, 100, integer=True)
        devices.append({"id": dev_id, "server_id": server_id, "name": _text(raw.get("name"), f"{path}.name", default=dev_id, max_len=120),
                        "manufacturer": _text(raw.get("manufacturer"), f"{path}.manufacturer", max_len=80) or None, "model": _text(raw.get("model"), f"{path}.model", max_len=120) or None,
                        "area": _text(raw.get("area"), f"{path}.area", max_len=80) or None, "sw": _text(raw.get("sw"), f"{path}.sw", max_len=60) or None,
                        "protocol": _text(raw.get("protocol"), f"{path}.protocol", max_len=40) or None, "mac": _mac(raw.get("mac"), f"{path}.mac"), "ip": _ipv4(raw.get("ip"), f"{path}.ip"),
                        "via_id": _id(via, f"{path}.via_id") if via not in (None, "") else None, "available": bool(raw.get("available", True)), "battery": battery,
                        "battery_low": bool(raw.get("battery_low", False)), "update": bool(raw.get("update", False)), "url": _text(raw.get("url"), f"{path}.url", max_len=300) or None,
                        "entities": _byte_count(raw.get("entities"), f"{path}.entities")})
    for d in devices:
        if d["via_id"] is not None and d["via_id"] not in ids:
            d["via_id"] = None
    return {"servers": servers, "devices": devices}


def _switch_ports(value: Any, path: str) -> list[dict]:
    """The ports of a switch node: link state, speed and packet counters (a plugin for a switch that has no SNMP reads them from its web page)."""
    ports, seen = [], set()
    for i, raw in enumerate(_list(value, path)[:128]):
        p = f"{path}[{i}]"
        raw = _dict(raw, p)
        number = _optional_number(raw.get("port"), f"{p}.port", 1, 1024, integer=True)
        if number is None:
            _fail(f"{p}.port", "is required")
        if number in seen:
            _fail(f"{p}.port", f"port {number} is listed twice")
        seen.add(number)
        duplex = raw.get("duplex")
        if duplex not in (None, "full", "half"):
            _fail(f"{p}.duplex", "must be full or half")
        for key in ("up", "enabled"):
            if key in raw and not isinstance(raw[key], bool):
                _fail(f"{p}.{key}", "must be true or false")
        ports.append({
            "port": number,
            "name": _text(raw.get("name"), f"{p}.name", max_len=40) or None,
            "enabled": raw.get("enabled", True),
            "up": raw.get("up", False),
            "speed_mbps": _optional_number(raw.get("speed_mbps"), f"{p}.speed_mbps", 0, 1000000),
            "duplex": duplex,
            **{k: _optional_number(raw.get(k), f"{p}.{k}", 0, 2**63 - 1, integer=True) for k in ("tx_packets", "rx_packets", "tx_errors", "rx_errors")},
        })
    return ports


def _firewall(value: Any, path: str) -> dict | None:
    """What a firewall node tells besides its clients: version, high availability, VPN tunnels and licences."""
    if not value:
        return None
    value = _dict(value, path)
    ha = value.get("ha")
    if ha:
        ha = _dict(ha, f"{path}.ha")
        in_sync = ha.get("in_sync")
        if in_sync is not None and not isinstance(in_sync, bool):
            _fail(f"{path}.ha.in_sync", "must be true or false")
        ha = {"mode": _text(ha.get("mode"), f"{path}.ha.mode", max_len=30) or None, "state": _text(ha.get("state"), f"{path}.ha.state", max_len=20).lower() or None,
              "peer_state": _text(ha.get("peer_state"), f"{path}.ha.peer_state", max_len=20).lower() or None, "in_sync": in_sync}
    else:
        ha = None
    tunnels, names = [], set()
    for i, raw in enumerate(_list(value.get("tunnels"), f"{path}.tunnels")[:200]):
        raw = _dict(raw, f"{path}.tunnels[{i}]")
        name = _text(raw.get("name"), f"{path}.tunnels[{i}].name", required=True, max_len=80)
        if name in names or not isinstance(raw.get("up", False), bool):
            continue
        names.add(name)
        tunnels.append({"name": name, "remote": _text(raw.get("remote"), f"{path}.tunnels[{i}].remote", max_len=80) or None, "up": raw.get("up", False)})
    licences = []
    for i, raw in enumerate(_list(value.get("licences"), f"{path}.licences")[:50]):
        raw = _dict(raw, f"{path}.licences[{i}]")
        expires = _text(raw.get("expires"), f"{path}.licences[{i}].expires", max_len=10) or None
        if expires is not None and not re.match(r"^\d{4}-\d{2}-\d{2}$", expires):
            _fail(f"{path}.licences[{i}].expires", "must be a date like 2027-01-31")
        licences.append({"name": _text(raw.get("name"), f"{path}.licences[{i}].name", required=True, max_len=80), "expires": expires})
    return {"version": _text(value.get("version"), f"{path}.version", max_len=60) or None, "serial": _text(value.get("serial"), f"{path}.serial", max_len=60) or None,
            "model": _text(value.get("model"), f"{path}.model", max_len=80) or None, "ha": ha, "tunnels": tunnels, "licences": licences}


def _topology(data: Any) -> dict:
    data = _dict(data, "output")
    nodes, node_macs = [], set()
    for i, raw in enumerate(_list(data.get("nodes"), "nodes")):
        path = f"nodes[{i}]"
        raw = _dict(raw, path)
        mac = _mac(raw.get("mac"), f"{path}.mac")
        if mac is None:      # a node that is only known by its address (a firewall managed from a controller): a placeholder derived from it; Netlens matches it by IP
            node_ip = _ipv4(raw.get("ip"), f"{path}.ip")
            if node_ip is None:
                _fail(f"{path}.mac", "is required (or give the node an ip)")
            mac = "02:00:" + ":".join(f"{int(part):02x}" for part in node_ip.split("."))
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
            "ports": _switch_ports(raw.get("ports"), f"{path}.ports"),
            "firewall": _firewall(raw.get("firewall"), f"{path}.firewall"),
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
            # what the router / controller has worked out about the device (all optional; used as evidence, never trusted blindly)
            "vendor": _text(raw.get("vendor"), f"{path}.vendor", max_len=100) or None,
            "os": _text(raw.get("os"), f"{path}.os", max_len=100) or None,
            "model": _text(raw.get("model"), f"{path}.model", max_len=100) or None,
            "device_type": _client_type(raw.get("device_type"), f"{path}.device_type"),
            "port": _text(raw.get("port"), f"{path}.port", max_len=60) or None,   # the switch port a wired client sits on ("Gi1/0/5")
        })
    return {"nodes": nodes, "clients": clients}
