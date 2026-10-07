import json
import re
from dataclasses import dataclass, asdict, field, fields
from typing import Any

from app.db import get_setting, set_setting


@dataclass
class NotifyConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    security: str = "starttls"
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    notify_new: bool = True
    notify_offline: bool = True
    last_event_id: int | None = None


ALLOWED_SECURITY = {"none", "starttls", "ssl"}
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


def load_config(conn) -> NotifyConfig:
    raw = get_setting(conn, "notifications")
    if not raw:
        return NotifyConfig()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return NotifyConfig()

    cfg = NotifyConfig()
    for f in fields(cfg):
        if f.name not in data:
            continue
        val = data[f.name]
        if f.name == "security":
            if val not in ALLOWED_SECURITY:
                val = "starttls"
        elif f.name == "smtp_port":
            if not isinstance(val, int) or val < 1 or val > 65535:
                val = 587
        elif f.name == "to_addrs":
            if not isinstance(val, list):
                val = []
            val = [str(v) for v in val]
        elif f.name == "last_event_id":
            if val is not None and not isinstance(val, int):
                val = None
        elif f.name == "enabled":
            if not isinstance(val, bool):
                val = False
        elif f.name in ("notify_new", "notify_offline"):
            if not isinstance(val, bool):
                val = True
        elif f.name in ("smtp_host", "username", "password", "from_addr"):
            if not isinstance(val, str):
                val = ""
        setattr(cfg, f.name, val)
    return cfg


def save_config(conn, cfg: NotifyConfig) -> None:
    set_setting(conn, "notifications", json.dumps(asdict(cfg)))


def is_configured(cfg: NotifyConfig) -> bool:
    return bool(cfg.smtp_host.strip()) and bool(cfg.from_addr.strip()) and bool(cfg.to_addrs)


def public_dict(cfg: NotifyConfig) -> dict:
    d = asdict(cfg)
    d.pop("password", None)
    d.pop("last_event_id", None)
    d["password_set"] = bool(cfg.password)
    d["configured"] = is_configured(cfg)
    return d


def parse_addresses(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = re.split(r"[,;\s]+", value)
    elif isinstance(value, list):
        parts = []
        for item in value:
            parts.extend(re.split(r"[,;\s]+", str(item)))
    else:
        raise ValueError(f"invalid email address: {value}")

    seen: set[str] = set()
    result: list[str] = []
    for part in parts:
        addr = part.strip()
        if not addr:
            continue
        if not EMAIL_RE.match(addr):
            raise ValueError(f"invalid email address: {addr}")
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            result.append(addr)
    return result