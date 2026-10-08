import json
from dataclasses import dataclass, asdict, fields
from urllib.parse import urlparse
from app.db import get_setting, set_setting


@dataclass
class AsusConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = False  # ASUS routers ship a self-signed certificate
    username: str = ""
    password: str = ""


def load_config(conn) -> AsusConfig:
    raw = get_setting(conn, "asus")
    if not raw:
        return AsusConfig()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return AsusConfig()
    if not isinstance(data, dict):
        return AsusConfig()
    cfg = AsusConfig()
    for f in fields(cfg):
        if f.name in data and isinstance(data[f.name], f.type):
            setattr(cfg, f.name, data[f.name])
    return cfg


def save_config(conn, cfg: AsusConfig) -> None:
    set_setting(conn, "asus", json.dumps(asdict(cfg)))


def normalize_url(url: str) -> str:
    """'192.168.0.1' -> 'https://192.168.0.1:8443' (the stock HTTPS port); 'http://host' keeps port 80."""
    url = url.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("invalid router address")
    if parsed.path not in ("", "/") or parsed.query:
        raise ValueError("enter only the router address, without a path")
    if parsed.port is None and parsed.scheme == "https":
        url += ":8443"
    return url


def is_configured(cfg: AsusConfig) -> bool:
    try:
        if not normalize_url(cfg.url):
            return False
    except ValueError:
        return False
    return bool(cfg.username) and bool(cfg.password)


def public_dict(cfg: AsusConfig) -> dict:
    d = asdict(cfg)
    d.pop("password", None)
    d["password_set"] = bool(cfg.password)
    d["configured"] = is_configured(cfg)
    return d
