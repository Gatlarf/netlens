import json
from dataclasses import dataclass, asdict, fields
from urllib.parse import urlparse
from app.db import get_setting, set_setting


@dataclass
class ProxmoxConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = True
    username: str = ""
    password: str = ""
    token_id: str = ""
    token_secret: str = ""


def load_config(conn) -> ProxmoxConfig:
    raw = get_setting(conn, "proxmox")
    if not raw:
        return ProxmoxConfig()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ProxmoxConfig()
    if not isinstance(data, dict):
        return ProxmoxConfig()
    cfg = ProxmoxConfig()
    for f in fields(cfg):
        if f.name in data:
            val = data[f.name]
            if isinstance(val, f.type):
                setattr(cfg, f.name, val)
    return cfg


def save_config(conn, cfg: ProxmoxConfig) -> None:
    set_setting(conn, "proxmox", json.dumps(asdict(cfg)))


def uses_token(cfg: ProxmoxConfig) -> bool:
    return bool(cfg.token_id) and bool(cfg.token_secret)


def is_configured(cfg: ProxmoxConfig) -> bool:
    try:
        if not normalize_url(cfg.url):
            return False
    except ValueError:
        return False
    if uses_token(cfg):
        return True
    return bool(cfg.username) and bool(cfg.password)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("invalid Proxmox URL")
    if not parsed.hostname:
        raise ValueError("invalid Proxmox URL")
    if parsed.port is None:
        url = url + ":8006"
    return url


def public_dict(cfg: ProxmoxConfig) -> dict:
    d = asdict(cfg)
    d.pop("password", None)
    d.pop("token_secret", None)
    d["password_set"] = bool(cfg.password)
    d["token_secret_set"] = bool(cfg.token_secret)
    if uses_token(cfg):
        d["auth_method"] = "token"
    elif cfg.username and cfg.password:
        d["auth_method"] = "password"
    else:
        d["auth_method"] = "none"
    d["configured"] = is_configured(cfg)
    return d