from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ProxmoxConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = True
    username: str = ""
    password: str = ""
    token_id: str = ""
    token_secret: str = ""


def uses_token(cfg: ProxmoxConfig) -> bool:
    return bool(cfg.token_id) and bool(cfg.token_secret)


def has_credentials(cfg: ProxmoxConfig) -> bool:
    return uses_token(cfg) or (bool(cfg.username) and bool(cfg.password))


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
