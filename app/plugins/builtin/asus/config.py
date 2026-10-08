from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class AsusConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = False  # ASUS routers ship a self-signed certificate
    username: str = ""
    password: str = ""


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
