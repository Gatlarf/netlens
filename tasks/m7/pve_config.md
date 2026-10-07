
TASK: write app/integrations/proxmox_config.py (full file, under 100 lines). Imports allowed: json, dataclasses (dataclass, asdict, field, fields), urllib.parse (urlparse), and `from app.db import get_setting, set_setting`.

Stores the Proxmox connector settings as one JSON document in the `settings` table under key "proxmox".

@dataclass
class ProxmoxConfig:  # all fields have defaults
    enabled: bool = False
    url: str = ""                 # e.g. "https://192.168.0.180:8006"
    verify_tls: bool = True
    username: str = ""            # password login, e.g. "root@pam"
    password: str = ""
    token_id: str = ""            # API token login, e.g. "root@pam!netlens"
    token_secret: str = ""

def load_config(conn) -> ProxmoxConfig
  - get_setting(conn, "proxmox"); missing, empty or invalid JSON -> ProxmoxConfig(). Unknown keys ignored; keys with a wrong type fall back to the field default.
def save_config(conn, cfg: ProxmoxConfig) -> None   # set_setting(conn, "proxmox", json.dumps(asdict(cfg)))
def uses_token(cfg) -> bool   # True when token_id and token_secret are both non-empty
def is_configured(cfg) -> bool
  - True when url is valid (see normalize_url) and either uses_token(cfg) or both username and password are non-empty.
def normalize_url(url: str) -> str
  - Strip whitespace and trailing slashes; if no scheme is present prepend "https://"; if no port is present append ":8006". Only http/https schemes are allowed and a host is required, otherwise raise ValueError("invalid Proxmox URL"). Return e.g. "https://192.168.0.180:8006". An empty string returns "" (not an error).
def public_dict(cfg) -> dict
  - All fields EXCEPT password and token_secret, plus "password_set": bool(cfg.password), "token_secret_set": bool(cfg.token_secret), "auth_method": "token" if uses_token(cfg) else ("password" if cfg.username and cfg.password else "none"), "configured": is_configured(cfg). Never include secret text.
