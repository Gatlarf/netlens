
TASK: write app/notify/config.py (full file, under 110 lines). Imports allowed: json, re, dataclasses (dataclass, asdict, fields), and `from app.db import get_setting, set_setting`.

Stores the e-mail notification settings as one JSON document in the `settings` table under key "notifications".

@dataclass
class NotifyConfig:  # all fields have defaults
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    security: str = "starttls"        # one of "none", "starttls", "ssl"
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    notify_new: bool = True           # mail when a new device appears
    notify_offline: bool = True       # mail when a device goes offline (a device can additionally opt out itself)
    last_event_id: int | None = None  # newest event id already handled; None = never initialised

def load_config(conn) -> NotifyConfig
  - get_setting(conn, "notifications"); missing, empty or invalid JSON -> NotifyConfig(). Unknown keys in the JSON are ignored; keys with a wrong type fall back to the field default. security values other than the three allowed ones fall back to "starttls". smtp_port outside 1..65535 falls back to 587.

def save_config(conn, cfg: NotifyConfig) -> None
  - set_setting(conn, "notifications", json.dumps(asdict(cfg)))

def is_configured(cfg: NotifyConfig) -> bool
  - True only when smtp_host, from_addr are non-empty (after strip) and to_addrs is non-empty.

def public_dict(cfg: NotifyConfig) -> dict
  - Returns every field EXCEPT password and last_event_id, plus "password_set": bool(cfg.password) and "configured": is_configured(cfg). Never include the password text.

def parse_addresses(value: str | list[str] | None) -> list[str]
  - Accepts None, a comma/semicolon/whitespace separated string, or a list of such strings. Returns the stripped non-empty addresses in order without duplicates (case-insensitive duplicates removed, first spelling kept). Each address must match r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$"; otherwise raise ValueError(f"invalid email address: {addr}").
