Create app/config.py.

Requirements:
- class ConfigError(ValueError).
- frozen dataclass Settings with fields: token: str; ranges: tuple[str, ...]; quick_interval: int (seconds); deep_interval: int; terminal_enabled: bool; snmp_community: str | None; bind_host: str; bind_port: int; data_dir: pathlib.Path.
- def load_settings(env: Mapping[str, str] | None = None) -> Settings. Uses os.environ when env is None. Reads:
  NETLENS_TOKEN (required, non-empty after strip, else ConfigError),
  NETLENS_RANGES (optional, comma separated IPv4 CIDRs, default empty tuple meaning autodetect; each normalised with ipaddress.ip_network(strict=False) and returned as str; must pass is_scannable_range else ConfigError),
  NETLENS_QUICK_INTERVAL (default 900) and NETLENS_DEEP_INTERVAL (default 86400): integers, each >= 60 else ConfigError,
  NETLENS_TERMINAL ("on" or "off", case-insensitive, default "on", anything else ConfigError),
  NETLENS_SNMP_COMMUNITY (optional, None if unset/empty),
  NETLENS_BIND (default "0.0.0.0:8080", format host:port, port 1-65535 else ConfigError),
  NETLENS_DATA_DIR (default "/data").
- def is_scannable_range(cidr: str) -> bool: True only for IPv4 networks that are private (RFC1918) or link-local (169.254.0.0/16) AND have prefix length >= 20 (i.e. no bigger than a /20). Invalid strings return False (never raise).
- Error messages must name the offending variable. Never include the token value in any error message.
