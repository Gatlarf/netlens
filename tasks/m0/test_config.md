Create tests/test_config.py using pytest for app/config.py (module app.config; names: load_settings, Settings, ConfigError, is_scannable_range). Pass an explicit env dict to load_settings, never touch os.environ.

Behaviour of the module under test:
- NETLENS_TOKEN required and non-empty; defaults: ranges=(), quick_interval=900, deep_interval=86400, terminal_enabled=True, snmp_community=None, bind_host="0.0.0.0", bind_port=8080, data_dir=Path("/data").
- NETLENS_RANGES comma separated CIDRs, normalised (e.g. "192.168.1.5/24" becomes "192.168.1.0/24"); only private/link-local IPv4 with prefix >= 20 allowed, else ConfigError.
- Intervals are ints >= 60. NETLENS_TERMINAL is on/off case-insensitive, else ConfigError. NETLENS_BIND is host:port with port 1-65535.
- ConfigError messages name the variable and never contain the token value.
- is_scannable_range: True for 192.168.1.0/24, 10.0.0.0/20, 169.254.0.0/16 is False (prefix too small? NO: /16 is bigger than /20 so False), 8.8.8.0/24 False, 10.0.0.0/8 False, "garbage" False, 172.16.0.0/24 True, 172.32.0.0/24 False.
Write at least 15 focused tests, using parametrize where it helps.
