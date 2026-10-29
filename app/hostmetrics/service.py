"""Host monitors: read the health of a device now and then (SNMP or SSH), keep the graphs, and raise alerts.

A monitor belongs to one device: how to ask it (method, address, login), how often, and which groups of readings it answers
(learned the first time: processor, memory, disks, network traffic, temperatures, UPS, printer supplies). The login is stored
encrypted (the vault). Every reading goes into the metrics store; a value that stays beyond a limit for a few rounds in a row
raises `metric_warning` / `metric_critical`, and `metric_ok` when it is back to normal.
"""

from __future__ import annotations

import asyncio
import json
import re
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app import arpcache, dbengine, tsdb, vault
from app.db import add_event, connect, get_setting, set_setting, utcnow
from app.hostmetrics import snmp, snmpv3, ssh, winrm

log = logging.getLogger(__name__)

METHODS = ("snmp", "ssh", "winrm")
DEFAULT_PORT = {"snmp": 161, "ssh": 22, "winrm": 5986}
MIN_INTERVAL, MAX_INTERVAL, DEFAULT_INTERVAL = 30, 3600, 60
MAX_CONCURRENT = 6
THRESHOLDS_KEY = "hostmetrics.thresholds"
DEVICE_LIMITS_KEY = "hostmetrics.device_limits"      # {device id: {metric: {warn, crit, enabled}}}: a device that differs from the rest

# What is worth a message by default. `low` means the value is bad when it is LOW (battery, supplies). `confirm` is the number
# of readings in a row that must agree before the level changes, so one busy second is not an alarm.
DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "cpu_pct": {"title": "Processor busy", "unit": "%", "warn": 90, "crit": 98, "confirm": 5},
    "mem_pct": {"title": "Memory in use", "unit": "%", "warn": 90, "crit": 97, "confirm": 3},
    "disk_pct": {"title": "Disk full", "unit": "%", "warn": 85, "crit": 95, "confirm": 2},
    "if_util_pct": {"title": "Port busy", "unit": "%", "warn": 85, "crit": 95, "confirm": 5},
    "if_err_ps": {"title": "Port errors", "unit": "/s", "warn": 1, "crit": 10, "confirm": 3},
    "temp_c": {"title": "Temperature", "unit": "°C", "warn": 80, "crit": 90, "confirm": 3},
    "sensor_fault": {"title": "Fan or power supply problem", "unit": "", "warn": 1, "crit": 2, "confirm": 2},
    "supply_pct": {"title": "Supply low", "unit": "%", "warn": 15, "crit": 5, "confirm": 1, "low": True},
    "ups_load_pct": {"title": "UPS load", "unit": "%", "warn": 80, "crit": 95, "confirm": 3},
    "battery_pct": {"title": "UPS battery", "unit": "%", "warn": 50, "crit": 25, "confirm": 1, "low": True},
    "on_battery": {"title": "UPS on battery power", "unit": "", "warn": 1, "crit": None, "confirm": 1},
    "storage_status": {"title": "Storage problem", "unit": "", "warn": 1, "crit": 2, "confirm": 1},
    "service_stopped": {"title": "Service stopped", "unit": "", "warn": 1, "crit": None, "confirm": 2},
    # a link that goes down (a cable out of a bond, a lost uplink). Off until it is switched on, because a switch has ports with nothing plugged in; `only` names the interfaces to watch
    "if_up": {"title": "Link down", "unit": "", "warn": 0, "crit": None, "confirm": 2, "low": True, "enabled": False, "only": []},
}


MAX_ONLY = 20          # interfaces one link rule may name


class MonitorError(ValueError):
    """The definition of a monitor is not valid."""


def make_agent(address: str, port: int, secret: dict[str, Any], timeout: float = 2.5, retries: int = 1):
    """The SNMP client for a monitor: v1, v2c with a community, or v3 with a user (and optional authentication and privacy)."""
    where = address if port == 161 else f"{address}:{port}"
    if str(secret.get("version", "2c")) == "3":
        return snmpv3.AgentV3(where, secret.get("username", ""), secret.get("auth_proto", ""), secret.get("auth_password", ""),
                              secret.get("priv_proto", ""), secret.get("priv_password", ""), timeout=timeout, retries=retries)
    return snmp.Agent(where, secret.get("community", "public"), secret.get("version", "2c"), timeout=timeout, retries=retries)


# ----------------------------------------------------------------------------- rules
def _apply(base: dict[str, dict[str, Any]], saved: Any) -> None:
    """Lay the saved changes (warn, crit, enabled) over `base`, ignoring what is not valid."""
    if not isinstance(saved, dict):
        return
    for metric, mine in saved.items():
        if metric not in base or not isinstance(mine, dict):
            continue
        for k in ("warn", "crit"):
            if k in mine and (mine[k] is None or isinstance(mine[k], (int, float)) and not isinstance(mine[k], bool)):
                base[metric][k] = mine[k]
        if isinstance(mine.get("enabled"), bool):
            base[metric]["enabled"] = mine["enabled"]
        if isinstance(mine.get("only"), list):
            base[metric]["only"] = [x for x in mine["only"] if isinstance(x, str)][:MAX_ONLY]


def _saved(conn, key: str) -> Any:
    try:
        return json.loads(get_setting(conn, key) or "{}")
    except ValueError:
        return {}


def rules(conn, device_id: int | None = None) -> dict[str, dict[str, Any]]:
    """The default rules with the user's changes applied: {metric: {title, unit, warn, crit, confirm, low, enabled}}.
    With a device id the limits that were set for that device alone are applied on top."""
    out = {metric: {**base, "enabled": base.get("enabled", True)} for metric, base in DEFAULT_RULES.items()}
    _apply(out, _saved(conn, THRESHOLDS_KEY))
    if device_id is not None:
        mine = _saved(conn, DEVICE_LIMITS_KEY)
        if isinstance(mine, dict):
            _apply(out, mine.get(str(device_id)))
    return out


def device_overrides(conn, device_id: int, saved: dict | None = None) -> dict[str, dict[str, Any]]:
    """Only what was changed for this device (empty when it follows the general limits). `saved` = all_overrides(), for a loop over devices."""
    mine = saved if saved is not None else _saved(conn, DEVICE_LIMITS_KEY)
    item = mine.get(str(device_id)) if isinstance(mine, dict) else None
    return item if isinstance(item, dict) else {}


def all_overrides(conn) -> dict:
    mine = _saved(conn, DEVICE_LIMITS_KEY)
    return mine if isinstance(mine, dict) else {}


def _clean_rules(data: dict) -> dict[str, dict]:
    clean: dict[str, dict] = {}
    for metric, mine in (data or {}).items():
        if metric not in DEFAULT_RULES:
            raise MonitorError(f"unknown measurement: {metric}")
        if not isinstance(mine, dict):
            raise MonitorError("a rule must be an object")
        item: dict[str, Any] = {}
        for k in ("warn", "crit"):
            if k in mine:
                v = mine[k]
                if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float))):
                    raise MonitorError(f"{k} must be a number")
                item[k] = v
        if "enabled" in mine:
            item["enabled"] = bool(mine["enabled"])
        if "only" in mine:
            if metric != "if_up":
                raise MonitorError("only the link rule can be limited to some interfaces")
            names = mine["only"]
            if not isinstance(names, list) or any(not isinstance(x, str) for x in names):
                raise MonitorError("the interfaces must be a list of names")
            clean_names = [" ".join(x.split())[:40] for x in names if x.strip()]
            if len(clean_names) > MAX_ONLY:
                raise MonitorError(f"at most {MAX_ONLY} interfaces")
            item["only"] = clean_names
        warn, crit = item.get("warn", DEFAULT_RULES[metric]["warn"]), item.get("crit", DEFAULT_RULES[metric]["crit"])
        if warn is not None and crit is not None:
            low = DEFAULT_RULES[metric].get("low")
            if (low and crit > warn) or (not low and crit < warn):
                raise MonitorError(f"{DEFAULT_RULES[metric]['title']}: the critical limit must be {'below' if low else 'above'} the warning limit")
        clean[metric] = item
    return clean


def save_rules(conn, data: dict) -> dict[str, dict[str, Any]]:
    """Validate and store changed limits. Only warn, crit and enabled can be changed."""
    set_setting(conn, THRESHOLDS_KEY, json.dumps(_clean_rules(data)))
    return rules(conn)


def save_device_limits(conn, device_id: int, data: dict) -> dict[str, dict[str, Any]]:
    """Limits for one device. An empty object makes it follow the general limits again."""
    clean = _clean_rules(data)
    mine = _saved(conn, DEVICE_LIMITS_KEY)
    mine = mine if isinstance(mine, dict) else {}
    if clean:
        mine[str(device_id)] = clean
    else:
        mine.pop(str(device_id), None)
    set_setting(conn, DEVICE_LIMITS_KEY, json.dumps(mine))
    return rules(conn, device_id)


def level_of(rule: dict[str, Any], value: float) -> str:
    low = bool(rule.get("low"))

    def beyond(limit):
        return limit is not None and (value <= limit if low else value >= limit)

    if beyond(rule.get("crit")):
        return "critical"
    if beyond(rule.get("warn")):
        return "warning"
    return "ok"


PLAIN_WINRM_KEY = "hostmetrics.allow_plain_winrm"


def plain_winrm_allowed(conn) -> bool:
    return (get_setting(conn, PLAIN_WINRM_KEY) or "0") == "1"


def set_plain_winrm(conn, allowed: bool) -> bool:
    set_setting(conn, PLAIN_WINRM_KEY, "1" if allowed else "0")
    conn.commit()
    winrm.ALLOW_PLAIN_HTTP = bool(allowed)
    return bool(allowed)


# ----------------------------------------------------------------------------- definition
def validate(data: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalise what the browser sent. Secrets that are not sent (None) keep their stored value."""
    from app.services import HOST_RE

    cur = current or {}
    method = data.get("method", cur.get("method"))
    if method not in METHODS:
        raise MonitorError("choose how to ask the device: SNMP, SSH or WinRM")
    address = str(data.get("address", cur.get("address")) or "").strip()
    if not HOST_RE.match(address):
        raise MonitorError("the address must be a host name or an IP address")
    port = data.get("port", cur.get("port"))
    port = DEFAULT_PORT[method] if port in (None, "") else port
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise MonitorError("the port must be a number from 1 to 65535")
    interval = data.get("interval_s", cur.get("interval_s", DEFAULT_INTERVAL))
    if isinstance(interval, bool) or not isinstance(interval, int) or not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        raise MonitorError(f"the interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds")
    secret = dict(cur.get("secret") or {})
    if method == "snmp":
        secret = {k: v for k, v in secret.items() if k in ("community", "version", "username", "auth_proto", "auth_password", "priv_proto", "priv_password")}
        community = data.get("community")
        if community is not None and str(community) != "":
            secret["community"] = str(community)
        version = data.get("version", secret.get("version", "2c"))
        if str(version) not in ("1", "2c", "3"):
            raise MonitorError("SNMP version must be 1, 2c or 3")
        secret["version"] = str(version)
        if str(version) == "3":
            for key in ("username", "auth_proto", "priv_proto"):
                if data.get(key) is not None:
                    secret[key] = str(data[key]).strip()
            for key in ("auth_password", "priv_password"):
                if data.get(key) not in (None, ""):
                    secret[key] = str(data[key])
            if not secret.get("username"):
                raise MonitorError("give the SNMPv3 user name")
            auth, priv = secret.get("auth_proto", ""), secret.get("priv_proto", "")
            if auth and auth not in snmpv3.AUTH:
                raise MonitorError("the authentication protocol must be " + ", ".join(snmpv3.AUTH))
            if priv and priv not in snmpv3.PRIV:
                raise MonitorError("the privacy protocol must be AES or DES")
            if priv and not auth:
                raise MonitorError("encryption needs authentication as well")
            if not auth:
                secret.pop("auth_password", None)
            if not priv:
                secret.pop("priv_password", None)
            if auth and len(secret.get("auth_password", "")) < 8:
                raise MonitorError("the authentication password must be at least 8 characters")
            if priv and len(secret.get("priv_password", "")) < 8:
                raise MonitorError("the privacy password must be at least 8 characters")
            secret.pop("community", None)
        else:
            for key in ("username", "auth_proto", "auth_password", "priv_proto", "priv_password"):
                secret.pop(key, None)
            if not secret.get("community"):
                secret["community"] = "public"
    elif method == "winrm":
        secret = {k: v for k, v in secret.items() if k in ("username", "password", "auth", "verify_tls", "credential_id")}
        bound = _bound(data, secret)
        if bound:
            for k in ("username", "password"):
                secret.pop(k, None)
            secret["credential_id"] = bound
        elif "credential_id" in secret:
            secret.pop("credential_id")
        if bound:
            pass
        elif data.get("username") is not None:
            secret["username"] = str(data["username"]).strip()
        if data.get("password") not in (None, ""):
            secret["password"] = str(data["password"])
        if data.get("auth") is not None:
            if data["auth"] not in ("ntlm", "basic"):
                raise MonitorError("the login method must be NTLM or Basic")
            secret["auth"] = data["auth"]
        secret.setdefault("auth", "ntlm")
        if data.get("verify_tls") is not None:
            secret["verify_tls"] = bool(data["verify_tls"])
        secret.setdefault("verify_tls", False)
        if not bound and (not secret.get("username") or not secret.get("password")):
            raise MonitorError("give the user name and the password of a Windows account that may use remote management")
        if port == 5985 and not winrm.ALLOW_PLAIN_HTTP:
            raise MonitorError(winrm.PLAIN_HTTP_REFUSED)
        if port == 5985 and secret.get("auth") != "basic":
            raise MonitorError("over plain http only the Basic login works (NTLM needs https, port 5986)")
    else:
        secret = {k: v for k, v in secret.items() if k in ("username", "password", "private_key", "passphrase", "platform", "credential_id")}
        bound = _bound(data, secret)
        if bound:
            for k in ("username", "password", "private_key", "passphrase"):
                secret.pop(k, None)
            secret["credential_id"] = bound
        else:
            secret.pop("credential_id", None)
        if data.get("platform") is not None:
            if data["platform"] not in ("auto", "linux", "windows"):
                raise MonitorError("the system must be Automatic, Linux or Windows")
            secret["platform"] = data["platform"]
        for key in ("username", "password", "private_key", "passphrase"):
            if not bound and key in data and data[key] is not None and (str(data[key]) != "" or key == "username"):
                secret[key] = str(data[key])
        if data.get("clear_password"):
            secret.pop("password", None)
        if not bound and not secret.get("username"):
            raise MonitorError("give the user name to sign in with")
        if not bound and not secret.get("password") and not secret.get("private_key"):
            raise MonitorError("give a password or a private key")
    arp_mode = data.get("arp_mode", cur.get("arp_mode", "auto")) if method == "snmp" else "auto"
    if arp_mode not in ("auto", "on", "off"):
        raise MonitorError("reading the ARP table is automatic, on or off")
    return {"method": method, "address": address, "port": port, "interval_s": interval, "secret": secret, "arp_mode": arp_mode,
            "alerts": bool(data.get("alerts", cur.get("alerts", True))), "enabled": bool(data.get("enabled", cur.get("enabled", True)))}


def _bound(data: dict[str, Any], secret: dict[str, Any]) -> str:
    """The id of the stored login (Settings → Credentials) the monitor uses: sent now (an empty text unbinds it), or kept from before."""
    if "credential_id" in data:
        return str(data["credential_id"] or "")
    return str(secret.get("credential_id") or "")


def raw_secret(conn, row) -> dict[str, Any]:
    """What the monitor row stores (a reference to a stored login stays a reference); {} when it cannot be read."""
    raw = row["credential"] or ""
    if not raw:
        return {}
    try:
        return json.loads(vault.decrypt(conn, raw))
    except (vault.VaultError, ValueError):
        return {}


def resolve_secret(conn, method: str, secret: dict[str, Any], fetch: bool = True, device: str = "") -> dict[str, Any]:
    """The login to use: a monitor that uses a stored login gets its user name and secret from the store each time, so changing the stored login changes every monitor that uses it. {} when that login is gone.
    A login that lives in the customer's PAM is fetched at this moment (fetch=True) and kept nowhere; {} when the PAM refuses (fail closed). With fetch=False (listing a monitor) the PAM is not asked."""
    if not secret.get("credential_id"):
        return secret
    from app import credstore

    stored = credstore.peek_bound(conn, secret["credential_id"])
    if stored is None:
        return {}
    if stored.get("kind") == "pam" and not fetch:
        return {**secret, "username": stored.get("username", ""), "via_pam": True}
    if fetch and (stored.get("kind") == "pam" or stored.get("route_mode")):
        try:
            stored = credstore.use_bound(conn, secret["credential_id"], f"monitoring {method.upper()}", device) or {}
        except credstore.CredentialError as exc:
            log.warning("login for a monitor refused: %s", exc)
            return {}
    user = stored.get("username", "")
    if method == "winrm" and stored.get("domain") and "\\" not in user and "@" not in user:
        user = f"{stored['domain']}\\{user}"
    return {**secret, "username": user, **{k: stored[k] for k in ("password", "private_key", "passphrase", "route") if stored.get(k)}}


async def resolve_secret_async(conn, method: str, secret: dict[str, Any], device: str = "") -> dict[str, Any]:
    """`resolve_secret` for code that runs on the event loop: a login in the PAM is a network call, which must not hold up everything else. Only a login that lives in the
    PAM leaves the loop (with a connection of its own); everything else is read as before."""
    cred = secret.get("credential_id")
    if not cred:
        return secret
    from app import credstore

    entry = credstore.peek_bound(conn, cred)
    path = dbengine.database_path(conn)
    if entry is None or not (entry.get("kind") == "pam" or entry.get("route_mode")) or not path:
        return resolve_secret(conn, method, secret, True, device)

    def work() -> dict[str, Any]:
        own = connect(path)
        try:
            return resolve_secret(own, method, secret, True, device)
        finally:
            own.close()
    return await asyncio.to_thread(work)


async def load_secret_async(conn, row) -> dict[str, Any]:
    return await resolve_secret_async(conn, row["method"], raw_secret(conn, row), f"device {row['device_id']}")


def unreadable_text(conn, row, default: str) -> str:
    """Why `load_secret` came back empty: the PAM's own sentence when the login lives there and was refused, otherwise `default`."""
    from app import pam

    cid = raw_secret(conn, row).get("credential_id")
    status = pam.last_status(cid) if cid else None
    return f"the PAM system did not hand out the login: {status['message']}" if status and not status["ok"] else default


def load_secret(conn, row, fetch: bool = True) -> dict[str, Any]:
    """The decrypted login of a monitor row, ready to use; {} when it cannot be read (the key is missing, or the stored login it points to is gone, or the PAM refused)."""
    return resolve_secret(conn, row["method"], raw_secret(conn, row), fetch, f"device {row['device_id']}")


def get_monitor(conn, device_id: int):
    return conn.execute("SELECT * FROM host_monitors WHERE device_id = ?", (device_id,)).fetchone()


def public(conn, row) -> dict[str, Any]:
    """The monitor as the API shows it: never the secrets, only whether they are set."""
    secret = load_secret(conn, row, fetch=False)
    return {
        "id": row["id"], "device_id": row["device_id"], "method": row["method"], "source": row["source"], "address": row["address"], "port": row["port"],
        "interval_s": row["interval_s"], "alerts": bool(row["alerts"]), "enabled": bool(row["enabled"]),
        "groups": json.loads(row["groups"] or "[]"), "last_ts": row["last_ts"], "last_ok": None if row["last_ok"] is None else bool(row["last_ok"]),
        "last_error": row["last_error"], "since": row["since"],
        "has_community": bool(secret.get("community")) if row["method"] == "snmp" else None,
        "version": secret.get("version", "2c") if row["method"] == "snmp" else None,
        "username": secret.get("username") if row["method"] in ("ssh", "snmp", "winrm") else None,
        "auth_proto": secret.get("auth_proto", "") if row["method"] == "snmp" else None,
        "priv_proto": secret.get("priv_proto", "") if row["method"] == "snmp" else None,
        "has_auth_password": bool(secret.get("auth_password")) if row["method"] == "snmp" else None,
        "has_priv_password": bool(secret.get("priv_password")) if row["method"] == "snmp" else None,
        "has_password": bool(secret.get("password") or secret.get("via_pam")) if row["method"] in ("ssh", "winrm") else None,
        "has_private_key": bool(secret.get("private_key")) if row["method"] == "ssh" else None,
        "platform": secret.get("platform", "auto") if row["method"] == "ssh" else None,
        "auth": secret.get("auth", "ntlm") if row["method"] == "winrm" else None,
        "verify_tls": bool(secret.get("verify_tls")) if row["method"] == "winrm" else None,
        "secret_unreadable": bool(row["credential"]) and not secret,
        "credential_id": raw_secret(conn, row).get("credential_id") or None,
        "arp_mode": row["arp_mode"] if row["method"] == "snmp" else None,
        "arp_entries": arpcache.entries_of(conn, row["device_id"]) if row["method"] == "snmp" else None,
    }


def save_monitor(conn, device_id: int, data: dict[str, Any], groups: list[str] | None = None) -> dict[str, Any]:
    row = get_monitor(conn, device_id)
    cur = None
    if row is not None:
        cur = {"method": row["method"], "address": row["address"], "port": row["port"], "interval_s": row["interval_s"],
               "alerts": bool(row["alerts"]), "enabled": bool(row["enabled"]), "secret": raw_secret(conn, row), "arp_mode": row["arp_mode"]}
        if data.get("method") not in (None, row["method"]):
            cur["secret"] = {}                       # another method: the old login does not apply
    d = validate(data, cur)
    credential = vault.encrypt(conn, json.dumps(d["secret"]))
    if row is None:
        conn.execute(
            "INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created, arp_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (device_id, d["method"], d["address"], d["port"], credential, d["interval_s"], json.dumps(groups or []), int(d["alerts"]), int(d["enabled"]), utcnow(), d["arp_mode"]))
    else:
        changed = (d["method"], d["address"], d["port"]) != (row["method"], row["address"], row["port"])
        conn.execute(
            "UPDATE host_monitors SET method=?, address=?, port=?, credential=?, interval_s=?, alerts=?, enabled=?, arp_mode=?"
            + (", groups=?, last_ts=NULL, last_ok=NULL, last_error=NULL, since=NULL" if changed else "") + " WHERE device_id=?",
            (d["method"], d["address"], d["port"], credential, d["interval_s"], int(d["alerts"]), int(d["enabled"]), d["arp_mode"])
            + ((json.dumps(groups or []),) if changed else ()) + (device_id,))
    conn.commit()
    return public(conn, get_monitor(conn, device_id))


# ----------------------------------------------------------------------------- newest readings
def latest_readings(store, device_id: int, series: list[dict] | None = None) -> dict[str, Any]:
    """The newest reading of each kind for a device. A page that lists many devices passes `series` (from store.metrics_of_many) to ask the store once."""
    out: dict[str, Any] = {"cpu": None, "mem": None, "disk": None, "disk_label": None, "temp": None, "battery": None, "uptime": None, "rx": None, "tx": None,
                           "supply": None, "supply_label": None}
    if store is None:
        return out
    now = time.time()
    worst = None
    rx = tx = 0.0
    seen_net = False
    for s in (series if series is not None else store.metrics_of("device", device_id)):
        if s["last"] is None or s["last_ts"] is None or now - s["last_ts"] > 3600:
            continue
        m = s["metric"]
        if m == "cpu_pct":
            out["cpu"] = s["last"]
        elif m == "mem_pct":
            out["mem"] = s["last"]
        elif m == "disk_pct" and (worst is None or s["last"] > worst[0]):
            worst = (s["last"], s["label"])
        elif m == "supply_pct" and (out["supply"] is None or s["last"] < out["supply"]):
            out["supply"], out["supply_label"] = s["last"], s["label"]
        elif m == "temp_c" and (out["temp"] is None or s["last"] > out["temp"]):
            out["temp"] = s["last"]
        elif m == "battery_pct":
            out["battery"] = s["last"]
        elif m == "uptime_s":
            out["uptime"] = s["last"]
        elif m == "net_rx_bps":
            rx += s["last"]
            seen_net = True
        elif m == "net_tx_bps":
            tx += s["last"]
    if worst:
        out["disk"], out["disk_label"] = worst
    if seen_net:
        out["rx"], out["tx"] = rx, tx
    return out


# ----------------------------------------------------------------------------- reading
async def read(method: str, address: str, port: int, secret: dict[str, Any], groups: list[str] | None, state: dict,
               known_fingerprint: str | None = None, now: float | None = None) -> tuple[list[tuple], list[str], str | None]:
    """One reading: (points, groups found, SSH host key fingerprint). Raises MonitorError with a sentence for the user."""
    now = now if now is not None else time.time()
    if method == "snmp":
        def work():
            agent = make_agent(address, port, secret)
            return snmp.collect(agent, groups or None, state, now)

        try:
            points, found = await asyncio.to_thread(work)
        except snmp.SnmpError as exc:
            raise MonitorError(str(exc)) from None
        if not points and not found:
            raise MonitorError("the device answered but reported nothing Netlens can use (is SNMP switched on, and is this the right community?)")
        return points, found, None
    if method == "winrm":
        def work():
            session = winrm.Session(address, port, port != 5985, secret.get("username", ""), secret.get("password", ""), secret.get("auth", "ntlm"),
                                    bool(secret.get("verify_tls")), timeout=20)
            try:
                return session.run_powershell(ssh.WIN_SCRIPT)
            finally:
                session.close()          # also after a refused login: the connection must not stay open

        try:
            out, err, _code = await asyncio.to_thread(work)
        except winrm.WinrmError as exc:
            raise MonitorError(str(exc)) from None
        try:
            points, found = ssh.parse_windows(out, state, now)
        except ssh.SshError as exc:
            # say what came back, so a permission problem or a PowerShell restriction can be recognised
            seen = re.sub(r"\s+", " ", out or "").strip()[:160]
            detail = winrm.powershell_error(err) or (f"the script printed: {seen}" if seen else "the script printed nothing")
            raise MonitorError(f"{exc}: {detail}") from None
        if not points and not found:
            raise MonitorError("the host answered but gave no readings")
        return points, found, None
    try:
        platform = secret.get("platform", "auto")
        if platform == "auto":
            platform = state.get("platform", "auto")
        points, found, fingerprint = [], [], None
        if platform in ("auto", "linux"):
            try:
                out, fingerprint = await ssh.run(address, port, secret.get("username", ""), secret.get("password"), secret.get("private_key"),
                                                 secret.get("passphrase"), known_fingerprint, route=secret.get("route"))
                points, found = ssh.parse(out, state, now)
                if found:
                    state["platform"] = "linux"
            except ssh.SshError:
                if platform == "linux":
                    raise
        if not found and platform in ("auto", "windows"):          # not a /proc system: try it as Windows (OpenSSH + PowerShell)
            out, _status, fingerprint = await ssh.run_command(address, port, secret.get("username", ""), secret.get("password"), secret.get("private_key"),
                                                              secret.get("passphrase"), ssh.WIN_COMMAND, known_fingerprint, timeout=30.0, route=secret.get("route"))
            points, found = ssh.parse_windows(out, state, now)
            if found:
                state["platform"] = "windows"
    except ssh.SshError as exc:
        raise MonitorError(str(exc)) from None
    if not points and not found:
        raise MonitorError("the host answered but gave no readings (is it a Linux system?)")
    return points, found, fingerprint


def record(conn, device_id: int, points: list[tuple], now: float | None = None) -> None:
    store = tsdb.for_conn(conn)
    if store is None or not points:
        return
    store.record([("device", device_id, metric, value, label, unit) for metric, label, value, unit in points], ts=int(now if now is not None else time.time()))


PROCESS_RE = __import__("re").compile(r"^[A-Za-z0-9_.@:+][A-Za-z0-9_.@:+-]{0,63}$")      # never starts with "-": it would be taken for an option


async def check_process(db_path: str, device_id: int | None, name: str, timeout: float = 10.0) -> tuple[bool, str, float | None]:
    """Is a program or service running on a device that has a health monitor? Returns (running, detail, milliseconds)."""
    if device_id is None:
        return False, "choose the device this check belongs to", None
    if not PROCESS_RE.match(name):
        return False, "the process name may only hold letters, digits and . _ @ : + -", None
    conn = connect(db_path)
    try:
        row = get_monitor(conn, device_id)
        secret = await load_secret_async(conn, row) if row is not None else {}
        why = unreadable_text(conn, row, "the stored login cannot be read, enter it again on the device page") if row is not None and not secret else ""
        known = None
        if row is not None and row["method"] == "ssh":
            from app.terminal.hostkeys import get_fingerprint

            known = get_fingerprint(conn, device_id)
    finally:
        conn.close()
    if row is None:
        return False, "this device has no health monitoring; set it up on the device page first", None
    if not secret:
        return False, why, None
    start = time.monotonic()
    try:
        if row["method"] == "winrm":
            bare = name[:-4] if name.lower().endswith(".exe") else name
            script = (f"if ((Get-Process -Name '{bare}' -ErrorAction SilentlyContinue) -or (Get-Service -Name '{bare}' -ErrorAction SilentlyContinue | "
                      "Where-Object Status -eq 'Running')) {exit 0} else {exit 1}")

            def probe():
                session = winrm.Session(row["address"], row["port"], row["port"] != 5985, secret.get("username", ""), secret.get("password", ""),
                                        secret.get("auth", "ntlm"), bool(secret.get("verify_tls")), timeout=min(timeout, 15.0))
                try:
                    return session.run_powershell(script)
                finally:
                    session.close()

            _out, _err, code = await asyncio.to_thread(probe)
            running = code == 0
            detail = "running" if running else "not running"
        elif row["method"] == "snmp":
            def work():
                agent = make_agent(row["address"], row["port"], secret, timeout=min(timeout, 4.0))
                return [snmp._text(v, 120) for _suffix, v in agent.walk(snmp.HR_SW_RUN_NAME)]
            names = await asyncio.to_thread(work)
            wanted = name.lower().removesuffix(".exe")
            running = any(n.lower().removesuffix(".exe") == wanted for n in names)
            detail = "running" if running else ("not in the list of running programs" if names else "the device reports no running programs over SNMP")
        else:
            quoted = name  # validated above: nothing a shell treats specially
            state_platform = _STATES.get(row["id"], {}).get("platform")
            windows = secret.get("platform", "auto") == "windows" or (secret.get("platform", "auto") == "auto" and state_platform == "windows")
            if windows:
                bare = quoted[:-4] if quoted.lower().endswith(".exe") else quoted
                command = ssh.powershell(f"if ((Get-Process -Name '{bare}' -ErrorAction SilentlyContinue) -or (Get-Service -Name '{bare}' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')) {{exit 0}} else {{exit 1}}")
            else:
                command = f"sh -c 'pgrep -x {quoted} >/dev/null 2>&1 || systemctl is-active --quiet {quoted} >/dev/null 2>&1'"
            _out, status, _fp = await ssh.run_command(row["address"], row["port"], secret.get("username", ""), secret.get("password"),
                                                      secret.get("private_key"), secret.get("passphrase"), command, known, timeout, route=secret.get("route"))
            running = status == 0
            detail = "running" if running else "not running"
    except (snmp.SnmpError, ssh.SshError, winrm.WinrmError) as exc:
        return False, str(exc)[:200], None
    return running, detail, round((time.monotonic() - start) * 1000, 1)


# ----------------------------------------------------------------------------- alerts
def _describe(rule: dict[str, Any], metric: str, label: str, value: float, level: str, device: str) -> str:
    unit = rule["unit"]
    shown = f"{value:.0f}{unit}" if unit else f"{value:g}"
    where = f" on {label}" if label else ""
    if metric == "on_battery":
        return f"{device}: the UPS is running on battery power"
    if metric == "storage_status":
        what = label or "storage"
        if level == "ok":
            return f"{device}: {what} is healthy again"
        return f"{device}: {what} is {'degraded or needs attention (a disk may be failing or rebuilding)' if level == 'warning' else 'FAILED'}"
    if metric == "sensor_fault":
        what = label or "a hardware sensor"
        if level == "ok":
            return f"{device}: {what} is fine again"
        return f"{device}: {what} {'has stopped (a fan is not turning)' if level == 'critical' else 'reports a failure (a fan or power supply)'}"
    if metric == "if_up":
        return f"{device}: the link of {label or 'an interface'} is up again" if level == "ok" else f"{device}: the link of {label or 'an interface'} is down"
    if metric == "service_stopped":
        what = f"the service {label}" if label else "a service"
        return f"{device}: {what} is running again" if level == "ok" else f"{device}: {what} has stopped with an error"
    if level == "ok":
        return f"{device}: {rule['title'].lower()}{where} is back to normal ({shown})"
    limit = rule["crit"] if level == "critical" else rule["warn"]
    return f"{device}: {rule['title'].lower()}{where} is {shown} (limit {limit:g}{unit})"


def evaluate(conn, monitor_id: int, device_id: int, device_name: str, points: list[tuple], now: str | None = None) -> list[str]:
    """Move each reading through its level (ok / warning / critical). Returns the events that were raised."""
    now = now or utcnow()
    the_rules = rules(conn, device_id)
    raised: list[str] = []
    for metric, label, value, _unit in points:
        rule = the_rules.get(metric)
        if rule is None or not rule["enabled"]:
            continue
        if rule.get("only") and label.lower() not in {x.lower() for x in rule["only"]}:          # the owner named the interfaces that matter
            continue
        level = level_of(rule, value)
        row = conn.execute("SELECT * FROM metric_state WHERE monitor_id = ? AND metric = ? AND label = ?", (monitor_id, metric, label)).fetchone()
        if row is None:
            conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value, pending, pending_n) VALUES (?,?,?,?,?,?,NULL,0)",
                         (monitor_id, metric, label, level, now, value))
            if level != "ok":     # a problem that exists the first time we look is a problem: tell about it
                kind = "metric_critical" if level == "critical" else "metric_warning"
                add_event(conn, kind, _describe(rule, metric, label, value, level, device_name), device_id=device_id, now=now, subject=f"metric:{device_id}:{metric}:{label}")
                raised.append(kind)
            continue
        if level == row["level"]:
            conn.execute("UPDATE metric_state SET value = ?, pending = NULL, pending_n = 0 WHERE monitor_id = ? AND metric = ? AND label = ?",
                         (value, monitor_id, metric, label))
            continue
        n = (row["pending_n"] + 1) if row["pending"] == level else 1
        if n < int(rule.get("confirm", 1)):
            conn.execute("UPDATE metric_state SET value = ?, pending = ?, pending_n = ? WHERE monitor_id = ? AND metric = ? AND label = ?",
                         (value, level, n, monitor_id, metric, label))
            continue
        conn.execute("UPDATE metric_state SET level = ?, since = ?, value = ?, pending = NULL, pending_n = 0 WHERE monitor_id = ? AND metric = ? AND label = ?",
                     (level, now, value, monitor_id, metric, label))
        kind = {"ok": "metric_ok", "warning": "metric_warning", "critical": "metric_critical"}[level]
        add_event(conn, kind, _describe(rule, metric, label, value, level, device_name), device_id=device_id, now=now, subject=f"metric:{device_id}:{metric}:{label}")
        raised.append(kind)
    # a service that is no longer in the list of stopped ones runs again (the empty-label reading says the list was read)
    rule = the_rules.get("service_stopped")
    if rule and rule["enabled"] and any(m == "service_stopped" and not lbl for m, lbl, _v, _u in points):
        present = {lbl for m, lbl, _v, _u in points if m == "service_stopped"}
        for row in conn.execute("SELECT label FROM metric_state WHERE monitor_id = ? AND metric = 'service_stopped' AND label != '' AND level != 'ok'", (monitor_id,)).fetchall():
            if row["label"] in present:
                continue
            conn.execute("UPDATE metric_state SET level = 'ok', since = ?, value = 0, pending = NULL, pending_n = 0 WHERE monitor_id = ? AND metric = 'service_stopped' AND label = ?",
                         (now, monitor_id, row["label"]))
            add_event(conn, "metric_ok", _describe(rule, "service_stopped", row["label"], 0.0, "ok", device_name), device_id=device_id, now=now,
                      subject=f"metric:{device_id}:service_stopped:{row['label']}")
            raised.append("metric_ok")
    # a reading that is no longer taken cannot stay a problem: a container used to report the temperature of its host and no longer does, so the old warning would
    # never clear. Only when the rest of the read worked (processor or memory present), so a failed read does not wipe the state.
    if points and not any(m == "temp_c" for m, _l, _v, _u in points) and any(m in ("cpu_pct", "mem_pct") for m, _l, _v, _u in points):
        conn.execute("UPDATE metric_state SET level = 'ok', since = ?, pending = NULL, pending_n = 0 WHERE monitor_id = ? AND metric = 'temp_c' AND level != 'ok'", (now, monitor_id))
    conn.commit()
    return raised


def problems(conn, include_snoozed: bool = True) -> list[dict[str, Any]]:
    """Readings that are beyond a limit now (for the dashboard and the health page). Each carries `snooze` (its subject) and
    `snoozed_until` (None unless someone said "I know"); `include_snoozed=False` leaves those out."""
    from app import snooze

    asleep = snooze.active(conn)
    general = rules(conn)
    per_device: dict[int, dict] = {}
    out = []
    for r in conn.execute(
        "SELECT s.metric, s.label, s.level, s.since, s.value, m.device_id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name "
        "FROM metric_state s JOIN host_monitors m ON m.id = s.monitor_id JOIN devices d ON d.id = m.device_id "
        "WHERE s.level != 'ok' AND m.alerts = 1 AND m.enabled = 1 ORDER BY s.level DESC, name"):
        the_rules = per_device.get(r["device_id"])
        if the_rules is None:
            the_rules = per_device[r["device_id"]] = rules(conn, r["device_id"]) if device_overrides(conn, r["device_id"]) else general
        rule = the_rules.get(r["metric"])
        if rule and rule.get("enabled", True):
            key = f"metric:{r['device_id']}:{r['metric']}:{r['label']}"
            sleeping = asleep.get(key)
            if sleeping and not include_snoozed:
                continue
            out.append({"device_id": r["device_id"], "device": r["name"], "metric": r["metric"], "label": r["label"], "level": r["level"], "since": r["since"],
                        "value": r["value"], "title": rule["title"], "unit": rule["unit"], "snooze": key, "snoozed_until": sleeping["until"] if sleeping else None})
    return out


# ----------------------------------------------------------------------------- the background job
_STATES: dict[int, dict] = {}        # monitor id -> counters kept between rounds (traffic, processor time)


def _due(conn, now_ts: float) -> list[Any]:
    out = []
    for row in conn.execute("SELECT * FROM host_monitors WHERE enabled = 1 AND method NOT IN ('plugin', 'agent')"):          # a plugin feeds its own rows (app/plugins/enrich.py), an agent pushes its own (app/ingest)
        if row["last_ts"] is None:
            out.append(row)
            continue
        try:
            last = datetime.strptime(row["last_ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            out.append(row)
            continue
        if now_ts - last >= row["interval_s"]:
            out.append(row)
    return out


ARP_EVERY = 300           # seconds between two reads of a router's ARP table (it can hold thousands of rows)


def reads_arp(conn, row) -> bool:
    """Does this SNMP monitor read the ARP table of its device? Automatic for a router or a switch (they know the MAC addresses of the hosts on their networks)."""
    mode = row["arp_mode"] if "arp_mode" in row.keys() else "auto"
    if mode != "auto":
        return mode == "on"
    d = conn.execute("SELECT type_override, device_type FROM devices WHERE id = ?", (row["device_id"],)).fetchone()
    return bool(d) and (d["type_override"] or d["device_type"]) in arpcache.AUTO_TYPES


async def _learn_arp(conn, row, secret: dict[str, Any], state: dict, now_ts: float, stamp: str) -> None:
    """Keep the ARP table of the device (app/arpcache.py), now and then. A failure here never fails the monitor."""
    if now_ts - state.get("arp_ts", 0) < ARP_EVERY or not reads_arp(conn, row):
        return
    state["arp_ts"] = now_ts
    try:
        def work():
            return snmp.read_arp(make_agent(row["address"], row["port"], secret))

        entries = await asyncio.to_thread(work)
    except (snmp.SnmpError, OSError):
        log.debug("the ARP table of %s could not be read", row["address"], exc_info=True)
        return
    arpcache.learn(conn, row["device_id"], entries, stamp)


async def run_monitor(db_path: str, monitor_id: int, now_ts: float | None = None) -> dict[str, Any]:
    """Read one monitor now and store the outcome. Returns {"ok", "error", "events"}."""
    now_ts = now_ts if now_ts is not None else time.time()
    stamp = datetime.fromtimestamp(now_ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM host_monitors WHERE id = ?", (monitor_id,)).fetchone()
        if row is None:
            return {"ok": False, "error": "gone", "events": []}
        secret = await load_secret_async(conn, row)
        device = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (row["device_id"],)).fetchone()
        name = device["n"] if device else f"device {row['device_id']}"
        groups = json.loads(row["groups"] or "[]")
        known = None
        if row["method"] == "ssh":
            from app.terminal.hostkeys import get_fingerprint

            known = get_fingerprint(conn, row["device_id"])
        state = _STATES.setdefault(monitor_id, {})
        locked = None
        if row["method"] in ("ssh", "winrm"):
            from app.hostprobe import service as host_probes

            state.pop("via", None)
            locked = await host_probes.locked_readings(conn, row, state, now_ts)          # a host with the probe installed is asked through the locked-down account
        if locked is not None:
            points, found, fingerprint = locked
            error = None
        elif not secret:
            error = unreadable_text(conn, row, "the stored login cannot be read (the encryption key is missing), enter it again")
            points, found, fingerprint = [], [], None
        else:
            try:
                points, found, fingerprint = await read(row["method"], row["address"], row["port"], secret, groups or None, state, known, now_ts)
                state["via"] = "login"
                error = None
            except MonitorError as exc:
                points, found, fingerprint, error = [], [], None, str(exc)
        raised: list[str] = []
        if error is None:
            if fingerprint and row["method"] == "ssh":
                from app.terminal.hostkeys import remember_fingerprint

                remember_fingerprint(conn, row["device_id"], fingerprint, stamp)
            record(conn, row["device_id"], points, now_ts)
            if not groups and found:
                groups = found
                conn.execute("UPDATE host_monitors SET groups = ? WHERE id = ?", (json.dumps(found), monitor_id))
            if row["alerts"]:
                raised = evaluate(conn, monitor_id, row["device_id"], name, points, stamp)
        if error is None and row["method"] == "snmp":
            await _learn_arp(conn, row, secret, state, now_ts, stamp)
        since = row["since"] if row["last_ok"] == (1 if error is None else 0) and row["since"] else stamp
        conn.execute("UPDATE host_monitors SET last_ts = ?, last_ok = ?, last_error = ?, since = ? WHERE id = ?",
                     (stamp, 1 if error is None else 0, error, since, monitor_id))
        conn.commit()
        return {"ok": error is None, "error": error, "events": raised, "points": len(points)}
    finally:
        conn.close()


async def run_due(db_path: str, now_ts: float | None = None) -> int:
    now_ts = now_ts if now_ts is not None else time.time()
    conn = connect(db_path)
    try:
        ids = [r["id"] for r in _due(conn, now_ts)]
    finally:
        conn.close()
    if not ids:
        return 0
    gate = asyncio.Semaphore(MAX_CONCURRENT)
    raised = False

    async def one(monitor_id: int) -> None:
        nonlocal raised
        async with gate:
            try:
                result = await run_monitor(db_path, monitor_id, now_ts)
            except Exception:  # noqa: BLE001 - one broken monitor must not stop the others
                log.exception("host monitor %s crashed", monitor_id)
                return
        if result.get("events"):
            raised = True

    await asyncio.gather(*(one(i) for i in ids))
    if raised:
        from app.notify.channels import process_channels

        await process_channels(db_path)
    return len(ids)


async def loop(db_path: str, interval: float = 10.0) -> None:
    """Background task: read the monitors that are due, a few at a time."""
    await asyncio.sleep(5)
    while True:
        try:
            await run_due(db_path)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("host monitor loop failed")
        await asyncio.sleep(interval)
