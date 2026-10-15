"""Configuration pushed from the central Netlens to a remote site: service checks and health monitors.

The central side keeps, per remote site, the list of checks and monitors (logins encrypted). The remote Netlens receives it in
the reply to its report, but only when it ticked "Accept configuration from the central Netlens"; what it applies is marked
as coming from the central Netlens and cannot be edited there. Everything is validated again on the remote side with the same
rules as for a user.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app import services
from app.db import get_setting, set_setting
from app.hostmetrics import service as hm

MAX_ITEMS = 100
KEY_RE = re.compile(r"^[A-Za-z0-9:._-]{1,80}$")
SECRET_FIELDS = ("community", "password", "private_key", "passphrase", "auth_password", "priv_password")
MONITOR_FIELDS = ("method", "address", "port", "interval_s", "alerts", "enabled", "version", "username", "auth_proto", "priv_proto", "platform")


class ConfigError(ValueError):
    pass


def _key(probe_id: int) -> str:
    return f"probe.config.{probe_id}"


# ----------------------------------------------------------------------------- the central side
def load(conn: sqlite3.Connection, probe_id: int) -> dict[str, Any]:
    try:
        data = json.loads(get_setting(conn, _key(probe_id)) or "{}")
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {"rev": int(data.get("rev") or 0) if isinstance(data.get("rev"), int) else 0,
            "services": [s for s in data.get("services", []) if isinstance(s, dict)], "monitors": [m for m in data.get("monitors", []) if isinstance(m, dict)]}


def public(cfg: dict[str, Any]) -> dict[str, Any]:
    """For the browser: never the passwords, only whether they are set."""
    monitors = []
    for m in cfg["monitors"]:
        item = {k: v for k, v in m.items() if k not in SECRET_FIELDS}
        for f in SECRET_FIELDS:
            item[f"has_{f}"] = bool(m.get(f))
        monitors.append(item)
    return {"rev": cfg["rev"], "services": cfg["services"], "monitors": monitors}


def save(conn: sqlite3.Connection, probe_id: int, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the whole list the user sent and store it as the next revision. A login that is not sent again is kept."""
    if not isinstance(data, dict):
        raise ConfigError("the configuration must be an object")
    old = load(conn, probe_id)
    old_monitors = {m.get("device_key"): m for m in old["monitors"]}
    svc_in, mon_in = data.get("services", []), data.get("monitors", [])
    if not isinstance(svc_in, list) or not isinstance(mon_in, list):
        raise ConfigError("services and monitors must be lists")
    if len(svc_in) > MAX_ITEMS or len(mon_in) > MAX_ITEMS:
        raise ConfigError(f"at most {MAX_ITEMS} service checks and {MAX_ITEMS} monitors per site")
    out_services, seen = [], set()
    for item in svc_in:
        if not isinstance(item, dict):
            raise ConfigError("a service check must be an object")
        try:
            clean = services.validate_check({**item, "device_id": None})
        except services.CheckError as exc:
            raise ConfigError(f"{item.get('name') or 'service check'}: {exc}") from None
        if clean["kind"] == "process":
            raise ConfigError(f"{clean['name']}: a process check belongs to a monitored device and cannot be set up from here")
        key = str(item.get("key") or "")
        if not KEY_RE.match(key):
            key = "svc-" + re.sub(r"[^A-Za-z0-9]+", "-", clean["name"].lower()).strip("-")[:60]
        if key in seen:
            raise ConfigError(f"{clean['name']}: two checks have the same name")
        seen.add(key)
        out_services.append({"key": key, **{k: clean[k] for k in ("name", "kind", "host", "port", "path", "expect", "interval_s", "timeout_s")}, "enabled": bool(clean["enabled"])})
    out_monitors, seen_dev = [], set()
    for item in mon_in:
        if not isinstance(item, dict):
            raise ConfigError("a monitor must be an object")
        dkey = str(item.get("device_key") or "")
        if not dkey or len(dkey) > 80:
            raise ConfigError("a monitor needs the device it belongs to")
        if dkey in seen_dev:
            raise ConfigError("a device can have one monitor")
        seen_dev.add(dkey)
        previous = old_monitors.get(dkey) or {}
        merged = {k: v for k, v in item.items() if k in MONITOR_FIELDS or k in SECRET_FIELDS}
        for f in SECRET_FIELDS:                       # not sent again: keep what is stored (only when the method did not change)
            if merged.get(f) in (None, "") and previous.get("method") == merged.get("method", previous.get("method")) and previous.get(f):
                merged[f] = previous[f]
        cur = None
        try:
            checked = hm.validate({**merged, "address": merged.get("address") or "127.0.0.1"}, cur)
        except hm.MonitorError as exc:
            raise ConfigError(f"{dkey}: {exc}") from None
        entry = {"device_key": dkey, "method": checked["method"], "address": merged.get("address") or "", "port": merged.get("port"),
                 "interval_s": checked["interval_s"], "alerts": checked["alerts"], "enabled": checked["enabled"], **checked["secret"]}
        out_monitors.append(entry)
    cfg = {"rev": old["rev"] + 1, "services": out_services, "monitors": out_monitors}
    set_setting(conn, _key(probe_id), json.dumps(cfg))
    return cfg


def for_probe(conn: sqlite3.Connection, probe_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    """What to put in the reply to a report: the configuration when the site wants it and has another revision."""
    if not payload.get("accepts_config"):
        return None
    cfg = load(conn, probe_id)
    have = payload.get("config_rev")
    have = have if isinstance(have, int) and not isinstance(have, bool) else 0
    if cfg["rev"] == have:
        return None
    return cfg


# ----------------------------------------------------------------------------- the remote side
def apply(conn: sqlite3.Connection, cfg: dict[str, Any]) -> dict[str, Any]:
    """Make this installation's centrally managed checks and monitors match `cfg`. Returns what was done."""
    result: dict[str, Any] = {"services": 0, "monitors": 0, "skipped": []}
    wanted: dict[str, dict] = {}
    for item in (cfg.get("services") or [])[:MAX_ITEMS]:
        if not isinstance(item, dict) or not KEY_RE.match(str(item.get("key") or "")):
            continue
        try:
            clean = services.validate_check({**item, "device_id": None})
        except services.CheckError as exc:
            result["skipped"].append(f"{item.get('name') or item.get('key')}: {exc}")
            continue
        if clean["kind"] == "process":
            continue
        wanted[f"central:{item['key']}"] = clean
    existing = {r["source"]: r for r in conn.execute("SELECT * FROM service_checks WHERE source LIKE 'central:%'")}
    for source, clean in wanted.items():
        row = existing.get(source)
        if row is None:
            conn.execute(
                "INSERT INTO service_checks (device_id, name, kind, host, port, path, expect, interval_s, timeout_s, enabled, created, source) VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)",
                (clean["name"], clean["kind"], clean["host"], clean["port"], clean["path"], clean["expect"], clean["interval_s"], clean["timeout_s"], clean["enabled"],
                 __import__("app.db", fromlist=["utcnow"]).utcnow(), source))
        else:
            changed = any(clean[k] != row[k] for k in ("kind", "host", "port", "path", "expect"))
            conn.execute(
                "UPDATE service_checks SET name=?, kind=?, host=?, port=?, path=?, expect=?, interval_s=?, timeout_s=?, enabled=?"
                + (", last_ts=NULL, last_up=NULL, last_ms=NULL, last_detail=NULL, since=NULL" if changed else "") + " WHERE id=?",
                (clean["name"], clean["kind"], clean["host"], clean["port"], clean["path"], clean["expect"], clean["interval_s"], clean["timeout_s"], clean["enabled"], row["id"]))
        result["services"] += 1
    for source, row in existing.items():
        if source not in wanted:
            conn.execute("DELETE FROM service_checks WHERE id = ?", (row["id"],))
    # monitors
    keep_devices: set[int] = set()
    for item in (cfg.get("monitors") or [])[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        dkey = str(item.get("device_key") or "")
        device = None
        if dkey.startswith("ip:"):
            device = conn.execute("SELECT id, primary_ip FROM devices WHERE primary_ip = ?", (dkey[3:],)).fetchone()
        elif dkey:
            device = conn.execute("SELECT id, primary_ip FROM devices WHERE mac = ?", (dkey,)).fetchone()
        if device is None:
            result["skipped"].append(f"{dkey}: this device is not known here (yet)")
            continue
        mine = conn.execute("SELECT id, source FROM host_monitors WHERE device_id = ?", (device["id"],)).fetchone()
        if mine is not None and mine["source"] != "central":
            result["skipped"].append(f"{dkey}: it already has a monitor that was set up here")
            continue
        data = {k: v for k, v in item.items() if k != "device_key"}
        data.setdefault("address", device["primary_ip"])
        data["address"] = data.get("address") or device["primary_ip"]
        try:
            hm.save_monitor(conn, device["id"], data)
        except hm.MonitorError as exc:
            result["skipped"].append(f"{dkey}: {exc}")
            continue
        conn.execute("UPDATE host_monitors SET source = 'central' WHERE device_id = ?", (device["id"],))
        keep_devices.add(device["id"])
        result["monitors"] += 1
    for row in conn.execute("SELECT id, device_id FROM host_monitors WHERE source = 'central'").fetchall():
        if row["device_id"] not in keep_devices:
            conn.execute("DELETE FROM metric_state WHERE monitor_id = ?", (row["id"],))
            conn.execute("DELETE FROM host_monitors WHERE id = ?", (row["id"],))
            hm._STATES.pop(row["id"], None)
    conn.commit()
    return result
