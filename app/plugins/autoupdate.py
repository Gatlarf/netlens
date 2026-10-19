"""Automatic plugin updates (per plugin, off by default) and the check for plugins that a new Netlens version may have broken.

Auto-update installs the newest release the index offers for a plugin that came from the index, with the same checks as a manual update
(checksum, package rules). It only goes to a release that has been *reviewed* or *verified*, never to a community release, never to a version
the user rolled back from, and never for a built-in or uploaded plugin. Settings and the on/off state of the plugin are kept. Every update
and every refusal is written to the event log.

The compatibility check compares the running Netlens with the one the plugins were last seen working under: after an upgrade it lists the
plugins that cannot be loaded, that the index says do not support this Netlens, or that started failing since the upgrade, together with a
newer version that fixes it (if there is one) and the Netlens version to go back to.
"""

from __future__ import annotations

from typing import Any

import json
import logging
from pathlib import Path

from app.db import add_event, get_setting, set_setting, utcnow
from app.plugins import index as idx
from app.plugins import index_install as inst
from app.plugins import registry
from app.plugins.service import get_status
from app.version import VERSION

log = logging.getLogger(__name__)

TRUSTED = ("reviewed", "verified")
LAST_VERSION_KEY = "netlens.plugin_compat.version"
UPGRADE_KEY = "netlens.plugin_compat.upgrade"
DISMISSED_KEY = "netlens.plugin_compat.dismissed"


def _key(plugin_id: str) -> str:
    return f"plugin.{plugin_id}.autoupdate"


def _load(conn, key: str) -> dict:
    try:
        data = json.loads(get_setting(conn, key) or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def settings(conn, plugin_id: str) -> dict:
    """{"enabled": bool, "skip": version the user rolled back from or None, "last": {...} what the last automatic update did}."""
    data = _load(conn, _key(plugin_id))
    return {"enabled": bool(data.get("enabled")), "skip": data.get("skip"), "last": data.get("last")}


def _save(conn, plugin_id: str, **changes) -> dict:
    data = {**settings(conn, plugin_id), **changes}
    set_setting(conn, _key(plugin_id), json.dumps(data))
    return data


def set_enabled(conn, plugin_id: str, enabled: bool) -> dict:
    return _save(conn, plugin_id, enabled=bool(enabled))


def skip_version(conn, plugin_id: str, version: str) -> None:
    """After a roll-back: do not update to this version (or older) automatically again."""
    _save(conn, plugin_id, skip=version)


def enabled_map(conn) -> dict[str, bool]:
    rows = conn.execute("SELECT key, value FROM settings WHERE key LIKE 'plugin.%.autoupdate'").fetchall()
    out = {}
    for row in rows:
        try:
            out[row["key"][len("plugin."):-len(".autoupdate")]] = bool(json.loads(row["value"]).get("enabled"))
        except (ValueError, AttributeError):
            continue
    return out


def candidate(entry: dict, have: dict, state: dict, netlens_version: str = VERSION) -> tuple[dict | None, str | None]:
    """(release to install, why not). `have` is the installed-map row of the plugin."""
    release, reason = idx.pick_release(entry, netlens_version)
    if release is None:
        return None, reason
    if not idx.is_newer(release["version"], have["version"]):
        return None, None
    if state.get("skip") and not idx.is_newer(release["version"], state["skip"]):
        return None, f"{release['version']} was rolled back and is not installed again automatically"
    if release["review"]["level"] not in TRUSTED:
        return None, f"{release['version']} has not been reviewed, so it is not installed automatically"
    return release, None


def run(conn, data_dir: Path | str, *, getter=None, netlens_version: str = VERSION) -> list[dict]:
    """Update every plugin that has auto-update switched on. Returns what was done: [{"id", "from", "to"}] and [{"id", "error"}]."""
    wanted = [pid for pid, on in enabled_map(conn).items() if on]
    if not wanted:
        return []
    index = idx.get_index(conn, offline=True)
    entries = {e["id"]: e for e in index["entries"]}
    installed = inst.installed_map(conn, registry.discover(data_dir), data_dir)
    done = []
    for pid in sorted(wanted):
        entry, have = entries.get(pid), installed.get(pid)
        if entry is None or have is None or have["builtin"]:
            continue
        info = inst.provenance(conn, pid) or {}
        if info.get("source") not in ("index", "rollback"):
            continue                                          # an uploaded plugin is the user's own code: never replaced behind their back
        state = settings(conn, pid)
        release, why = candidate(entry, have, state, netlens_version)
        if release is None:
            if why and (state.get("last") or {}).get("refused") != why:
                _save(conn, pid, last={"at": utcnow(), "refused": why})
                add_event(conn, "plugin_update_skipped", f"{entry['name']}: {why}", subject=f"plugin:{pid}")
            continue
        try:
            inst.install_release(conn, data_dir, entry, release, **({"getter": getter} if getter else {}), index_url=index.get("url", ""))
        except (idx.PluginIndexError, registry.InstallError) as exc:
            if (state.get("last") or {}).get("failed") != release["version"]:
                _save(conn, pid, last={"at": utcnow(), "failed": release["version"], "error": str(exc)[:200]})
                add_event(conn, "plugin_update_failed", f"{entry['name']} {release['version']}: {exc}", subject=f"plugin:{pid}")
            done.append({"id": pid, "error": str(exc)})
            continue
        _save(conn, pid, last={"at": utcnow(), "from": have["version"], "to": release["version"]})
        add_event(conn, "plugin_updated", f"{entry['name']} {have['version']} to {release['version']} (automatic update)", subject=f"plugin:{pid}")
        done.append({"id": pid, "from": have["version"], "to": release["version"]})
    return done


# ----------------------------------------------------------------------------- Netlens upgraded: are the plugins still fine?
def note_version(conn, *, now: str | None = None) -> dict | None:
    """Remember the running Netlens version; when it differs from the one seen before, record the upgrade. Returns the upgrade record."""
    last = get_setting(conn, LAST_VERSION_KEY)
    if last != VERSION:
        set_setting(conn, LAST_VERSION_KEY, VERSION)
        if last:
            record = {"from": last, "to": VERSION, "at": now or utcnow()}
            set_setting(conn, UPGRADE_KEY, json.dumps(record))
            set_setting(conn, DISMISSED_KEY, "")
            return record
    return upgrade(conn)


def upgrade(conn) -> dict | None:
    data = _load(conn, UPGRADE_KEY)
    return data if data.get("from") and data.get("to") == VERSION else None


def dismiss(conn) -> None:
    set_setting(conn, DISMISSED_KEY, VERSION)


ENVIRONMENT = ("timed out", "timeout", "cannot reach", "could not reach", "connection refused", "connection reset", "no route to host", "network is unreachable", "name or service not known",
               "temporary failure in name resolution", "nodename nor servname", "unreachable", "host is down", "ssl", "certificate verify")


def environment_problem(error: Any) -> bool:
    """A failure that is about the network or the system the plugin talks to (it does not answer, a name does not resolve), not about this Netlens version."""
    text = str(error or "").lower()
    return any(w in text for w in ENVIRONMENT)


def check(conn, data_dir: Path | str, *, netlens_version: str = VERSION) -> dict:
    """{"upgrade": {...}|None, "problems": [{"id", "name", "version", "reason", "fix": {...}|None}], "dismissed": bool}.

    A plugin is listed when it cannot be loaded, when the index says its installed release does not support this Netlens, or (only after an
    upgrade) when it started failing after the upgrade. `fix` is a newer release that supports this Netlens, if the index has one.
    """
    up = upgrade(conn)
    try:
        entries = {e["id"]: e for e in idx.get_index(conn, offline=True)["entries"]}
    except Exception:  # noqa: BLE001 - no cached index only means no suggestions
        entries = {}
    plugins = registry.discover(data_dir)
    problems = []
    for pid, plugin in sorted(plugins.items()):
        if plugin.builtin:
            continue
        entry = entries.get(pid)
        reason = None
        version = plugin.manifest["version"] if plugin.manifest else None
        if plugin.manifest is None:
            reason = plugin.problem or "the plugin cannot be loaded"
        elif entry is not None:
            mine = next((r for r in entry["releases"] if r["version"] == version), None)
            reason = idx.incompatible_reason(mine, netlens_version) if mine else None
            if reason:
                reason = "this version " + reason
        if reason is None and up and plugin.manifest is not None:
            status = get_status(conn, pid) or {}
            if status.get("error") and status.get("ts", "") >= up["at"] and not environment_problem(status["error"]):
                reason = "it started failing after the Netlens upgrade: " + str(status["error"])[:160]
        if reason is None:
            continue
        fix = None
        if entry is not None:
            best, _ = idx.pick_release(entry, netlens_version)
            if best and (version is None or idx.is_newer(best["version"], version)):
                fix = {"version": best["version"], "level": best["review"]["level"]}
        problems.append({"id": pid, "name": plugin.manifest["name"] if plugin.manifest else pid, "version": version, "reason": reason, "fix": fix})
    return {"upgrade": up, "problems": problems, "dismissed": get_setting(conn, DISMISSED_KEY) == VERSION, "netlens_version": netlens_version}
