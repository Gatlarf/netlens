"""Plugins that used to be built into Netlens and are now installed from the Plugin store (Proxmox VE and the ASUS router).

Somebody who used one of them has its settings in the database but no plugin folder after the upgrade. Once an hour (and at the start) Netlens
installs the release from the index for such a plugin and switches it on again when it was on, with the settings it had; nobody has to do anything.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.db import add_event, get_setting, set_setting, utcnow
from app.plugins import index as idx
from app.plugins import index_install as inst
from app.plugins import registry
from app.plugins import service
from app.version import VERSION

log = logging.getLogger(__name__)
MOVED = ("proxmox", "asus")


def pending(conn, data_dir: Path | str) -> list[str]:
    """Moved plugins that have settings in the database but no folder."""
    have = registry.discover(data_dir)
    out = []
    for pid in MOVED:
        if pid in have:
            continue
        saved = get_setting(conn, f"plugin.{pid}")
        if saved:
            out.append(pid)
    return out


def run(conn, data_dir: Path | str, *, getter=None, netlens_version: str = VERSION) -> list[dict]:
    """Install what is pending. Returns [{"id", "version"}] and [{"id", "error"}]."""
    todo = pending(conn, data_dir)
    if not todo:
        return []
    kwargs = {"getter": getter} if getter else {}
    index = idx.get_index(conn, **kwargs)
    entries = {e["id"]: e for e in index["entries"]}
    if any(entries.get(pid) is None or not entries[pid]["releases"] for pid in todo):      # a cached index from before the move lists them as built in: ask again
        index = idx.get_index(conn, force=True, **kwargs)
        entries = {e["id"]: e for e in index["entries"]}
    done = []
    for pid in todo:
        entry = entries.get(pid)
        release, why = idx.pick_release(entry, netlens_version) if entry else (None, "it is not in the plugin index")
        if release is None:
            _failed(conn, pid, why or "no release can be used")
            done.append({"id": pid, "error": why})
            continue
        try:
            saved = json.loads(get_setting(conn, f"plugin.{pid}") or "{}")
            inst.install_release(conn, data_dir, entry, release, **({"getter": getter} if getter else {}), index_url=index.get("url", ""))
            if saved.get("enabled") and isinstance(saved.get("config"), dict):      # the same code as before, now from the store: keep it on
                from app.plugins.contract import default_config

                manifest = registry.discover(data_dir)[pid].manifest
                config = default_config(manifest)
                config.update(saved["config"])      # all of it, also the single url and login of the built-in version: get_state turns those into the server list
                service.save_state(conn, pid, True, config)
        except (idx.PluginIndexError, registry.InstallError) as exc:
            _failed(conn, pid, str(exc))
            done.append({"id": pid, "error": str(exc)})
            continue
        add_event(conn, "plugin_updated", f"{entry['name']} is no longer built into Netlens: version {release['version']} was installed from the Plugin store, with your settings", subject=f"plugin:{pid}")
        done.append({"id": pid, "version": release["version"]})
    return done


def _failed(conn, pid: str, reason: str) -> None:
    key = f"plugin.{pid}.moved_error"
    if get_setting(conn, key) != reason:
        set_setting(conn, key, reason)
        add_event(conn, "plugin_update_failed",
                  f"{pid} is no longer built into Netlens and could not be installed from the Plugin store ({reason}); install it from Settings → Plugin store, your settings are kept", subject=f"plugin:{pid}")
