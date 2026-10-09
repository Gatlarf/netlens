"""Installing, updating and rolling back plugins from the index (the downloads are verified by `index.download_release`)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from app.db import get_setting, set_setting, utcnow
from app.plugins import registry
from app.plugins.contract import clean_config
from app.plugins.index import download_release
from app.plugins.service import save_state
from app.plugins.registry import Plugin

KEEP_BACKUPS = 3


def _key(plugin_id: str) -> str:
    return f"plugin.{plugin_id}.install"


def provenance(conn, plugin_id: str) -> dict | None:
    try:
        data = json.loads(get_setting(conn, _key(plugin_id)) or "null")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def backup_dir(data_dir: Path | str, plugin_id: str) -> Path:
    return Path(data_dir) / "plugin-backups" / plugin_id


def remember_zip(data_dir: Path | str, plugin_id: str, version: str, data: bytes) -> None:
    """Keep the zip of an installed version so it can be restored; only the newest few are kept."""
    if not re.fullmatch(r"[a-z0-9_-]{1,31}", plugin_id):
        return
    folder = backup_dir(data_dir, plugin_id)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{version}-{hashlib.sha256(data).hexdigest()[:12]}.zip").write_bytes(data)
    zips = sorted(folder.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in zips[KEEP_BACKUPS:]:
        old.unlink(missing_ok=True)


def backups(data_dir: Path | str, plugin_id: str) -> list[tuple[str, Path]]:
    """[(version, path)] newest first."""
    folder = backup_dir(data_dir, plugin_id)
    if not folder.is_dir():
        return []
    items = sorted(folder.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [(p.name.rsplit("-", 1)[0], p) for p in items]


def installed_map(conn, plugins: dict[str, Plugin], data_dir: Path | str) -> dict[str, dict]:
    """What is installed, for the Browse view: {id: {version, builtin, source, level, can_rollback}}."""
    out = {}
    for plugin_id, plugin in plugins.items():
        if plugin.manifest is None:
            continue
        info = provenance(conn, plugin_id) or {}
        current = plugin.manifest["version"]
        out[plugin_id] = {
            "version": current, "builtin": plugin.builtin, "source": "builtin" if plugin.builtin else info.get("source", "upload"),
            "level": info.get("level"), "can_rollback": (not plugin.builtin) and any(v != current for v, _ in backups(data_dir, plugin_id)),
        }
    return out


def install_release(conn, data_dir: Path | str, entry: dict, release: dict, *, getter=None, index_url: str = "") -> dict:
    """Download, verify and install one release. A plugin that is already installed is replaced and keeps its settings.

    The plugin is left switched off after a fresh install. Raises PluginIndexError / registry.InstallError.
    """
    if (registry.BUILTIN_DIR / entry["id"]).exists():
        raise registry.InstallError(f"{entry['name']} is built in; it cannot be installed from the index")
    data = download_release(release, **({"getter": getter} if getter else {}))
    files, manifest = registry.read_zip(data)  # the same checks as an upload
    if manifest["id"] != entry["id"]:
        raise registry.InstallError(f"the download is the plugin {manifest['id']!r}, not {entry['id']!r}")
    if manifest["version"] != release["version"]:
        raise registry.InstallError(f"the download says version {manifest['version']}, the index says {release['version']}")
    if manifest["kind"] != entry["kind"]:
        raise registry.InstallError("the plugin type in the download does not match the index")
    existing = (Path(data_dir) / "plugins" / entry["id"]).exists()
    result = registry.install(data_dir, data, replace=existing)
    remember_zip(data_dir, entry["id"], release["version"], data)
    if not existing:
        save_state(conn, entry["id"], False, clean_config(manifest, {}))
    set_setting(conn, _key(entry["id"]), json.dumps({
        "source": "index", "index_url": index_url, "version": release["version"], "sha256": release["sha256"],
        "level": release["review"]["level"], "reviewer": release["review"]["reviewer"], "installed": utcnow(),
    }))
    return {"id": entry["id"], "version": release["version"], "replaced": result["replaced"], "level": release["review"]["level"]}


def rollback(conn, data_dir: Path | str, plugin_id: str) -> dict:
    """Go back to the newest kept version that is not the current one (settings are kept)."""
    plugins = registry.discover(data_dir)
    plugin = plugins.get(plugin_id)
    if plugin is None or plugin.builtin or plugin.manifest is None:
        raise registry.InstallError("only installed (not built-in) plugins can be rolled back")
    current = plugin.manifest["version"]
    previous = [(v, p) for v, p in backups(data_dir, plugin_id) if v != current]
    if not previous:
        raise registry.InstallError("there is no earlier version to go back to")
    version, path = previous[0]
    data = path.read_bytes()
    registry.install(data_dir, data, replace=True)
    set_setting(conn, _key(plugin_id), json.dumps({"source": "rollback", "version": version, "sha256": hashlib.sha256(data).hexdigest(), "level": None, "installed": utcnow()}))
    return {"id": plugin_id, "version": version, "from": current}
