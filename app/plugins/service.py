"""Plugin state (enabled, settings, status), turning a plugin's output into links, and the scan hook."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Callable

from app import containers
from app.db import add_event, connect, delete_setting, get_setting, set_setting, utcnow
from app.plugins.contract import ContractError, clean_config, default_config, missing_required, validate_output
from app.plugins import enrich
from app.plugins.enrich import device_lookup, record_client_hints, record_client_links, record_router_names, record_wifi
from app.plugins.matching import match_hypervisor, norm_mac, topology_links
from app.plugins.registry import Plugin, discover
from app.plugins.runner import PluginRunError, run_subprocess

log = logging.getLogger(__name__)
KIND_ORDER = {"hypervisor": 0, "topology": 1, "dns": 2}  # hypervisor links first: they rank higher in the hierarchy anyway


def source_of(plugin_id: str) -> str:
    """The `source` of every relation a plugin creates."""
    return f"plugin:{plugin_id}"


# ----------------------------------------------------------------------------- stored state
def _key(plugin_id: str, part: str = "") -> str:
    return f"plugin.{plugin_id}" + (f".{part}" if part else "")


def _load_json(conn: sqlite3.Connection, key: str) -> Any:
    raw = get_setting(conn, key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def get_state(conn: sqlite3.Connection, plugin: Plugin) -> dict:
    """{"enabled": bool, "config": {...}} with defaults filled in for fields never saved."""
    manifest = plugin.manifest or {"config": []}
    saved = _load_json(conn, _key(plugin.id))
    saved = saved if isinstance(saved, dict) else {}
    values = saved.get("config") if isinstance(saved.get("config"), dict) else {}
    config = default_config(manifest)
    config.update({k: v for k, v in values.items() if k in config})
    return {"enabled": bool(saved.get("enabled", False)) and plugin.manifest is not None, "config": config}


def save_state(conn: sqlite3.Connection, plugin_id: str, enabled: bool, config: dict) -> None:
    set_setting(conn, _key(plugin_id), json.dumps({"enabled": enabled, "config": config}))


def get_status(conn: sqlite3.Connection, plugin_id: str) -> dict | None:
    status = _load_json(conn, _key(plugin_id, "status"))
    return status if isinstance(status, dict) else None


def set_status(conn: sqlite3.Connection, plugin_id: str, **fields) -> None:
    set_setting(conn, _key(plugin_id, "status"), json.dumps({"ts": utcnow(), **fields}))


def forget_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    """Remove everything stored for a plugin (used when an uploaded plugin is removed)."""
    for part in ("", "status", "data", "install"):
        delete_setting(conn, _key(plugin_id, part))
    clear_plugin_data(conn, plugin_id)


def public_state(conn: sqlite3.Connection, plugin: Plugin) -> dict:
    """Everything the UI needs; secrets are replaced by a 'set' flag."""
    state = get_state(conn, plugin)
    manifest = plugin.manifest
    config, secrets_set = {}, {}
    if manifest:
        for f in manifest["config"]:
            if f["secret"]:
                secrets_set[f["key"]] = bool(state["config"].get(f["key"]))
            else:
                config[f["key"]] = state["config"].get(f["key"])
    return {
        "id": plugin.id,
        "builtin": plugin.builtin,
        "problem": plugin.problem,
        "manifest": manifest,
        "enabled": state["enabled"],
        "configured": bool(manifest) and not missing_required(manifest, state["config"]),
        "config": config,
        "secrets_set": secrets_set,
        "status": get_status(conn, plugin.id),
    }


def merge_config(plugin: Plugin, current: dict, changes: dict) -> dict:
    """Apply form values to the saved config. A secret that is left empty keeps its saved value."""
    manifest = plugin.manifest
    merged = dict(current)
    for f in manifest["config"]:
        if f["key"] not in changes:
            continue
        value = changes[f["key"]]
        if f["secret"] and value in (None, ""):
            continue
        merged[f["key"]] = value
    return clean_config(manifest, merged)


# ----------------------------------------------------------------------------- applying results
def _devices_for_matching(conn: sqlite3.Connection) -> list[dict]:
    devices: dict[int, dict] = {}
    for row in conn.execute("SELECT id, mac, primary_ip FROM devices"):
        devices[row["id"]] = {"id": row["id"], "mac": row["mac"], "ips": [row["primary_ip"]] if row["primary_ip"] else []}
    for row in conn.execute("SELECT device_id, ip FROM device_ips"):
        d = devices.get(row["device_id"])
        if d is not None and row["ip"] not in d["ips"]:
            d["ips"].append(row["ip"])
    return list(devices.values())


def clear_plugin_links(conn: sqlite3.Connection, plugin_id: str) -> None:
    conn.execute("DELETE FROM relations WHERE source = ? AND manual = 0", (source_of(plugin_id),))
    conn.commit()


def clear_plugin_data(conn: sqlite3.Connection, plugin_id: str) -> None:
    conn.execute("DELETE FROM hypervisor_guests WHERE plugin_id = ?", (plugin_id,))
    clear_plugin_links(conn, plugin_id)


def _insert_links(conn: sqlite3.Connection, plugin_id: str, kind: str, pairs: list[tuple[int, int]]) -> None:
    source = source_of(plugin_id)
    for child, parent in pairs:
        if kind == "hypervisor":
            # the plugin knows better than a heuristic guess where this guest runs
            conn.execute(
                "DELETE FROM relations WHERE kind = 'host-of' AND manual = 0 AND src_id = ? AND dst_id != ?", (child, parent)
            )
        conn.execute(
            """
            INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual)
            VALUES (?, ?, ?, ?, 1.0, 0)
            ON CONFLICT(src_id, dst_id, kind) DO UPDATE SET source = excluded.source, confidence = 1.0 WHERE manual = 0
            """,
            (child, parent, "host-of" if kind == "hypervisor" else "uplink", source),
        )


def apply_plugin(conn: sqlite3.Connection, plugin: Plugin) -> dict:
    """(Re)build the plugin's guests and links from its last stored output. Call after every relation re-inference.

    Links the user deleted (manual = -1) stay hidden and manual links are never touched.
    """
    kind = plugin.manifest["kind"]
    data = _load_json(conn, _key(plugin.id, "data"))
    if not isinstance(data, dict):
        return {}  # nothing fetched yet: leave whatever is stored (for example data carried over from an older version)
    if kind == "dns":  # a DNS plugin makes no links: its snapshot is only stored (the DNS page works from it)
        return {"zones": len(data["zones"]), "records": len(data["records"]), "managed": sum(1 for r in data["records"] if r["managed"])}
    conn.execute("DELETE FROM relations WHERE source = ? AND manual = 0", (source_of(plugin.id),))
    before = containers.previous_state(conn, plugin.id) if kind == "hypervisor" else {}
    if kind == "hypervisor":
        conn.execute("DELETE FROM hypervisor_guests WHERE plugin_id = ?", (plugin.id,))
    summary: dict[str, int]
    if kind == "hypervisor":
        matched = match_hypervisor(data, _devices_for_matching(conn))
        now = utcnow()
        hosts_by_id = {h["id"]: h for h in data["hosts"]}
        pairs = []
        for g in matched["guests"]:
            conn.execute(
                """
                INSERT INTO hypervisor_guests
                    (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, host_device_id, updated, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (plugin.id, g["id"], g["name"], g["kind"],
                 hosts_by_id.get(g["host_id"], {}).get("name", g["host_id"] or ""), g["status"],
                 json.dumps(g["macs"]), json.dumps(g["ips"]), g["device_id"], g["host_device_id"], now, json.dumps(g.get("details") or {})),
            )
            if g["device_id"] is not None and g["host_device_id"] is not None and g["device_id"] != g["host_device_id"]:
                pairs.append((g["device_id"], g["host_device_id"]))
        _insert_links(conn, plugin.id, kind, pairs)
        enrich.record_guest_names(conn, plugin.id, matched["guests"], now)
        for event_kind, text, device_id in containers.changes(before, matched["guests"], {h["id"]: h["name"] for h in data["hosts"]}):
            add_event(conn, event_kind, text, device_id=device_id, now=now)
        summary = {
            "hosts": len(data["hosts"]),
            "hosts_matched": sum(1 for v in matched["hosts"].values() if v is not None),
            "guests": len(matched["guests"]),
            "guests_matched": sum(1 for g in matched["guests"] if g["device_id"] is not None),
            "links": len(pairs),
        }
    else:
        by_mac, by_ip = device_lookup(conn)
        links = topology_links(data, by_mac, by_ip)
        _insert_links(conn, plugin.id, kind, [(c, p) for c, p, _how in links])
        summary = {"nodes": len(data["nodes"]), "clients": len(data["clients"]), "links": len(links)}
    conn.commit()
    return summary


# ----------------------------------------------------------------------------- running
Runner = Callable[..., Any]


class PluginService:
    """Everything that talks to plugins. `runner(plugin, action, config)` is replaceable for tests."""

    def __init__(self, db_path: str, data_dir: Path | str | None, runner: Runner | None = None):
        self.db_path = str(db_path)
        self.data_dir = data_dir
        self.runner = runner or run_subprocess

    def plugins(self) -> dict[str, Plugin]:
        return discover(self.data_dir)

    def _with_extras(self, plugin: Plugin, config: dict) -> dict:
        """A DNS plugin also gets the zones to read and the marker, from the DNS settings."""
        if (plugin.manifest or {}).get("kind") != "dns":
            return config
        from app.dns.service import plugin_config_extra

        conn = connect(self.db_path)
        try:
            return {**config, **plugin_config_extra(conn)}
        finally:
            conn.close()

    async def _call(self, plugin: Plugin, action: str, config: dict, payload=None):
        config = self._with_extras(plugin, config)
        if payload is None:
            return await asyncio.to_thread(lambda: self.runner(plugin, action, config))
        return await asyncio.to_thread(lambda: self.runner(plugin, action, config, payload=payload))

    async def test(self, plugin: Plugin, config: dict) -> dict:
        """Try a configuration without saving anything. Raises PluginRunError / ContractError."""
        result = await self._call(plugin, "test", config)
        message = result.get("message") if isinstance(result, dict) else None
        return {"ok": True, "message": message if isinstance(message, str) and message else "Connection successful"}

    async def apply_dns(self, plugin: Plugin, changes: list[dict]) -> list[dict]:
        """Hand approved changes to a DNS plugin. Raises PluginRunError / ContractError; per-change failures are in the results."""
        from app.plugins.contract import validate_dns_results

        conn = connect(self.db_path)
        try:
            config = get_state(conn, plugin)["config"]
        finally:
            conn.close()
        raw = await self._call(plugin, "apply", config, payload=changes)
        return validate_dns_results(raw, [c["id"] for c in changes])

    async def diagnose(self, plugin: Plugin, config: dict) -> dict:
        """The plugin's diagnostic report with everything private removed. Raises PluginRunError / DiagnoseError."""
        from app.plugins.diagnose import prepare

        return prepare(await self._call(plugin, "diagnose", config), plugin.manifest, config)

    async def sync(self, plugin_id: str) -> dict:
        """Fetch, validate, store and apply. Returns the summary, or {'error': ..., 'auth_failed': bool}."""
        plugin = self.plugins().get(plugin_id)
        if plugin is None or plugin.manifest is None:
            return {"error": plugin.problem if plugin else "no such plugin", "auth_failed": False}
        conn = connect(self.db_path)
        try:
            state = get_state(conn, plugin)
            missing = missing_required(plugin.manifest, state["config"])
            if missing:
                return {"error": "not configured yet: " + ", ".join(missing), "auth_failed": False}
            try:
                raw = await self._call(plugin, "fetch", state["config"])
                data = validate_output(plugin.manifest["kind"], raw)
            except PluginRunError as exc:
                log.warning("plugin %s failed: %s", plugin.id, exc)
                set_status(conn, plugin.id, ok=False, error=str(exc), auth_failed=exc.auth_failed)
                return {"error": str(exc), "auth_failed": exc.auth_failed}
            except ContractError as exc:
                log.warning("plugin %s returned invalid data: %s", plugin.id, exc)
                message = f"the plugin returned data that does not follow the contract: {exc}"
                set_status(conn, plugin.id, ok=False, error=message, auth_failed=False)
                return {"error": message, "auth_failed": False}
            set_setting(conn, _key(plugin.id, "data"), json.dumps(data))
            summary = apply_plugin(conn, plugin)
            if plugin.manifest["kind"] == "dns":
                try:  # the grace clock and the generated names are kept per scan, not when somebody looks at the page
                    from app.dns.service import get_settings as dns_settings, make_plan

                    if dns_settings(conn)["networks"].strip():       # nothing to plan until a network and zone are set
                        plan = make_plan(conn, plugin.id, data, persist=True)
                        summary.update({"planned": sum(1 for i in plan["items"] if i["state"] in ("add", "update", "delete")), "conflicts": plan["counts"].get("conflict", 0)})
                except (sqlite3.Error, ValueError):
                    log.exception("could not work out the DNS plan")
            if plugin.manifest["kind"] == "topology":
                try:  # what the router tells us besides the links; a failure here must not fail the sync
                    record_router_names(conn, data)
                    record_client_hints(conn, data)
                    record_client_links(conn, plugin.id, data)
                    summary.update(record_wifi(conn, data))
                except sqlite3.Error:
                    log.exception("could not store the router's names and Wi-Fi samples")
            set_status(conn, plugin.id, ok=True, **summary)
            return summary
        finally:
            conn.close()

    def reapply(self, plugin: Plugin) -> None:
        conn = connect(self.db_path)
        try:
            apply_plugin(conn, plugin)
        finally:
            conn.close()

    async def after_scan(self) -> None:
        """Scan hook: refresh every enabled plugin, then put back the links the scan's inference just replaced.

        A plugin whose last attempt was a refused login is not asked again until the user saves or syncs it (so a
        wrong password cannot get an account locked). A failing plugin keeps its last good links.
        """
        conn = connect(self.db_path)
        try:
            enabled = []
            for plugin in sorted(self.plugins().values(), key=lambda p: KIND_ORDER.get((p.manifest or {}).get("kind"), 9)):
                if plugin.manifest is None:
                    continue
                if get_state(conn, plugin)["enabled"]:
                    status = get_status(conn, plugin.id) or {}
                    enabled.append((plugin, bool(status.get("auth_failed"))))
        finally:
            conn.close()
        for plugin, paused in enabled:
            ok = False
            if not paused:
                try:
                    ok = "error" not in await self.sync(plugin.id)
                    if ok and plugin.manifest["kind"] == "dns":
                        from app.dns.service import auto_apply

                        if await auto_apply(self, plugin):
                            await self.sync(plugin.id)      # read back what the server has now
                except Exception:  # noqa: BLE001 - one plugin must never break the others or the scan
                    log.exception("plugin %s crashed the sync", plugin.id)
            if not ok:
                self.reapply(plugin)


async def plugins_after_scan(db_path: str, data_dir: Path | str | None = None) -> None:
    await PluginService(db_path, data_dir).after_scan()
