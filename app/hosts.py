"""Hosts: set up or remove the monitoring of many hosts in one go.

One place for what used to be two: the health monitor (basic readings over SSH or WinRM) and the host probes (the read-only digital engineer).
The levels, for each chosen host:
  basic    a health monitor that uses a stored login (Settings → Credentials)
  probes   basic, plus the read-only probe script installed on the host (with an administrator login that is used once) and the probes switched on
  update   put the newest probe script on hosts that have an older one
  unprobe  take the probe off the host again (the health monitor stays)
  remove   take the probe off and delete the health monitor
Each host is handled on its own: one that fails never stops the others, and every host gets its own result lines and audit line.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from app import audit, credstore
from app.db import connect
from app.hostmetrics import service as hm
from app.hostprobe import installer, scripts, service as probes

LEVELS = ("basic", "probes", "update", "unprobe", "remove")
CONCURRENCY = 3


def _method_of(conn, device_id: int, ip: str | None) -> str | None:
    """SSH when the port is open, WinRM otherwise (Windows hosts without an SSH server)."""
    open_ports = {(r["proto"], r["port"]) for r in conn.execute("SELECT proto, port FROM ports WHERE device_id = ? AND state LIKE 'open%'", (device_id,))}
    ports = {p for _proto, p in open_ports}
    if 22 in ports:
        return "ssh"
    if ports & {5986, 5985}:
        return "winrm"
    return None


def overview(conn) -> list[dict[str, Any]]:
    out = []
    for d in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip, online, COALESCE(type_override, device_type) AS type FROM devices "
                          "WHERE primary_ip IS NOT NULL ORDER BY online DESC, LOWER(COALESCE(custom_name, hostname, primary_ip))").fetchall():
        method = _method_of(conn, d["id"], d["primary_ip"])
        row = hm.get_monitor(conn, d["id"])
        mon = None
        if row is not None and row["method"] in ("ssh", "winrm"):
            pub = hm.public(conn, row)
            cred = credstore.peek_bound(conn, pub["credential_id"]) if pub.get("credential_id") else None
            mon = {"method": row["method"], "enabled": bool(row["enabled"]), "ok": pub["last_ok"], "error": pub["last_error"], "login": cred["name"] if cred else ("typed in" if pub.get("username") else None),
                   "managed": row["source"] == "central"}
        elif row is not None:
            mon = {"method": row["method"], "other": True}
        cfg = probes.device_config(conn, d["id"])
        newest = probes.latest_ok(conn, d["id"])
        installed = (newest["data"].get("script_version") if newest and newest["mode"] == "locked" else None)
        probe = {"enabled": cfg["enabled"], "mode": newest["mode"] if newest else None, "installed_version": installed, "update_available": bool(installed and installed < scripts.SCRIPT_VERSION),
                 "last": newest["taken"] if newest else None}
        out.append({"id": d["id"], "name": d["name"], "ip": d["primary_ip"], "online": bool(d["online"]), "type": d["type"], "can_monitor": method, "monitor": mon, "probes": probe})
    return out


def _admin_login(conn, user: str, opts: dict[str, Any]) -> dict[str, Any]:
    """The administrator login for the install, used for this run only: from the store, or typed (never stored, never logged)."""
    if opts.get("admin_credential_id"):
        try:
            c = credstore.resolve(conn, user, str(opts["admin_credential_id"]), "installing host probes")
        except credstore.CredentialError:
            raise installer.InstallError("no such stored administrator login")
        return {"username": c.get("username", ""), "password": c.get("password"), "private_key": c.get("private_key"), "passphrase": c.get("passphrase"), "sudo_password": c.get("password")}
    return {"username": str(opts.get("admin_username") or "").strip(), "password": opts.get("admin_password") or None, "private_key": opts.get("admin_private_key") or None,
            "passphrase": None, "sudo_password": opts.get("admin_password") or None}


async def _one(db_path, device_id: int, level: str, opts: dict[str, Any], who) -> dict[str, Any]:
    conn = connect(db_path)
    steps: list[str] = []
    name = f"device {device_id}"
    try:
        d = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip FROM devices WHERE id = ?", (device_id,)).fetchone()
        if d is None:
            return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "no such device"}
        name = d["name"]
        user = getattr(who, "username", "") or ""
        row = hm.get_monitor(conn, device_id)
        if level in ("basic", "probes"):
            if row is not None and row["source"] == "central":
                return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "this monitor is managed by the central Netlens"}
            method = opts.get("method") if opts.get("method") in ("ssh", "winrm") else (row["method"] if row is not None and row["method"] in ("ssh", "winrm") else _method_of(conn, device_id, d["primary_ip"]))
            if method is None:
                return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "neither SSH nor WinRM is open on this host"}
            if opts.get("credential_id"):
                if credstore.peek(conn, user, str(opts["credential_id"])) is None:
                    return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "no such stored login"}
            elif row is None or not hm.raw_secret(conn, row):
                return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "choose the login the health monitor uses"}
            if row is None or opts.get("credential_id") or row["method"] != method:
                data = {"method": method, "address": d["primary_ip"], **({"credential_id": opts["credential_id"]} if opts.get("credential_id") else {})}
                try:
                    hm.save_monitor(conn, device_id, data)
                except hm.MonitorError as exc:
                    return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": str(exc)}
                steps.append(f"Health monitor over {method.upper()} set up" + (" with the stored login" if opts.get("credential_id") else ""))
            else:
                steps.append(f"Health monitor over {row['method'].upper()} was already there")
            row = hm.get_monitor(conn, device_id)
            read = await hm.run_monitor(db_path, row["id"])
            if read.get("ok"):
                steps.append("Read the host once: it answers")
            else:
                steps.append(f"The host did not answer yet: {str(read.get('error'))[:200]}")
                if level == "probes":
                    return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "the health monitor cannot log in, so the probe cannot be installed: fix the login first"}
        if level in ("probes", "update", "unprobe", "remove"):
            if row is None:
                if level in ("unprobe", "remove"):
                    steps.append("No health monitor and no probe on this host")
                    return {"device_id": device_id, "name": name, "ok": True, "steps": steps, "error": None}
                return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": "no health monitor on this host"}
            action = {"probes": "install", "update": "update", "unprobe": "remove", "remove": "remove"}[level]
            have_probe = probes.device_config(conn, device_id)["enabled"] or probes.latest_ok(conn, device_id) is not None
            if level in ("unprobe", "remove") and not have_probe:
                steps.append("No probe on this host")
            else:
                admin = _admin_login(conn, user, opts)
                result = await installer.administer(conn, device_id, action, admin, None, bool(opts.get("enable_sshd")), str(opts.get("allow_from") or ""))
                steps += [str(l) for l in result.get("log", [])][-6:]
                if not result["ok"]:
                    return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": str(result.get("error") or "the install failed")}
                if level == "probes":
                    probes.save_settings(conn, {"devices": {str(device_id): {"enabled": True}}})
                    steps.append("Probes switched on")
                    if result.get("verified") and not result["verified"].get("ok"):
                        steps.append(f"Installed, but the check afterwards failed: {result['verified'].get('error')}")
                elif level in ("unprobe", "remove"):
                    probes.save_settings(conn, {"devices": {str(device_id): {"enabled": False, "provider": "static"}}})
                    steps.append("Probes switched off")
            if level == "remove" and row is not None and row["source"] != "central":
                conn.execute("DELETE FROM metric_state WHERE monitor_id = ?", (row["id"],))
                conn.execute("DELETE FROM host_monitors WHERE id = ?", (row["id"],))
                conn.commit()
                hm._STATES.pop(row["id"], None)
                steps.append("Health monitor removed")
        return {"device_id": device_id, "name": name, "ok": True, "steps": steps, "error": None}
    except installer.InstallError as exc:
        return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - one host's trouble must not stop the others
        return {"device_id": device_id, "name": name, "ok": False, "steps": steps, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    finally:
        conn.close()


async def apply(db_path, device_ids: list[int], level: str, opts: dict[str, Any], who, ip: str = "") -> list[dict[str, Any]]:
    if level not in LEVELS:
        raise ValueError("level must be one of: " + ", ".join(LEVELS))
    sem = asyncio.Semaphore(CONCURRENCY)

    async def guarded(device_id: int) -> dict[str, Any]:
        async with sem:
            result = await _one(db_path, device_id, level, opts, who)
        conn = connect(db_path)
        try:
            login = f" with the stored login {opts['credential_id']}" if opts.get("credential_id") else ""
            audit.record_by(conn, who, ip, "POST", "/api/hosts/apply", 200 if result["ok"] else 502,
                            f"Host setup '{level}' for {result['name']}{login}: " + ("done" if result["ok"] else f"failed: {str(result['error'])[:120]}") + " (administrator logins are used once and not stored)")
        finally:
            conn.close()
        return result

    return list(await asyncio.gather(*(guarded(i) for i in device_ids)))
