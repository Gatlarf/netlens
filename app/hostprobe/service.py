"""Host probes: look at what uses the storage of a host, keep snapshots, and say what grew between two of them.

Switched on per device (the device needs a host monitor over SSH or WinRM, which supplies the address). A snapshot is taken every few hours
and, as soon as a disk goes over its limit, at once, so the next morning "what happened to the disk?" has an answer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import connect, get_setting, insert_id, set_setting
from app.hostmetrics import service as hm, ssh, winrm
from app.hostprobe import analyze, credentials, parse, parsers, scripts

log = logging.getLogger(__name__)
SETTINGS_KEY = "hostprobe.settings"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_INTERVAL_H = 6
KEEP_DAYS = 30            # default; Settings → Host probes
KEEP_MAX = 120
ALARM_GAP_S = {"storage": 1800}     # while something is over its limit: at most one snapshot of that probe per half hour (a quarter for the others)
ALARM_GAP_DEFAULT_S = 900
BASELINE_H = 24               # the probes that are not about storage are also looked at once a day, so there is a picture of 'normal'
# which probe to run when a reading goes over its limit
ALARM_PROBES = {"disk_pct": ["storage"], "cpu_pct": ["cpu", "apps"], "load1": ["cpu"], "mem_pct": ["memory", "apps"], "swap_pct": ["memory"], "temp_c": ["hardware", "cpu"],
                "storage_status": ["hardware", "storage"], "service_stopped": ["apps"], "if_util_pct": ["network"], "if_err_ps": ["network", "hardware"], "net_rx_bps": ["network"], "net_tx_bps": ["network"]}
PROVIDER_NAMES = ("static", "netlens_ca", "vault_ssh")
_running: set[tuple[int, str]] = set()


class ProbeFailed(Exception):
    pass


# ----------------------------------------------------------------------------- settings
def _load(conn) -> dict[str, Any]:
    try:
        data = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        data = {}
    data = data if isinstance(data, dict) else {}
    return {"devices": data.get("devices") if isinstance(data.get("devices"), dict) else {},
            "providers": data.get("providers") if isinstance(data.get("providers"), dict) else {},
            "names_to_llm": bool(data.get("names_to_llm")), "keep_days": min(max(int(data.get("keep_days") or KEEP_DAYS), 1), 365)}


def _save(conn, data: dict) -> None:
    set_setting(conn, SETTINGS_KEY, json.dumps(data))
    conn.commit()


def device_config(conn, device_id: int) -> dict[str, Any]:
    cfg = _load(conn)["devices"].get(str(device_id)) or {}
    probes = [p for p in (cfg.get("probes") if isinstance(cfg.get("probes"), list) else scripts.PROBES) if p in scripts.PROBES]
    return {"enabled": bool(cfg.get("enabled")), "interval_h": int(cfg.get("interval_h") or DEFAULT_INTERVAL_H), "provider": cfg.get("provider") or "static", "username": cfg.get("username") or "", "probes": probes, "ssh_port": int(cfg.get("ssh_port") or 22)}


def public_settings(conn) -> dict[str, Any]:
    """Everything for the settings page; secrets only as 'is set'."""
    data = _load(conn)
    vault_cfg = data["providers"].get("vault_ssh") or {}
    ca_cfg = data["providers"].get("netlens_ca") or {}
    return {"names_to_llm": data["names_to_llm"], "keep_days": data["keep_days"], "ca_public_key": credentials.ca_public(conn),
            "providers": {"netlens_ca": {"ttl_s": credentials._ttl(ca_cfg), "username": ca_cfg.get("username") or "netlens-ro"},
                          "vault_ssh": {"url": vault_cfg.get("url") or "", "mount": vault_cfg.get("mount") or "ssh", "role": vault_cfg.get("role") or "",
                                        "namespace": vault_cfg.get("namespace") or "", "username": vault_cfg.get("username") or "netlens-ro", "ttl_s": credentials._ttl(vault_cfg),
                                        "has_token": bool(vault_cfg.get("token")), "has_approle": bool(vault_cfg.get("role_id") and vault_cfg.get("secret_id"))}},
            "devices": {k: device_config(conn, int(k)) for k in data["devices"] if k.isdigit()}}


def save_settings(conn, body: dict[str, Any]) -> dict[str, Any]:
    data = _load(conn)
    if "names_to_llm" in body:
        data["names_to_llm"] = bool(body["names_to_llm"])
    if "keep_days" in body:
        data["keep_days"] = min(max(int(body["keep_days"]), 1), 365)
    for name, incoming in (body.get("providers") or {}).items():
        if name not in ("netlens_ca", "vault_ssh") or not isinstance(incoming, dict):
            raise ValueError(f"unknown credential source: {name}")
        cur = data["providers"].setdefault(name, {})
        for key in ("url", "mount", "role", "namespace", "username", "approle_mount"):
            if key in incoming:
                cur[key] = str(incoming[key] or "").strip()[:200]
        if "ttl_s" in incoming:
            cur["ttl_s"] = min(max(int(incoming["ttl_s"]), credentials.MIN_TTL_S), credentials.MAX_TTL_S)
        for key in ("token", "role_id", "secret_id"):
            if incoming.get(key):
                cur[key] = str(incoming[key]).strip()
        for key in ("clear_token", "clear_approle"):
            if incoming.get(key):
                for k in (("token",) if key == "clear_token" else ("role_id", "secret_id")):
                    cur.pop(k, None)
        if name == "vault_ssh" and cur.get("url") and not cur["url"].startswith(("http://", "https://")):
            raise ValueError("the address of the secrets service must start with http:// or https://")
    for key, incoming in (body.get("devices") or {}).items():
        if not str(key).isdigit() or not isinstance(incoming, dict):
            raise ValueError("devices must be keyed by device id")
        cur = data["devices"].setdefault(str(key), {})
        if "enabled" in incoming:
            cur["enabled"] = bool(incoming["enabled"])
        if "interval_h" in incoming:
            cur["interval_h"] = min(max(int(incoming["interval_h"]), 1), 168)
        if "provider" in incoming:
            if incoming["provider"] not in PROVIDER_NAMES:
                raise ValueError("the credential source must be static, netlens_ca or vault_ssh")
            cur["provider"] = incoming["provider"]
        if "username" in incoming:
            cur["username"] = str(incoming["username"] or "").strip()[:60]
        if "ssh_port" in incoming:
            cur["ssh_port"] = min(max(int(incoming["ssh_port"]), 1), 65535)
        if "probes" in incoming:
            if not isinstance(incoming["probes"], list) or any(p not in scripts.PROBES for p in incoming["probes"]):
                raise ValueError("probes must be a list of: " + ", ".join(scripts.PROBES))
            cur["probes"] = [p for p in scripts.PROBES if p in incoming["probes"]]
    _save(conn, data)
    return public_settings(conn)


# ----------------------------------------------------------------------------- snapshots
def _stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime(STAMP)


def store(conn, device_id: int, ok: bool, mode: str | None, error: str | None, data: dict | None, now: float | None = None, probe: str = "storage", reason: str = "schedule") -> int:
    now = now if now is not None else time.time()
    new_id = insert_id(conn, "INSERT INTO probe_snapshots (device_id, probe, taken, ok, mode, error, data, reason) VALUES (?,?,?,?,?,?,?,?)",
                       (device_id, probe, _stamp(now), int(ok), mode, error, json.dumps(data) if data else None, reason))
    conn.execute("DELETE FROM probe_snapshots WHERE device_id = ? AND probe = ? AND (taken < ? OR id NOT IN (SELECT id FROM probe_snapshots WHERE device_id = ? AND probe = ? ORDER BY id DESC LIMIT ?))",
                 (device_id, probe, _stamp(now - _load(conn)["keep_days"] * 86400), device_id, probe, KEEP_MAX))
    conn.commit()
    return new_id


def snapshots(conn, device_id: int, limit: int = 20, with_data: bool = False, probe: str | None = "storage") -> list[dict[str, Any]]:
    """The newest snapshots of one probe (default storage; probe=None for all of them)."""
    where, args = ("AND probe = ?", [probe]) if probe else ("", [])
    rows = conn.execute(f"SELECT id, probe, taken, ok, mode, error, data FROM probe_snapshots WHERE device_id = ? {where} ORDER BY taken DESC, id DESC LIMIT ?", (device_id, *args, limit)).fetchall()
    return [{"id": r["id"], "probe": r["probe"], "taken": r["taken"], "ok": bool(r["ok"]), "mode": r["mode"], "error": r["error"], **({"data": json.loads(r["data"]) if r["data"] else None} if with_data else {})} for r in rows]


def history(conn, device_id: int, probe: str, before: str, limit: int = 24, days: int = 21) -> list[dict[str, Any]]:
    """The earlier answers of one probe, oldest first, that tell what is normal: successful, older than `before`, within `days`, and not taken while a reading was over its limit."""
    cutoff = _stamp(datetime.strptime(before, STAMP).replace(tzinfo=timezone.utc).timestamp() - days * 86400)
    rows = conn.execute("SELECT data FROM probe_snapshots WHERE device_id = ? AND probe = ? AND ok = 1 AND reason != 'alarm' AND taken < ? AND taken >= ? ORDER BY taken DESC LIMIT ?",
                        (device_id, probe, before, cutoff, limit)).fetchall()
    return [json.loads(r["data"]) for r in reversed(rows) if r["data"]]


def latest_ok(conn, device_id: int, before: str | None = None, after: str | None = None, probe: str = "storage") -> dict[str, Any] | None:
    sql, args = "SELECT id, taken, mode, data FROM probe_snapshots WHERE device_id = ? AND probe = ? AND ok = 1", [device_id, probe]
    if before:
        sql += " AND taken <= ?"
        args.append(before)
    if after:
        sql += " AND taken >= ?"
        args.append(after)
    sql += " ORDER BY taken " + ("ASC" if after else "DESC") + ", id " + ("ASC" if after else "DESC") + " LIMIT 1"
    r = conn.execute(sql, args).fetchone()
    return {"id": r["id"], "taken": r["taken"], "mode": r["mode"], "data": json.loads(r["data"])} if r and r["data"] else None


def explain(conn, device_id: int, start: str, end: str | None = None) -> dict[str, Any] | None:
    """What grew on a host around [start, end]: the newest storage snapshot at or before `start` against the first one at or after `end` (else the newest).
    None when there are not two snapshots to compare."""
    before = latest_ok(conn, device_id, before=start)
    after = latest_ok(conn, device_id, after=end or start) or latest_ok(conn, device_id)
    first = False
    if before is None:                                    # nothing before: the oldest one we have is the best baseline
        row = conn.execute("SELECT taken FROM probe_snapshots WHERE device_id = ? AND probe = 'storage' AND ok = 1 ORDER BY taken ASC LIMIT 1", (device_id,)).fetchone()
        before = latest_ok(conn, device_id, after=row["taken"]) if row else None
        first = True
    if before is None or after is None or before["id"] == after["id"]:
        return None
    result = parse.compare(before["data"], after["data"])
    return {"from": before["taken"], "to": after["taken"], "baseline_is_later_than_start": first, **result}


def describe(growth: dict[str, Any], limit: int = 3) -> list[str]:
    out = []
    for g in growth["growth"][:limit]:
        what = {"directory": "The directory", "file": "The file", "container log": "The log of the container", "container layer": "The data of the container"}.get(g["kind"], "")
        out.append(f"{what} {g['path']} grew by {parse.nice_bytes(g['bytes'])}" + (f" to {parse.nice_bytes(g['now'])}" if g.get("now") else "") + (" (new)" if g.get("new") and g["kind"] == "file" else ""))
    return out


# ----------------------------------------------------------------------------- running a probe
_TIMEOUT = {"storage": 200.0, "network": 60.0}


async def _linux(cred: credentials.Credential, address: str, port: int, known: str | None, probe: str) -> tuple[str, str, str | None]:
    """(output, mode, host key fingerprint): the locked-down script first; a host that has none gets the same script sent directly."""
    out, status, fp = await ssh.run_command(address, port, cred.username, cred.password, cred.private_key, cred.passphrase, scripts.locked_command(probe), known, timeout=30.0 if probe != "storage" else 200.0,
                                            certificate=cred.certificate)
    if "##end" in out:                  # the host ran its own installed script (its version is in the answer)
        return out, "locked", fp
    out, status, fp = await ssh.run_command(address, port, cred.username, cred.password, cred.private_key, cred.passphrase, scripts.LINUX_COMMANDS[probe], known, timeout=_TIMEOUT.get(probe, 60.0), certificate=cred.certificate)
    return out, "direct", fp


_NO_READINGS: dict[int, float] = {}        # device id -> when the host last said it has no "readings" script yet (an older install): the stored login is used meanwhile
_NO_READINGS_FOR = 3600.0


async def locked_readings(conn, row, state: dict, now: float | None = None) -> tuple[list, list, str | None] | None:
    """The health monitor's numbers through the locked-down probe account, with a certificate made for this one look: no standing password or key is used.
    Returns None when this host has no locked-down probe (or an older one without the readings script): the caller then uses the stored login.
    Raises nothing: any trouble means None, so the monitor never depends on the probe."""
    device_id = row["device_id"]
    try:
        cfg = device_config(conn, device_id)
        if cfg["provider"] == "static" or row["method"] not in ("ssh", "winrm"):
            return None
        if time.time() - _NO_READINGS.get(device_id, 0.0) < _NO_READINGS_FOR:
            return None
        providers = _load(conn)["providers"]
        config = {**(providers.get(cfg["provider"]) or {}), **({"username": cfg["username"]} if cfg["username"] else {})}
        cred = await credentials.issue(conn, cfg["provider"], config, {})
        from app.terminal.hostkeys import get_fingerprint

        port = cfg["ssh_port"] if row["method"] == "winrm" else row["port"]
        out, status, fp = await ssh.run_command(row["address"], port, cred.username, cred.password, cred.private_key, cred.passphrase, scripts.locked_command(scripts.READINGS),
                                                get_fingerprint(conn, device_id), timeout=40.0, certificate=cred.certificate)
        if "##netlens-windows" in out:
            points, found = ssh.parse_windows(out, state, now)
        elif "##loadavg" in out or "##end" in out:
            points, found = ssh.parse(out, state, now)
        else:                                                    # "refused" / "unknown probe": the script on the host is older than this Netlens
            _NO_READINGS[device_id] = time.time()
            return None
        if not points and not found:
            return None
        state["via"] = "locked"
        return points, found, fp
    except Exception:  # noqa: BLE001 - see the docstring
        return None


def _parse(probe: str, platform: str, out: str) -> dict[str, Any]:
    if probe == "storage":
        return parse.parse_linux(out) if platform == "linux" else parse.parse_windows(out)
    return parsers.parse_probe(probe, platform, out)


async def run(conn, device_id: int, probe: str = "storage", reason: str = "manual") -> dict[str, Any]:
    """One snapshot of one probe now. Returns {"ok", "error", "mode", "data", "credential", "probe"} and stores it."""
    if probe not in scripts.PROBES:
        raise ProbeFailed(f"no such probe: {probe}")
    row = hm.get_monitor(conn, device_id)
    if row is None or row["method"] not in ("ssh", "winrm"):
        raise ProbeFailed("this device needs a host monitor over SSH or WinRM first (Health monitoring on the device page): it supplies the address and the login")
    cfg = device_config(conn, device_id)
    secret = hm.load_secret(conn, row)
    providers = _load(conn)["providers"]
    config = {**(providers.get(cfg["provider"]) or {}), **({"username": cfg["username"]} if cfg["username"] else {})}
    started = time.time()
    mode, data, error, cred_info = None, None, None, None
    try:
        if row["method"] == "winrm" and cfg["provider"] == "static":                  # a Windows host with no locked-down login: the stored WinRM login runs the script directly
            session = winrm.Session(row["address"], row["port"], row["port"] != 5985, secret.get("username", ""), secret.get("password", ""), secret.get("auth", "ntlm"), bool(secret.get("verify_tls")), timeout=30)
            try:
                out, err, _code = await asyncio.to_thread(session.run_powershell, scripts.windows_script(probe), 180)
            except winrm.WinrmError as exc:
                raise ProbeFailed(str(exc)) from None
            finally:
                session.close()
            try:
                data, mode = _parse(probe, "windows", out), "direct"
            except parse.ProbeError as exc:
                raise ProbeFailed(f"{exc}: {winrm.powershell_error(err) or 'the script printed nothing'}") from None
        else:
            cred = await credentials.issue(conn, cfg["provider"], config, secret)
            cred_info = cred.public()
            from app.terminal.hostkeys import get_fingerprint

            known = get_fingerprint(conn, device_id)
            winrm_host = row["method"] == "winrm"                                         # a Windows host that is watched over WinRM but probed through its OpenSSH server
            platform = "windows" if winrm_host else (hm._STATES.get(row["id"]) or {}).get("platform") or secret.get("platform", "auto")
            port = cfg["ssh_port"] if winrm_host else row["port"]
            seen = None
            try:
                if platform in ("auto", "linux"):
                    try:
                        out, mode, seen = await _linux(cred, row["address"], port, known, probe)
                        data = _parse(probe, "linux", out)
                    except (parse.ProbeError, ssh.SshError):
                        if platform == "linux":
                            raise
                        data = None
                if data is None and winrm_host:                                            # the locked-down Windows script, then (a login that is not locked down) the same script sent directly
                    out, _s, seen = await ssh.run_command(row["address"], port, cred.username, cred.password, cred.private_key, cred.passphrase, scripts.locked_command(probe), known,
                                                          timeout=_TIMEOUT.get(probe, 90.0) + 20, certificate=cred.certificate)
                    if "##netlens-probe" in out:
                        data, mode = _parse(probe, "windows", out), "locked"
                if data is None:
                    out, _s, seen = await ssh.run_command(row["address"], port, cred.username, cred.password, cred.private_key, cred.passphrase, scripts.WINDOWS_COMMANDS[probe], known,
                                                          timeout=_TIMEOUT.get(probe, 90.0) + 20, certificate=cred.certificate)
                    data, mode = _parse(probe, "windows", out), "direct"
            except (ssh.SshError, parse.ProbeError) as exc:
                raise ProbeFailed(str(exc)) from None
            if winrm_host and seen and known is None:                                      # first contact: remember the host key (the monitor does that for SSH devices)
                from app.terminal.hostkeys import remember_fingerprint

                remember_fingerprint(conn, device_id, seen, _stamp(time.time()))
            data["credential"] = cred_info
    except credentials.CredentialError as exc:
        error = str(exc)
    except ProbeFailed as exc:
        error = str(exc)
    data = data if error is None else None
    if data is not None:
        data["seconds"] = round(time.time() - started, 1)
    store(conn, device_id, error is None, mode, error, data, probe=probe, reason=reason)
    return {"ok": error is None, "error": error, "mode": mode, "data": data, "probe": probe, "credential": cred_info or {"source": "static", "username": secret.get("username", "")}}


# ----------------------------------------------------------------------------- the schedule
def alarms(conn) -> dict[int, set[str]]:
    """device -> the probes to look at now because a reading is over its limit (or a container is in trouble)."""
    out: dict[int, set[str]] = {}
    try:
        for p in hm.problems(conn, include_snoozed=True):
            out.setdefault(p["device_id"], set()).update(ALARM_PROBES.get(p["metric"], []))
        for r in conn.execute("SELECT DISTINCT device_id FROM events WHERE device_id IS NOT NULL AND kind IN ('container_restarting', 'container_unhealthy', 'container_stopped') AND ts >= ?", (_stamp(time.time() - 900),)):
            out.setdefault(r["device_id"], set()).update(["apps", "memory", "cpu"])
    except Exception:  # noqa: BLE001 - a broken problems list must not stop the schedule
        log.exception("host probe: problems")
    return out


def due(conn, now: float | None = None) -> list[tuple[int, str]]:
    """(device, probe) pairs to take now: the interval has passed, or a reading is over its limit and the last look of that probe is older than the alarm gap."""
    now = now if now is not None else time.time()
    settings = _load(conn)["devices"]
    alarm = alarms(conn)
    out = []
    for key, cfg in settings.items():
        if not key.isdigit() or not cfg.get("enabled"):
            continue
        device_id = int(key)
        wanted = device_config(conn, device_id)["probes"]
        for probe in wanted:
            last = conn.execute("SELECT MAX(taken) AS t FROM probe_snapshots WHERE device_id = ? AND probe = ?", (device_id, probe)).fetchone()["t"]
            if last is None:
                out.append((device_id, probe))
                continue
            age = now - datetime.strptime(last, STAMP).replace(tzinfo=timezone.utc).timestamp()
            every = (int(cfg.get("interval_h") or DEFAULT_INTERVAL_H) if probe == "storage" else BASELINE_H) * 3600
            if age >= every or (probe in alarm.get(device_id, ()) and age >= ALARM_GAP_S.get(probe, ALARM_GAP_DEFAULT_S)):
                out.append((device_id, probe))
    return out


def due_with_reason(conn, now: float | None = None) -> list[tuple[int, str, str]]:
    """Like due(), with why: "alarm" (a reading is over its limit: the answer is not what is normal) or "schedule"."""
    alarm = alarms(conn)
    return [(d, p, "alarm" if p in alarm.get(d, ()) else "schedule") for d, p in due(conn, now)]


def audit_text(name: str, result: dict[str, Any], trigger: str) -> str:
    """The audit line for one look: which host and probe, why it ran, which login (never the secret), and how it ended. The certificate id is what the host's sshd logs."""
    cred = result.get("credential") or {}
    login = {"netlens_ca": "a certificate from the Netlens CA", "vault_ssh": "a certificate from Vault/OpenBao"}.get(cred.get("source"), "the stored login of the health monitor")
    if cred.get("certificate"):
        until = _stamp(cred["expires"])[11:16] + " UTC" if cred.get("expires") else "?"
        login += f" (id {cred.get('key_id')}, user {cred.get('username')}, valid until {until})"
    elif cred.get("username"):
        login += f" (user {cred['username']})"
    outcome = f"ok, {result.get('mode')} script" if result["ok"] else "failed: " + str(result.get("error") or "")[:160]
    label = "Storage inspection" if result.get("probe", "storage") == "storage" else f"Host probe '{result['probe']}'"
    return f"{label} of {name} ({trigger}): read-only probe with {login}: {outcome}"


def _audit(conn, device_id: int, result: dict[str, Any], actor) -> None:
    try:
        from app import audit

        row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (device_id,)).fetchone()
        name = row["n"] if row else f"device {device_id}"
        path = f"/api/devices/{device_id}/hostprobe/run"
        if actor is None:
            audit.record_system(conn, audit_text(name, result, "scheduled"), path, 200 if result["ok"] else 502)
        else:
            principal, ip = actor
            audit.record_by(conn, principal, ip, "POST", path, 200 if result["ok"] else 502, audit_text(name, result, "started by a person"))
        log.info("host probe %s of device %s: %s", result.get("probe"), device_id, "ok" if result["ok"] else result.get("error"))
    except Exception:  # noqa: BLE001 - the log must never stop the probe
        log.exception("host probe: audit line")


async def run_one(db_path: str, device_id: int, actor=None, probe: str = "storage", reason: str | None = None) -> dict[str, Any]:
    """`actor` is (principal, ip) when a person started it; None for the schedule. Every attempt, failed or not, is written to the audit log."""
    key = (device_id, probe)
    if key in _running:
        return {"ok": False, "error": "a probe of this device is already running", "mode": None, "data": None, "probe": probe}
    _running.add(key)
    conn = connect(db_path)
    try:
        try:
            result = await run(conn, device_id, probe, reason or ("manual" if actor else "schedule"))
        except ProbeFailed as exc:
            store(conn, device_id, False, None, str(exc), None, probe=probe, reason=reason or "manual")
            result = {"ok": False, "error": str(exc), "mode": None, "data": None, "credential": None, "probe": probe}
        _audit(conn, device_id, result, actor)
        return result
    finally:
        _running.discard(key)
        conn.close()


async def run_probes(db_path: str, device_id: int, probes: list[str], actor=None) -> dict[str, dict[str, Any]]:
    """Several probes of one host, one after the other (a host is not asked for everything at once)."""
    return {probe: await run_one(db_path, device_id, actor=actor, probe=probe) for probe in probes}


async def loop(db_path: str, interval: float = 60.0) -> None:
    await asyncio.sleep(30)
    gate = asyncio.Semaphore(2)

    async def one(device_id: int, probe: str, reason: str) -> None:
        async with gate:
            try:
                await run_one(db_path, device_id, probe=probe, reason=reason)
            except Exception:  # noqa: BLE001
                log.exception("host probe %s of device %s crashed", probe, device_id)

    while True:
        try:
            conn = connect(db_path)
            try:
                pairs = due_with_reason(conn)
            finally:
                conn.close()
            if pairs:
                await asyncio.gather(*(one(d, p, r) for d, p, r in pairs))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("host probe loop failed")
        await asyncio.sleep(interval)
