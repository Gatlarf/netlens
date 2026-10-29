"""Auto-remediation (a paid feature): when an event happens, a rule can fix it, or propose the fix.

A rule says: for these events (optionally on one device, optionally with some text in the message) do this action. The actions are a short fixed list,
never free-form: wake a device (Wake-on-LAN), call a web address (a Home Assistant webhook, n8n, a Portainer stack webhook ...), or run one command that
the administrator wrote down, over the SSH login that the device's host monitor already has. Each rule has a mode:

  suggest   only shown on the Remediation page
  ask       shown and announced as an alert; an administrator approves or denies it
  auto      done at once
  engineer  asked: the digital engineer (an LLM, see app/engineer.py) reads the situation and when it recommends this rule with high confidence the action
            is approved for it; otherwise it waits for an administrator like "ask"

Guardrails that apply to every mode: a cooldown per rule and device, a daily limit per rule and an hourly limit for everything, nothing while a
maintenance window or a snooze holds the event, and a pause switch for the whole feature. Every run, its result and whether the problem went away
afterwards are kept and shown.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app import licence, vault
from app.db import add_event, ago, get_setting, insert_id, main_file, set_setting, utcnow

log = logging.getLogger(__name__)
STAMP = "%Y-%m-%dT%H:%M:%SZ"
ACTIONS = ("wake", "webhook", "ssh", "vm")
POWER = {"reset": "hard reset", "reboot": "clean restart", "shutdown": "clean shutdown", "start": "start"}
MODES = ("suggest", "ask", "auto", "engineer")
CURSOR = "remediation.cursor"
PAUSED = "remediation.paused"
HOURLY_LIMIT = 10
RECOVERY = {"service_down": "service_up", "device_offline": "device_online", "metric_critical": "metric_ok", "metric_warning": "metric_ok", "remote_offline": "remote_online",
            "remote_service_down": "remote_service_up", "inventory_unavailable": "inventory_available", "guest_backup_failed": "guest_backup_recovered", "storage_degraded": "storage_recovered",
            "probe_offline": "probe_online", "central_unreachable": "central_reachable", "remote_metric_critical": "remote_metric_ok", "remote_metric_warning": "remote_metric_ok"}
RECOVERY_WINDOW = timedelta(minutes=60)


class RuleError(ValueError):
    pass


# ----------------------------------------------------------------------------- rules
def trigger_kinds() -> list[str]:
    from app.notify.channels import EVENT_LABELS

    return [k for k in EVENT_LABELS if not k.startswith("report_") and not k.startswith("remediation_") and k not in ("login_failed", "licence_expiring")]


def _text(value: Any, label: str, limit: int, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise RuleError(f"give {label}")
    if len(text) > limit:
        raise RuleError(f"{label} is too long (at most {limit} characters)")
    return text


def _blocked_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in ("localhost", "metadata.google.internal")
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast


def clean_rule(conn: sqlite3.Connection, data: dict, current: dict | None = None) -> dict:
    """Validated rule fields ready to store; RuleError with a sentence for the user. `current` carries the stored rule for a partial update."""
    cur = current or {}
    name = _text(data.get("name", cur.get("name")), "the rule a name", 80, True)
    kinds = data.get("kinds", cur.get("kinds") or [])
    allowed = set(trigger_kinds())
    if not isinstance(kinds, list) or not kinds or any(k not in allowed for k in kinds):
        raise RuleError("choose at least one event this rule reacts to")
    device_id = data.get("device_id", cur.get("device_id"))
    if device_id in ("", None):
        device_id = None
    elif not isinstance(device_id, int) or isinstance(device_id, bool) or not conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone():
        raise RuleError("that device does not exist")
    mode = data.get("mode", cur.get("mode") or "ask")
    if mode not in MODES:
        raise RuleError("the mode must be one of: " + ", ".join(MODES))
    cooldown = data.get("cooldown_min", cur.get("cooldown_min", 30))
    per_day = data.get("max_per_day", cur.get("max_per_day", 3))
    if not isinstance(cooldown, int) or isinstance(cooldown, bool) or not 1 <= cooldown <= 1440:
        raise RuleError("the cooldown is between 1 and 1440 minutes")
    if not isinstance(per_day, int) or isinstance(per_day, bool) or not 1 <= per_day <= 50:
        raise RuleError("the daily limit is between 1 and 50")
    action = data.get("action", cur.get("action") or {})
    if not isinstance(action, dict) or action.get("type") not in ACTIONS:
        raise RuleError("choose an action: " + ", ".join(ACTIONS))
    kind = action["type"]
    secret = dict(cur.get("secret") or {})
    if kind == "wake":
        out = {"type": "wake"}
    elif kind == "webhook":
        url = _text(action.get("url"), "the web address", 500, True)
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RuleError("the web address must start with http:// or https://")
        if _blocked_host(parts.hostname):
            raise RuleError("this address (localhost, link-local) is not allowed")
        method = str(action.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            raise RuleError("the method is GET or POST")
        out = {"type": "webhook", "url": url, "method": method, "body": _text(action.get("body"), "the body", 2000), "header_name": _text(action.get("header_name"), "the header name", 60)}
        if action.get("header_value"):
            secret["header_value"] = _text(action["header_value"], "the header value", 500)
        elif not out["header_name"]:
            secret.pop("header_value", None)
    elif kind == "vm":
        power = str(action.get("power") or "reset")
        if power not in POWER:
            raise RuleError("the power action is " + ", ".join(POWER))
        out = {"type": "vm", "power": power}
    else:
        command = _text(action.get("command"), "the command", 500, True)
        if "\n" in command or "\r" in command:
            raise RuleError("one command on one line (use && or a script on the device for more)")
        out = {"type": "ssh", "command": command}
    return {"name": name, "enabled": bool(data.get("enabled", cur.get("enabled", True))), "kinds": kinds, "device_id": device_id, "match_text": _text(data.get("match_text", cur.get("match_text")), "the text", 100),
            "action": out, "secret": secret, "mode": mode, "cooldown_min": cooldown, "max_per_day": per_day}


def _row_to_rule(conn: sqlite3.Connection, row: sqlite3.Row, with_secret: bool = False) -> dict:
    secret: dict = {}
    if row["secret"]:
        try:
            secret = json.loads(vault.decrypt(conn, row["secret"]))
        except (vault.VaultError, ValueError):
            secret = {}
    rule = {"id": row["id"], "name": row["name"], "enabled": bool(row["enabled"]), "kinds": json.loads(row["kinds"] or "[]"), "device_id": row["device_id"], "match_text": row["match_text"],
            "action": json.loads(row["action"]), "mode": row["mode"], "cooldown_min": row["cooldown_min"], "max_per_day": row["max_per_day"], "created": row["created"]}
    if with_secret:
        rule["secret"] = secret
    else:
        rule["action"] = {**rule["action"], "has_header_value": bool(secret.get("header_value"))}
    return rule


def list_rules(conn: sqlite3.Connection, with_secret: bool = False) -> list[dict]:
    return [_row_to_rule(conn, r, with_secret) for r in conn.execute("SELECT * FROM remediation_rules ORDER BY LOWER(name)")]


def get_rule(conn: sqlite3.Connection, rule_id: int, with_secret: bool = False) -> dict | None:
    row = conn.execute("SELECT * FROM remediation_rules WHERE id = ?", (rule_id,)).fetchone()
    return _row_to_rule(conn, row, with_secret) if row else None


def _store_secret(conn: sqlite3.Connection, secret: dict) -> str:
    return vault.encrypt(conn, json.dumps(secret)) if secret else ""


def save_rule(conn: sqlite3.Connection, data: dict, rule_id: int | None = None) -> dict:
    current = get_rule(conn, rule_id, with_secret=True) if rule_id else None
    if rule_id and current is None:
        raise RuleError("that rule does not exist")
    fields = clean_rule(conn, data, current)
    if rule_id is None:
        rule_id = insert_id(
            conn,
            "INSERT INTO remediation_rules (name, enabled, kinds, device_id, match_text, action, secret, mode, cooldown_min, max_per_day, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fields["name"], int(fields["enabled"]), json.dumps(fields["kinds"]), fields["device_id"], fields["match_text"], json.dumps(fields["action"]), _store_secret(conn, fields["secret"]),
             fields["mode"], fields["cooldown_min"], fields["max_per_day"], utcnow()))
    else:
        conn.execute(
            "UPDATE remediation_rules SET name = ?, enabled = ?, kinds = ?, device_id = ?, match_text = ?, action = ?, secret = ?, mode = ?, cooldown_min = ?, max_per_day = ? WHERE id = ?",
            (fields["name"], int(fields["enabled"]), json.dumps(fields["kinds"]), fields["device_id"], fields["match_text"], json.dumps(fields["action"]), _store_secret(conn, fields["secret"]),
             fields["mode"], fields["cooldown_min"], fields["max_per_day"], rule_id))
    conn.commit()
    return get_rule(conn, rule_id)


def delete_rule(conn: sqlite3.Connection, rule_id: int) -> None:
    conn.execute("DELETE FROM remediation_rules WHERE id = ?", (rule_id,))
    conn.commit()


# ----------------------------------------------------------------------------- the actions
def _device(conn: sqlite3.Connection, device_id: int | None) -> sqlite3.Row | None:
    return conn.execute("SELECT id, mac, primary_ip, hostname, custom_name FROM devices WHERE id = ?", (device_id,)).fetchone() if device_id else None


def _fill(text: str, device: sqlite3.Row | None, run: dict, mode: str = "text") -> str:
    """Put the device and the event into a template. What goes in comes from the network (a device chooses its own host name), so it is escaped for where it lands:
    `url` percent-encodes it (a name like "x/../admin?y=" cannot change the address), `json` escapes it for a JSON string, `text` leaves it alone."""
    import json as _json
    import urllib.parse as _up

    def esc(value: str) -> str:
        value = str(value or "")
        if mode == "url":
            return _up.quote(value, safe="")
        if mode == "json":
            return _json.dumps(value)[1:-1]
        return value

    name = (device["custom_name"] or device["hostname"] or device["primary_ip"] or "") if device else ""
    return (text.replace("{device}", esc(name)).replace("{ip}", esc((device["primary_ip"] or "") if device else "")).replace("{event}", esc(run.get("kind") or ""))
            .replace("{detail}", esc(run.get("detail") or "")))


def run_wake(conn: sqlite3.Connection, rule: dict, run: dict) -> str:
    from app import actions

    device = _device(conn, run.get("device_id"))
    if device is None or not device["mac"]:
        raise RuntimeError("the event has no device with a MAC address to wake")
    return "Wake-on-LAN sent to " + ", ".join(actions.wake(device["mac"], device["primary_ip"]))


def run_webhook(conn: sqlite3.Connection, rule: dict, run: dict) -> str:
    action, secret = rule["action"], rule.get("secret") or {}
    device = _device(conn, run.get("device_id"))
    template = action.get("body") or ""
    body = _fill(template, device, run, "json" if template.lstrip().startswith(("{", "[")) else "text").encode() if action["method"] == "POST" else None
    from app import safenet

    try:
        url = safenet.check_url(_fill(action["url"], device, run, "url"), what="the address of the rule")
    except safenet.BlockedAddress as exc:
        raise RuntimeError(str(exc)) from None
    request = urllib.request.Request(url, data=body, method=action["method"], headers={"User-Agent": "Netlens-remediation", "Content-Type": "application/json"})
    if action.get("header_name") and secret.get("header_value"):
        request.add_header(action["header_name"], secret["header_value"])

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as resp:        # noqa: S310 - scheme checked when the rule was saved
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"cannot reach the address: {getattr(exc, 'reason', exc)}") from None
    if not 200 <= code < 300:
        raise RuntimeError(f"the address answered HTTP {code}")
    return f"HTTP {code}"


def run_ssh(conn: sqlite3.Connection, rule: dict, run: dict) -> str:
    from app.hostmetrics import service as hm
    from app.hostmetrics import ssh
    from app.terminal.hostkeys import get_fingerprint

    device_id = rule.get("device_id") or run.get("device_id")
    monitor = hm.get_monitor(conn, device_id) if device_id else None
    if monitor is None or monitor["method"] != "ssh":
        raise RuntimeError("the device needs an SSH host monitor (device page, Monitor) so Netlens has a login to use")
    secret = hm.load_secret(conn, monitor)
    if not secret:
        raise RuntimeError(hm.unreadable_text(conn, monitor, "the login of the host monitor cannot be read"))
    out, status, _fp = asyncio.run(ssh.run_command(monitor["address"], monitor["port"], secret.get("username", ""), secret.get("password"), secret.get("private_key"), secret.get("passphrase"),
                                                   rule["action"]["command"], get_fingerprint(conn, device_id), timeout=60.0, route=secret.get("route")))
    text = " ".join(out.split())[:300]
    if status not in (0, None):
        raise RuntimeError(f"the command ended with status {status}" + (f": {text}" if text else ""))
    return "done" + (f": {text}" if text else "")


POWER_RUNNER = None        # replaced by tests: (plugin, "power", config, payload=...)


def run_vm(conn: sqlite3.Connection, rule: dict, run: dict) -> str:
    """Reset, restart, shut down or start the virtual machine this device is, through the hypervisor plugin that reported it."""
    from pathlib import Path

    from app.plugins.registry import discover
    from app.plugins.runner import run_subprocess
    from app.plugins.service import get_state

    device_id = rule.get("device_id") or run.get("device_id")
    guest = conn.execute("SELECT * FROM hypervisor_guests WHERE device_id = ? ORDER BY updated DESC LIMIT 1", (device_id,)).fetchone() if device_id else None
    if guest is None:
        raise RuntimeError("no hypervisor plugin has reported this device as a virtual machine (install the plugin of its hypervisor and let it sync)")
    plugin = discover(Path(main_file(conn)).parent).get(guest["plugin_id"])
    power = rule["action"]["power"]
    if plugin is None or plugin.manifest is None:
        raise RuntimeError(f"the plugin {guest['plugin_id']} is not available")
    if power not in plugin.manifest.get("power", []):
        raise RuntimeError(f"the plugin {plugin.name} cannot do a {POWER[power]} (update it to a newer version)")
    payload = {"guest_id": guest["guest_id"], "host": guest["host_name"], "name": guest["name"], "kind": guest["kind"], "action": power}
    out = (POWER_RUNNER or run_subprocess)(plugin, "power", get_state(conn, plugin)["config"], payload=payload)
    message = out.get("message") if isinstance(out, dict) else None
    return str(message or f"{POWER[power]} sent to {guest['name']}")[:300]


RUNNERS: dict[str, Callable[[sqlite3.Connection, dict, dict], str]] = {"wake": run_wake, "webhook": run_webhook, "ssh": run_ssh, "vm": run_vm}


def execute(conn: sqlite3.Connection, run_id: int, runners: dict | None = None, now: datetime | None = None) -> dict:
    """Perform the action of a run (blocking: call it in a thread) and record the result."""
    run = _run(conn, run_id)
    rule = get_rule(conn, run["rule_id"], with_secret=True) if run["rule_id"] else None
    stamp = (now or datetime.now(timezone.utc)).strftime(STAMP)
    if rule is None:
        conn.execute("UPDATE remediation_runs SET state = 'failed', result = ?, finished = ? WHERE id = ?", ("the rule was removed", stamp, run_id))
        conn.commit()
        return _run(conn, run_id)
    conn.execute("UPDATE remediation_runs SET state = 'running' WHERE id = ?", (run_id,))
    conn.commit()
    try:
        result = (runners or RUNNERS)[rule["action"]["type"]](conn, rule, run)
        state = "ok"
    except Exception as exc:  # noqa: BLE001 - whatever an action raises is the result, not a crash
        result, state = str(exc)[:300] or exc.__class__.__name__, "failed"
    conn.execute("UPDATE remediation_runs SET state = ?, result = ?, finished = ? WHERE id = ?", (state, result, stamp, run_id))
    conn.commit()
    label = _label(conn, run)
    add_event(conn, "remediation_ran" if state == "ok" else "remediation_failed", f"{rule['name']} on {label}: {result}", device_id=run["device_id"], now=stamp)
    return _run(conn, run_id)


# ----------------------------------------------------------------------------- runs
def _run(conn: sqlite3.Connection, run_id: int) -> dict:
    row = conn.execute("SELECT * FROM remediation_runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise RuleError("that run does not exist")
    out = dict(row)
    out["analysis"] = json.loads(out["analysis"]) if out.get("analysis") else None
    return out


def _label(conn: sqlite3.Connection, run: dict) -> str:
    device = _device(conn, run.get("device_id"))
    return (device["custom_name"] or device["hostname"] or device["primary_ip"] or "the device") if device else "the network"


def recent_runs(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute("SELECT * FROM remediation_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    names = {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    out = []
    for r in rows:
        d = dict(r)
        d["analysis"] = json.loads(d["analysis"]) if d.get("analysis") else None
        d["device"] = names.get(d["device_id"])
        out.append(d)
    return out


def _new_run(conn: sqlite3.Connection, rule: dict, event: dict | None, state: str, stamp: str, device_id: int | None = None, result: str | None = None) -> int:
    new_id = insert_id(
        conn,
        "INSERT INTO remediation_runs (rule_id, rule_name, action_type, event_id, device_id, kind, detail, state, result, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (rule["id"], rule["name"], rule["action"]["type"], event["id"] if event else None, device_id if device_id is not None else (event or {}).get("device_id"), (event or {}).get("kind"),
         ((event or {}).get("detail") or "")[:300], state, result, stamp))
    conn.commit()
    return new_id


def paused(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, PAUSED) == "1"


def set_paused(conn: sqlite3.Connection, value: bool) -> None:
    set_setting(conn, PAUSED, "1" if value else "0")


def _blocked(conn: sqlite3.Connection, rule: dict, device_id: int | None, now: datetime) -> str | None:
    """Why a run must not happen now (None = fine)."""
    since = (now - timedelta(minutes=rule["cooldown_min"])).strftime(STAMP)
    if conn.execute("SELECT 1 FROM remediation_runs WHERE rule_id = ? AND device_id IS ? AND created >= ? AND state NOT IN ('skipped', 'denied', 'suggested') LIMIT 1", (rule["id"], device_id, since)).fetchone():
        return "cooldown"
    day = (now - timedelta(hours=24)).strftime(STAMP)
    if conn.execute("SELECT COUNT(*) FROM remediation_runs WHERE rule_id = ? AND created >= ? AND state IN ('ok', 'failed', 'running')", (rule["id"], day)).fetchone()[0] >= rule["max_per_day"]:
        return "daily limit"
    hour = (now - timedelta(hours=1)).strftime(STAMP)
    if conn.execute("SELECT COUNT(*) FROM remediation_runs WHERE created >= ? AND state IN ('ok', 'failed', 'running')", (hour,)).fetchone()[0] >= HOURLY_LIMIT:
        return "hourly limit"
    return None


def matches(rule: dict, event: dict) -> bool:
    if not rule["enabled"] or event["kind"] not in rule["kinds"]:
        return False
    if rule["device_id"] is not None and event.get("device_id") != rule["device_id"]:
        return False
    return not rule["match_text"] or rule["match_text"].lower() in (event.get("detail") or "").lower()


def plan(conn: sqlite3.Connection, now: datetime | None = None) -> list[int]:
    """Look at the events since the last time and open runs for the rules that match (nothing is executed here). Returns the ids of runs to execute now."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime(STAMP)
    top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
    cursor = get_setting(conn, CURSOR)
    if cursor is None or not cursor.isdigit():
        set_setting(conn, CURSOR, str(top))                    # the first look: what happened before is not news
        return []
    if not licence.allows(conn, "remediation", now):
        set_setting(conn, CURSOR, str(top))
        return []
    rows = conn.execute("SELECT id, ts, device_id, kind, detail, maintenance FROM events WHERE id > ? ORDER BY id LIMIT 300", (int(cursor),)).fetchall()
    if not rows:
        return []
    rules = [r for r in list_rules(conn) if r["enabled"]]
    to_run: list[int] = []
    for row in rows:
        event = dict(row)
        if event["kind"].startswith("remediation_") or event.get("maintenance"):
            continue
        for rule in rules:
            if not matches(rule, event):
                continue
            why = _blocked(conn, rule, event["device_id"], now)
            if why:
                if why != "cooldown" and not conn.execute("SELECT 1 FROM remediation_runs WHERE rule_id = ? AND state = 'skipped' AND created >= ?", (rule["id"], (now - timedelta(hours=6)).strftime(STAMP))).fetchone():
                    _new_run(conn, rule, event, "skipped", stamp, result=f"not done: {why} reached")
                continue
            if paused(conn):
                continue
            if rule["mode"] == "auto":
                to_run.append(_new_run(conn, rule, event, "pending", stamp))
            elif rule["mode"] == "suggest":
                _new_run(conn, rule, event, "suggested", stamp)
            else:                                               # ask, engineer
                run_id = _new_run(conn, rule, event, "pending", stamp)
                add_event(conn, "remediation_pending", f"{rule['name']} on {_label(conn, {'device_id': event['device_id']})} is waiting for approval (Monitoring → Remediation)",
                          device_id=event["device_id"], now=stamp)
                if rule["mode"] == "engineer":
                    to_run.append(-run_id)                      # a negative id: ask the engineer first
    set_setting(conn, CURSOR, str(rows[-1]["id"]))
    return to_run


def decide(conn: sqlite3.Connection, run_id: int, approve: bool, who: str, now: datetime | None = None, runners: dict | None = None) -> dict:
    """An administrator approves or denies a waiting run. Approving executes it (blocking)."""
    run = _run(conn, run_id)
    if run["state"] not in ("pending", "suggested"):
        raise RuleError("this run was already decided")
    if approve and not licence.allows(conn, "remediation", now):
        raise RuleError("auto-remediation needs a licence (Settings → Licence)")
    stamp = (now or datetime.now(timezone.utc)).strftime(STAMP)
    conn.execute("UPDATE remediation_runs SET decided_by = ?, decided_at = ?, state = ? WHERE id = ?", (who, stamp, "pending" if approve else "denied", run_id))
    conn.commit()
    return execute(conn, run_id, runners, now) if approve else _run(conn, run_id)


def check_recovery(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """Note which successful runs were followed by the matching recovery event, and announce it."""
    now = now or datetime.now(timezone.utc)
    horizon = (now - RECOVERY_WINDOW).strftime(STAMP)
    count = 0
    for run in conn.execute("SELECT * FROM remediation_runs WHERE state = 'ok' AND recovered IS NULL AND finished >= ? AND kind IS NOT NULL AND device_id IS NOT NULL", (horizon,)).fetchall():
        good = RECOVERY.get(run["kind"])
        if good and conn.execute("SELECT 1 FROM events WHERE kind = ? AND device_id = ? AND ts >= ? LIMIT 1", (good, run["device_id"], run["finished"])).fetchone():
            stamp = now.strftime(STAMP)
            conn.execute("UPDATE remediation_runs SET recovered = ? WHERE id = ?", (stamp, run["id"]))
            conn.commit()
            add_event(conn, "remediation_recovered", f"{run['rule_name']} on {_label(conn, dict(run))}: the problem is gone", device_id=run["device_id"], now=stamp)
            count += 1
    return count


def summary(conn: sqlite3.Connection) -> dict[str, int]:
    one = lambda sql, *args: conn.execute(sql, args).fetchone()[0]    # noqa: E731
    return {"rules": one("SELECT COUNT(*) FROM remediation_rules WHERE enabled = 1"), "pending": one("SELECT COUNT(*) FROM remediation_runs WHERE state = 'pending'"),
            "failed_today": one("SELECT COUNT(*) FROM remediation_runs WHERE state = 'failed' AND created >= ?", ago(days=1))}


async def process(db_path: str, *, runners: dict | None = None, now: datetime | None = None, ask=None) -> dict:
    """One round: open runs for new events, execute the automatic ones, let the engineer judge the others, note recoveries."""
    from app.db import connect

    out = {"executed": 0, "recovered": 0}
    conn = connect(db_path)
    try:
        todo = await asyncio.to_thread(plan, conn, now)
        for run_id in todo:
            if run_id < 0:
                from app import engineer

                run_id = -run_id
                try:
                    verdict = await asyncio.to_thread(engineer.advise, conn, run_id, ask)
                except Exception:  # noqa: BLE001 - an unreachable engineer only means a person has to decide
                    log.debug("the digital engineer could not be asked", exc_info=True)
                    continue
                run = _run(conn, run_id)
                if verdict and verdict.get("approve") and run["state"] == "pending":
                    await asyncio.to_thread(decide, conn, run_id, True, "digital engineer", now, runners)
                    out["executed"] += 1
                continue
            await asyncio.to_thread(execute, conn, run_id, runners, now)
            out["executed"] += 1
        out["recovered"] = await asyncio.to_thread(check_recovery, conn, now)
    finally:
        conn.close()
    if out["executed"] or out["recovered"]:
        from app.notify.channels import process_channels

        await process_channels(db_path)
    return out


async def loop(db_path: str) -> None:
    await asyncio.sleep(25)
    while True:
        try:
            await process(db_path)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - remediation must never stop the monitoring
            log.exception("auto-remediation round failed")
        await asyncio.sleep(15)
