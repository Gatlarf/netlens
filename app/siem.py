"""Log forwarding (a paid feature): events and the audit log are sent to a syslog server or SIEM (Graylog, Splunk, Wazuh, Elastic, rsyslog ...).

Messages follow RFC 5424 over UDP or TCP (one message per line). Netlens remembers the last event and audit entry it sent, so after a restart or an outage it
continues where it stopped; a server that is down only delays the delivery. Severity follows the kind of event: the serious ones are `crit`, the rest `info` or
`warning`. The detail of each message is the same text you see in Netlens; passwords and tokens are never part of an event or an audit line.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from app import licence
from app.db import get_setting, set_setting

log = logging.getLogger(__name__)
KEY = "siem.policy"
STATUS = "siem.status"
CURSOR_EVENTS = "siem.cursor.events"
CURSOR_AUDIT = "siem.cursor.audit"
FACILITIES = {f"local{i}": 16 + i for i in range(8)} | {"user": 1, "daemon": 3, "auth": 4, "authpriv": 10}
BATCH = 200


class SiemError(ValueError):
    pass


def get_policy(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        doc = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        doc = {}
    return {"enabled": bool(doc.get("enabled")), "host": str(doc.get("host") or ""), "port": int(doc.get("port") or 514), "protocol": doc.get("protocol") if doc.get("protocol") in ("udp", "tcp") else "udp",
            "facility": doc.get("facility") if doc.get("facility") in FACILITIES else "local0", "send_events": doc.get("send_events", True) is not False, "send_audit": doc.get("send_audit", True) is not False}


def save_policy(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    cur = get_policy(conn)
    cur.update({k: v for k, v in data.items() if k in cur})
    host = str(cur["host"]).strip()
    if cur["enabled"] and not re.match(r"^[A-Za-z0-9._:-]{1,253}$", host):
        raise SiemError("enter the address of the syslog server")
    if not isinstance(cur["port"], int) or isinstance(cur["port"], bool) or not 1 <= cur["port"] <= 65535:
        raise SiemError("the port is between 1 and 65535")
    if cur["protocol"] not in ("udp", "tcp") or cur["facility"] not in FACILITIES:
        raise SiemError("choose udp or tcp, and a facility from the list")
    cur["host"] = host
    set_setting(conn, KEY, json.dumps(cur))
    return get_policy(conn)


def status(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        return json.loads(get_setting(conn, STATUS) or "{}")
    except ValueError:
        return {}


def severity(kind: str) -> int:
    from app.notify.channels import CRITICAL

    if kind in CRITICAL or kind.endswith(("_failed", "_critical")) or kind == "remediation_failed":
        return 2
    if kind.endswith(("_warning", "_offline", "_late", "_unhealthy", "_unavailable", "_pending")) or kind in ("login_failed", "licence_expiring", "link_down"):
        return 4
    return 6


def _clean(text: Any, limit: int = 1000) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(text or "")).strip()[:limit]


def format_message(facility: str, sev: int, ts: str, app_id: str, msg_id: str, fields: dict[str, Any], text: str, host: str = "netlens") -> str:
    """RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG"""
    pri = FACILITIES[facility] * 8 + sev
    structured = " ".join(f'{k}="{_clean(v, 200).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34)).replace("]", chr(92) + "]")}"' for k, v in fields.items() if v not in (None, ""))
    sd = f"[netlens@32473 {structured}]" if structured else "-"
    return f"<{pri}>1 {ts} {host} {app_id} - {msg_id} {sd} {_clean(text)}"


def pending(conn: sqlite3.Connection, policy: dict) -> tuple[list[str], dict[str, int]]:
    """The next messages to send and the cursors they would move to."""
    out: list[str] = []
    cursors: dict[str, int] = {}
    host = socket.gethostname().split(".")[0] or "netlens"
    if policy["send_events"]:
        last = get_setting(conn, CURSOR_EVENTS)
        top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        if last is None or not last.isdigit():
            set_setting(conn, CURSOR_EVENTS, str(top))            # what happened before the switch-on is not sent
            last = str(top)
        for e in conn.execute("SELECT e.id, e.ts, e.kind, e.detail, e.maintenance, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS device FROM events e LEFT JOIN devices d ON d.id = e.device_id "
                              "WHERE e.id > ? ORDER BY e.id LIMIT ?", (int(last), BATCH)):
            out.append(format_message(policy["facility"], severity(e["kind"]), e["ts"], "netlens", "EVENT", {"kind": e["kind"], "device": e["device"], "maintenance": e["maintenance"]}, e["detail"] or e["kind"], host))
            cursors[CURSOR_EVENTS] = e["id"]
    if policy["send_audit"]:
        last = get_setting(conn, CURSOR_AUDIT)
        top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log").fetchone()[0]
        if last is None or not last.isdigit():
            set_setting(conn, CURSOR_AUDIT, str(top))
            last = str(top)
        for a in conn.execute("SELECT id, ts, user, role, ip, method, path, status, action FROM audit_log WHERE id > ? ORDER BY id LIMIT ?", (int(last), BATCH)):
            out.append(format_message(policy["facility"], 6 if a["status"] < 400 else 4, a["ts"], "netlens", "AUDIT", {"user": a["user"], "role": a["role"], "src": a["ip"], "method": a["method"], "path": a["path"], "status": a["status"]}, a["action"], host))
            cursors[CURSOR_AUDIT] = a["id"]
    return out, cursors


def send(policy: dict, messages: list[str], timeout: float = 8.0) -> None:
    data = [m.encode("utf-8", "replace") for m in messages]
    try:
        if policy["protocol"] == "udp":
            with socket.socket(socket.AF_INET6 if ":" in policy["host"] else socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for chunk in data:
                    sock.sendto(chunk[:1400], (policy["host"], policy["port"]))
        else:
            with socket.create_connection((policy["host"], policy["port"]), timeout=timeout) as sock:
                sock.sendall(b"".join(chunk + b"\n" for chunk in data))
    except OSError as exc:
        raise SiemError(f"cannot send to {policy['host']}:{policy['port']}: {exc}") from None


def run_once(conn: sqlite3.Connection, sender: Callable[[dict, list[str]], None] = send, now: datetime | None = None) -> int:
    policy = get_policy(conn)
    if not policy["enabled"] or not policy["host"] or not licence.allows(conn, "siem", now):
        return 0
    messages, cursors = pending(conn, policy)
    if not messages:
        return 0
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        sender(policy, messages)
    except SiemError as exc:
        set_setting(conn, STATUS, json.dumps({"ts": stamp, "ok": False, "error": str(exc)}))
        return 0
    for key, value in cursors.items():
        set_setting(conn, key, str(value))
    set_setting(conn, STATUS, json.dumps({"ts": stamp, "ok": True, "sent": len(messages)}))
    return len(messages)


def test_message(conn: sqlite3.Connection, sender: Callable[[dict, list[str]], None] = send) -> None:
    policy = get_policy(conn)
    if not policy["host"]:
        raise SiemError("enter the address of the syslog server first")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sender(policy, [format_message(policy["facility"], 6, ts, "netlens", "TEST", {"kind": "test"}, "Netlens log forwarding test", socket.gethostname().split(".")[0] or "netlens")])


async def loop(db_path: str) -> None:
    from app.db import connect

    await asyncio.sleep(35)
    while True:
        try:
            conn = connect(db_path)
            try:
                while await asyncio.to_thread(run_once, conn) >= BATCH:
                    pass
            finally:
                conn.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - forwarding must never stop the monitoring
            log.exception("log forwarding round failed")
        await asyncio.sleep(15)
