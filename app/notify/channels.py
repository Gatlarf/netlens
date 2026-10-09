"""Notification channels beyond e-mail: ntfy, Telegram, Discord, Pushover and a generic webhook.

Every channel has its own list of events it wants, and its own position in the event log, so a channel that fails
catches up later without disturbing the others. Quiet hours hold messages back (a service going down can still break
through) and deliver them afterwards as one digest.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.db import connect, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)
CHANNELS_KEY = "notify.channels"
QUIET_KEY = "notify.quiet"
MAX_CHANNELS = 20
MAX_EVENTS_PER_MESSAGE = 40
CRITICAL = {"service_down"}
_lock = asyncio.Lock()

TYPES: dict[str, dict[str, Any]] = {
    "ntfy": {"label": "ntfy", "fields": [
        {"key": "server", "label": "Server", "default": "https://ntfy.sh", "required": True, "help": "https://ntfy.sh or your own ntfy server"},
        {"key": "topic", "label": "Topic", "required": True, "help": "Anyone who knows the topic name can read it on ntfy.sh: pick a long random one."},
        {"key": "token", "label": "Access token", "secret": True, "help": "Only for servers that need a login."},
        {"key": "priority", "label": "Priority", "default": "default", "help": "min, low, default, high or max"},
    ]},
    "telegram": {"label": "Telegram", "fields": [
        {"key": "bot_token", "label": "Bot token", "secret": True, "required": True, "help": "From @BotFather"},
        {"key": "chat_id", "label": "Chat ID", "required": True, "help": "Your chat or group id (message the bot first)"},
    ]},
    "discord": {"label": "Discord", "fields": [
        {"key": "webhook_url", "label": "Webhook URL", "secret": True, "required": True, "help": "Channel settings -> Integrations -> Webhooks"},
    ]},
    "pushover": {"label": "Pushover", "fields": [
        {"key": "app_token", "label": "Application token", "secret": True, "required": True},
        {"key": "user_key", "label": "User key", "secret": True, "required": True},
    ]},
    "webhook": {"label": "Webhook (JSON)", "fields": [
        {"key": "url", "label": "URL", "required": True, "help": "Netlens POSTs {title, message, events[]} as JSON. Works with Home Assistant webhooks, n8n, Node-RED and similar."},
        {"key": "secret", "label": "Bearer token", "secret": True, "help": "Sent as 'Authorization: Bearer ...' when set."},
    ]},
}

EVENT_LABELS = {
    "device_new": "A new (unknown) device appears",
    "device_offline": "A device goes offline",
    "device_online": "A device comes back online",
    "service_down": "A service check goes down",
    "service_up": "A service check recovers",
    "port_opened": "A new port opens on a device",
    "ip_changed": "A device changes its IP address",
    "ip_reused": "An IP address is taken over by another device",
    "os_changed": "A device's operating system changes",
    "wifi_roamed": "A Wi-Fi device moves to another mesh node",
    "host_timeout": "A host times out during a scan",
    "backup_failed": "A scheduled backup fails",
}
DEFAULT_EVENTS = ["device_new", "device_offline", "service_down", "service_up", "port_opened"]


class ChannelError(Exception):
    """Sending failed; the message is safe to show (it never contains tokens)."""


# ----------------------------------------------------------------------------- storage
def load_channels(conn: sqlite3.Connection) -> list[dict]:
    try:
        data = json.loads(get_setting(conn, CHANNELS_KEY) or "[]")
    except ValueError:
        return []
    return [c for c in data if isinstance(c, dict) and c.get("type") in TYPES] if isinstance(data, list) else []


def save_channels(conn: sqlite3.Connection, channels: list[dict]) -> None:
    set_setting(conn, CHANNELS_KEY, json.dumps(channels))


def current_max_event_id(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]


def public_channel(ch: dict) -> dict:
    """The channel without its secrets (only whether each is set)."""
    spec = TYPES[ch["type"]]
    secret_keys = {f["key"] for f in spec["fields"] if f.get("secret")}
    return {
        "id": ch["id"], "type": ch["type"], "name": ch["name"], "enabled": ch["enabled"], "events": ch["events"],
        "settings": {k: v for k, v in ch["settings"].items() if k not in secret_keys},
        "secrets_set": {k: bool(ch["settings"].get(k)) for k in secret_keys},
        "status": ch.get("status"),
    }


def clean_settings(channel_type: str, values: dict, current: dict | None = None) -> dict:
    """Validate form values for a channel type. A secret left empty keeps its saved value."""
    spec = TYPES[channel_type]
    out = {}
    current = current or {}
    for f in spec["fields"]:
        key = f["key"]
        raw = values.get(key)
        if f.get("secret") and (raw is None or raw == ""):
            raw = current.get(key, "")
        if raw is None:
            raw = current.get(key, f.get("default", ""))
        value = str(raw).strip()
        if not value:
            value = f.get("default", "") if not f.get("secret") else ""
        if f.get("required") and not value:
            raise ValueError(f"{f['label']} is required")
        if len(value) > 500:
            raise ValueError(f"{f['label']} is too long")
        out[key] = value
    for key in ("server", "url", "webhook_url"):
        if out.get(key):
            parsed = urllib.parse.urlparse(out[key])
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("the address must start with http:// or https://")
    if channel_type == "ntfy":
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", out["topic"]):
            raise ValueError("the topic may only contain letters, digits, '-' and '_'")
        if out["priority"] not in ("min", "low", "default", "high", "max", "1", "2", "3", "4", "5"):
            raise ValueError("priority must be min, low, default, high or max")
    return out


def clean_events(events: Any) -> list[str]:
    if not isinstance(events, list):
        raise ValueError("events must be a list")
    unknown = [e for e in events if e not in EVENT_LABELS]
    if unknown:
        raise ValueError(f"unknown event: {unknown[0]}")
    return [e for e in EVENT_LABELS if e in events]


def new_channel_id() -> str:
    return secrets.token_hex(4)


# ----------------------------------------------------------------------------- quiet hours
def load_quiet(conn: sqlite3.Connection) -> dict:
    default = {"enabled": False, "start": "23:00", "end": "07:00", "tz": "UTC", "offset_min": 0, "bypass_critical": True}
    try:
        data = json.loads(get_setting(conn, QUIET_KEY) or "{}")
    except ValueError:
        return default
    return {**default, **{k: v for k, v in data.items() if k in default}} if isinstance(data, dict) else default


def clean_quiet(data: dict) -> dict:
    out = {"enabled": bool(data.get("enabled")), "bypass_critical": bool(data.get("bypass_critical", True))}
    for key in ("start", "end"):
        value = str(data.get(key) or "")
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", value):
            raise ValueError(f"{key} must look like 23:00")
        out[key] = value
    tz = str(data.get("tz") or "UTC")
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{1,60}", tz):
        raise ValueError("invalid time zone")
    offset = data.get("offset_min", 0)
    if isinstance(offset, bool) or not isinstance(offset, int) or not -840 <= offset <= 840:
        raise ValueError("invalid UTC offset")
    out["tz"], out["offset_min"] = tz, offset
    return out


def local_time(now: datetime, quiet: dict) -> datetime:
    try:
        from zoneinfo import ZoneInfo

        return now.astimezone(ZoneInfo(quiet["tz"]))
    except Exception:  # noqa: BLE001 - no tz database or an unknown name: fall back to the offset the browser gave
        return now.astimezone(timezone(timedelta(minutes=quiet["offset_min"])))


def in_quiet_hours(now: datetime, quiet: dict) -> bool:
    if not quiet["enabled"]:
        return False
    t = local_time(now, quiet).strftime("%H:%M")
    start, end = quiet["start"], quiet["end"]
    if start == end:
        return False
    return start <= t < end if start < end else (t >= start or t < end)


# ----------------------------------------------------------------------------- messages
def _line(e: dict) -> str:
    name, ip, kind = e["name"], e["ip"] or "", e["kind"]
    where = f"{name} ({ip})" if ip and ip != name else name
    detail = e["detail"] or ""
    if kind == "device_new":
        flag = "" if e.get("trusted") else " [unknown device]"
        extra = f", {e['vendor']}" if e.get("vendor") else ""
        return f"New device: {where}{extra}{flag}"
    return {
        "device_offline": f"Offline: {where}",
        "device_online": f"Back online: {where}",
        "port_opened": f"Port opened on {where}: {detail}",
        "ip_changed": f"{name}: IP changed {detail}",
        "os_changed": f"{where}: system changed {detail}",
        "wifi_roamed": f"{name} moved: {detail}",
        "host_timeout": f"Scan timeout: {detail}",
        "backup_failed": f"Scheduled backup failed: {detail}",
    }.get(kind, detail or kind)


def build_digest(events: list[dict], app_name: str = "Netlens") -> tuple[str, str]:
    counts: dict[str, int] = {}
    for e in events:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    short = {
        "device_new": "new device", "device_offline": "offline", "device_online": "back online", "service_down": "service down",
        "service_up": "service up", "port_opened": "port opened", "ip_changed": "IP changed", "ip_reused": "IP reused",
        "os_changed": "OS changed", "wifi_roamed": "Wi-Fi move", "host_timeout": "scan timeout", "backup_failed": "backup failed",
    }
    title = f"[{app_name}] " + ", ".join(f"{n} {short.get(k, k)}" for k, n in counts.items())
    lines = [_line(e) for e in events[:MAX_EVENTS_PER_MESSAGE]]
    if len(events) > MAX_EVENTS_PER_MESSAGE:
        lines.append(f"... and {len(events) - MAX_EVENTS_PER_MESSAGE} more")
    return title, "\n".join(lines)


# ----------------------------------------------------------------------------- sending
def http_post(url: str, data: bytes, headers: dict[str, str], timeout: float = 15.0) -> tuple[int, str]:
    request = urllib.request.Request(url, data=data, headers={"User-Agent": "Netlens", **headers}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - scheme validated when saved
            return resp.status, resp.read(2000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ChannelError(f"cannot reach the server ({getattr(exc, 'reason', exc.__class__.__name__)})") from None


Poster = Callable[[str, bytes, dict[str, str], float], tuple[int, str]]


def send_channel(channel: dict, title: str, body: str, events: list[dict], *, poster: Poster = http_post) -> None:
    """Send one message through a channel; raises ChannelError with a message that never contains a token."""
    s = channel["settings"]
    kind = channel["type"]
    json_headers = {"Content-Type": "application/json"}
    if kind == "ntfy":
        headers = {"Title": title.encode("ascii", "replace").decode(), "Priority": s.get("priority") or "default", "Tags": "satellite"}
        if s.get("token"):
            headers["Authorization"] = f"Bearer {s['token']}"
        status, text = poster(f"{s['server'].rstrip('/')}/{s['topic']}", body.encode("utf-8"), headers, 15.0)
    elif kind == "telegram":
        status, text = poster(f"https://api.telegram.org/bot{s['bot_token']}/sendMessage",
                              json.dumps({"chat_id": s["chat_id"], "text": f"{title}\n{body}"[:4000]}).encode(), json_headers, 15.0)
    elif kind == "discord":
        status, text = poster(s["webhook_url"], json.dumps({"content": f"**{title}**\n{body}"[:1900]}).encode(), json_headers, 15.0)
    elif kind == "pushover":
        form = urllib.parse.urlencode({"token": s["app_token"], "user": s["user_key"], "title": title[:250], "message": body[:1000] or title}).encode()
        status, text = poster("https://api.pushover.net/1/messages.json", form, {"Content-Type": "application/x-www-form-urlencoded"}, 15.0)
    else:  # webhook
        headers = dict(json_headers)
        if s.get("secret"):
            headers["Authorization"] = f"Bearer {s['secret']}"
        payload = {"source": "netlens", "title": title, "message": body, "events": [{k: e.get(k) for k in ("id", "ts", "kind", "name", "ip", "mac", "detail", "device_id")} for e in events]}
        status, text = poster(s["url"], json.dumps(payload).encode(), headers, 15.0)
    if not 200 <= status < 300:
        hint = {401: " (check the token)", 403: " (not allowed)", 404: " (check the address or topic)", 429: " (rate limited)"}.get(status, "")
        raise ChannelError(f"the service answered HTTP {status}{hint}")


# ----------------------------------------------------------------------------- processing
def _pending_events(conn: sqlite3.Connection, after_id: int) -> list[dict]:
    rows = conn.execute(
        """
        SELECT e.id, e.ts, e.kind, e.device_id, e.detail,
               COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, d.primary_ip AS ip, d.mac, d.vendor, d.trusted, d.notify_offline
        FROM events e LEFT JOIN devices d ON d.id = e.device_id
        WHERE e.id > ? ORDER BY e.id LIMIT 500
        """,
        (after_id,),
    ).fetchall()
    out = []
    for r in rows:
        e = dict(r)
        if not e["name"]:
            e["name"] = (e["detail"] or "").split(" ")[0] or "device"
        out.append(e)
    return out


async def process_channels(db_path: str, *, now: datetime | None = None, poster: Poster = http_post) -> dict:
    """Send what each enabled channel wants to hear about. Never raises for a failing channel."""
    now = now or datetime.now(timezone.utc)
    result = {"sent": 0, "failed": 0}
    async with _lock:
        conn = connect(db_path)
        try:
            channels = load_channels(conn)
            if not any(c["enabled"] for c in channels):
                return result
            quiet = load_quiet(conn)
            quiet_now = in_quiet_hours(now, quiet)
            changed = False
            for ch in channels:
                if not ch["enabled"]:
                    continue
                if ch.get("last_event_id") is None:
                    ch["last_event_id"] = current_max_event_id(conn)
                    changed = True
                    continue
                pending = _pending_events(conn, ch["last_event_id"])
                if not pending:
                    continue
                top = pending[-1]["id"]
                wanted = [e for e in pending if e["kind"] in ch["events"] and not (e["kind"] == "device_offline" and e["device_id"] is not None and e["notify_offline"] == 0)]
                if not wanted:
                    ch["last_event_id"] = top
                    changed = True
                    continue
                if quiet_now and not (quiet["bypass_critical"] and any(e["kind"] in CRITICAL for e in wanted)):
                    continue  # held back until the quiet hours end
                title, body = build_digest(wanted)
                try:
                    await asyncio.to_thread(send_channel, ch, title, body, wanted, poster=poster)
                except ChannelError as exc:
                    ch["status"] = {"ts": utcnow(), "ok": False, "error": str(exc), "pending": len(wanted)}
                    result["failed"] += 1
                else:
                    ch["last_event_id"] = top
                    ch["status"] = {"ts": utcnow(), "ok": True, "sent": len(wanted), "title": title}
                    result["sent"] += 1
                changed = True
            if changed:
                save_channels(conn, channels)
        finally:
            conn.close()
    return result
