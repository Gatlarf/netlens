
TASK: write app/notify/digest.py (full file, under 120 lines). Imports allowed: sqlite3, `from app.notify.config import NotifyConfig`.

Existing facts: table events(id, ts, device_id, kind, detail). Kinds relevant here: "device_new" (detail like "192.168.1.50 Acme Corp") and "device_offline" (detail is the ip). Table devices has: id, mac, primary_ip, hostname, vendor, custom_name, notify_offline (INTEGER 1/0, per-device switch for offline mails). device_id in events can be NULL (device deleted).

def current_max_event_id(conn) -> int      # MAX(id) of events, 0 when empty

def collect_events(conn, after_id: int, cfg: NotifyConfig) -> tuple[list[dict], int]
  - Look at ALL events with id > after_id ordered by id. The returned second value is the highest event id seen among them (after_id when none) so the caller can advance even when everything was filtered out.
  - Keep an event only if: kind == "device_new" and cfg.notify_new; or kind == "device_offline" and cfg.notify_offline and the joined device row exists with notify_offline == 1 (LEFT JOIN devices; if the device row is gone, drop the offline event).
  - Each kept event is a dict {"id","ts","kind","device_id","name","ip","mac","vendor"}: name = custom_name or hostname or primary_ip or the ip-looking first word of detail or "unknown device"; ip = primary_ip or first whitespace separated word of detail; mac and vendor from devices (None if missing).

def build_message(events: list[dict], app_name: str = "Netlens") -> tuple[str, str]
  - Returns (subject, body). Two sections, each only when non-empty: new devices first, then offline devices.
  - Subject: f"[{app_name}] " + parts joined by ", ": f"{n} new device(s)" -> "1 new device" / "3 new devices"; offline: "1 device offline" / "2 devices offline". Example: "[Netlens] 2 new devices, 1 device offline".
  - Body (plain text): a heading line "New devices:" then one line per event f"  - {name} ({ip}) MAC {mac or '-'} vendor {vendor or '-'} at {ts}", a blank line, then "Went offline:" with lines f"  - {name} ({ip}) at {ts}". End with a blank line and "-- sent by Netlens".
  - events is non-empty when called; if empty return ("", "").
