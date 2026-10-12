"""Everything the dashboard page needs on top of the summary: the problems worth a look, the latest events and a few small series."""
import json
import re
import sqlite3

from app.maintenance import covered
from app.stats import _ago, _pct, utcnow
from app import sites as sites_mod, speedtest


def _attention(s: dict, certs: list[dict], login_failed: int, down: list[str]) -> list[dict]:
    items: list[dict] = []

    def add(level: str, text: str, href: str) -> None:
        items.append({"level": level, "text": text, "href": href})

    if down:
        add("bad", f"{len(down)} service{'s' if len(down) != 1 else ''} down: {', '.join(down[:3])}{'…' if len(down) > 3 else ''}", "#/services")
    for p in s["plugins"]:
        if p["enabled"] and p["ok"] is False:
            add("bad", f"Plugin {p['id']} is failing" + (f": {p['error']}" if p.get("error") else ""), f"#/settings/plugin-{p['id']}")
    last = s["scans"]["last"]
    if last and last["status"] == "failed":
        add("bad", "The last scan failed", "#/scans")
    age = s["scans"]["last_ok_age_s"]
    if age is not None and age > 3 * 3600:
        add("warn", f"No scan finished for {age // 3600} hours", "#/scans")
    if s["backup"]["last_ok"] is False:
        add("bad", "The last backup failed", "#/settings/backup")
    c = s["containers"]
    if c["unhealthy"] or c["restarting"]:
        add("warn", f"{c['unhealthy']} unhealthy and {c['restarting']} restarting containers", "#/devices")
    expired = [x for x in certs if x["days"] < 0]
    soon = [x for x in certs if 0 <= x["days"] <= 14]
    if expired:
        add("bad", f"{len(expired)} certificate{'s' if len(expired) != 1 else ''} expired: {expired[0]['name']}", "#/stats")
    if soon:
        add("warn", f"Certificate {soon[0]['name']} ends in {soon[0]['days']} day{'s' if soon[0]['days'] != 1 else ''}", "#/stats")
    if s["sites"]["down"]:
        add("bad", f"{s['sites']['down']} proxy site{'s' if s['sites']['down'] != 1 else ''} not answering", "#/stats")
    if s["devices"]["flapping"]:
        add("warn", f"{s['devices']['flapping']} device{'s' if s['devices']['flapping'] != 1 else ''} keep going up and down", "#/uptime")
    if s["devices"]["unknown"]:
        add("info", f"{s['devices']['unknown']} device{'s' if s['devices']['unknown'] != 1 else ''} not marked as known yet", "#/devices")
    if s["dns"]["conflicts"]:
        add("warn", f"{s['dns']['conflicts']} DNS name conflict{'s' if s['dns']['conflicts'] != 1 else ''}", "#/settings/dns")
    if s["netchecks"]["untrusted"]:
        add("bad", f"{s['netchecks']['untrusted']} DHCP server{'s' if s['netchecks']['untrusted'] != 1 else ''} you do not trust", "#/settings/netchecks")
    if login_failed:
        add("warn", f"{login_failed} burst{'s' if login_failed != 1 else ''} of failed sign-ins in the last 24 hours", "#/scans")
    if s["update"]["available"]:
        add("info", f"Netlens {s['update']['latest']} is available", "#/settings/about")
    if s["update"]["plugin_updates"]:
        add("info", f"{s['update']['plugin_updates']} plugin update{'s' if s['update']['plugin_updates'] != 1 else ''} available", "#/settings/plugin-browse")
    order = {"bad": 0, "warn": 1, "info": 2}
    return sorted(items, key=lambda i: order[i["level"]])


def build(conn: sqlite3.Connection, s: dict, now: str | None = None) -> dict:
    """`s` is the summary document."""
    now = now or utcnow()
    names = {d["id"]: d["name"] for d in s["device_list"]}
    events = [
        {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "detail": r["detail"], "device_id": r["device_id"], "device": names.get(r["device_id"])}
        for r in conn.execute("SELECT id, ts, device_id, kind, detail FROM events ORDER BY id DESC LIMIT 12")
    ]
    login_failed = conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'login_failed' AND ts >= ?", (_ago(now, hours=24),)).fetchone()[0]
    certs = sites_mod.certificates(conn)
    down = [r["name"] for r in conn.execute("SELECT name FROM service_checks WHERE enabled = 1 AND last_up = 0 ORDER BY name COLLATE NOCASE")]
    worst = [
        {"id": r["device_id"], "name": names.get(r["device_id"]), "pct": _pct(r["u"], r["n"])}
        for r in conn.execute("SELECT device_id, SUM(up) AS u, COUNT(*) AS n FROM checks WHERE ts >= ? GROUP BY device_id HAVING SUM(up) < COUNT(*) ORDER BY CAST(SUM(up) AS REAL) / COUNT(*) LIMIT 5", (_ago(now, days=7),))
        if r["device_id"] in names
    ]
    since = _ago(now, days=14)[:10]
    trend = [{"day": r["day"], "devices": r["devices"], "online": r["online"], "events": r["events"]}
             for r in conn.execute("SELECT day, devices, online, events FROM stats_daily WHERE day >= ? ORDER BY day", (since,))]
    new_devices = [{"id": r["id"], "name": names.get(r["id"]), "first_seen": r["first_seen"]}
                   for r in conn.execute("SELECT id, first_seen FROM devices WHERE first_seen >= ? ORDER BY first_seen DESC LIMIT 6", (_ago(now, days=7),))]
    uptime = {r["device_id"]: [_pct(r["u1"], r["n1"]), _pct(r["u7"], r["n7"])] for r in conn.execute(
        "SELECT device_id, SUM(CASE WHEN ts >= ? THEN up ELSE 0 END) AS u1, SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS n1, SUM(up) AS u7, COUNT(*) AS n7 FROM checks WHERE ts >= ? GROUP BY device_id",
        (_ago(now, hours=24), _ago(now, hours=24), _ago(now, days=7)))}
    from app.stats import _services

    return {
        "summary": s,
        "devices_uptime": uptime,
        "service_checks": _services(conn, now)["checks"],
        "attention": _attention(s, certs, login_failed, down),
        "events": events,
        "services_down": down,
        "login_failed_24h": login_failed,
        "worst": worst,
        "trend": trend,
        "new_devices": new_devices,
        "certificates": [{"name": c["name"], "proxy": c["proxy"], "days": c["days"], "expires": c["expires"]} for c in certs[:5]],
        "maintenance": len(covered(conn)),
        "speed": speedtest.latest(conn, "internet"),
    }


# ---------- the cards a user chose (per user, so every browser and device shows the same dashboard) ----------

CARD_ID = re.compile(r"^[a-z0-9_.:-]{1,80}$")
CUSTOM_ID = re.compile(r"^c-[a-z0-9]{3,16}$")
SOURCE_PATH = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+){0,6}$")
HREF = re.compile(r"^#/[A-Za-z0-9_/\-]{1,60}$")
LINK = re.compile(r"^(https?://[^\s\"'<>]{1,280}|#/[A-Za-z0-9_/\-]{1,60})$")
MAX_CARDS = 100
MAX_CUSTOM = 40
FORMATS = ("number", "percent", "mbps", "ms", "duration", "bytes", "text")
DISPLAYS = ("number", "gauge", "status")


def _layout_key(principal) -> str:
    uid = getattr(principal, "user_id", None)
    return f"dashboard.layout.user{uid}" if uid is not None else "dashboard.layout.builtin"      # the access token has no account


def get_layout(conn: sqlite3.Connection, principal) -> dict | None:
    """{"order": [...], "custom": [...]}, or None while the user has never changed the default."""
    from app.db import get_setting

    try:
        value = json.loads(get_setting(conn, _layout_key(principal)) or "null")
    except ValueError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("order"), list):
        return None
    return {"order": value["order"], "custom": value.get("custom") if isinstance(value.get("custom"), list) else []}


def clean_order(order) -> list[str]:
    if not isinstance(order, list) or len(order) > MAX_CARDS:
        raise ValueError(f"a layout has at most {MAX_CARDS} cards")
    out: list[str] = []
    for card in order:
        if not isinstance(card, str) or not CARD_ID.match(card):
            raise ValueError("a card id is 1 to 80 lowercase letters, digits, - _ . or :")
        if card not in out:
            out.append(card)
    return out


def _text(value, name: str, limit: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{name} is required")
    if len(value) > limit:
        raise ValueError(f"{name} is at most {limit} characters")
    return value


def _number(value, name: str) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or abs(value) > 1e12:
        raise ValueError(f"{name} must be a number")
    return value


def clean_card(raw) -> dict:
    """One card a user made: only known fields, checked. Raises ValueError with a message for the person."""
    if not isinstance(raw, dict):
        raise ValueError("a card must be an object")
    cid = raw.get("id")
    if not isinstance(cid, str) or not CUSTOM_ID.match(cid):
        raise ValueError("a card needs an id like c-ab12cd")
    kind = raw.get("type")
    card: dict = {"id": cid, "type": kind, "title": _text(raw.get("title"), "the title", 60)}
    if kind == "value":
        source = _text(raw.get("source"), "the data", 120, required=True)
        if not SOURCE_PATH.match(source):
            raise ValueError("the data path is not valid")
        fmt, display = raw.get("format", "number"), raw.get("display", "number")
        if fmt not in FORMATS or display not in DISPLAYS:
            raise ValueError("unknown format or display")
        direction = raw.get("direction", "below")
        if direction not in ("above", "below"):
            raise ValueError("direction must be above or below")
        decimals = raw.get("decimals", 0)
        if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 3:
            raise ValueError("decimals must be 0 to 3")
        href = _text(raw.get("href"), "the link", 64)
        if href and not HREF.match(href):
            raise ValueError("the link must be a page of Netlens such as #/devices")
        card.update(source=source, format=fmt, display=display, unit=_text(raw.get("unit"), "the unit", 12), decimals=decimals, direction=direction,
                    warn=_number(raw.get("warn"), "the warning limit"), bad=_number(raw.get("bad"), "the problem limit"),
                    min=_number(raw.get("min"), "the minimum"), max=_number(raw.get("max"), "the maximum"), href=href)
    elif kind == "device":
        device = raw.get("device_id")
        if isinstance(device, bool) or not isinstance(device, int) or device < 1:
            raise ValueError("pick a device")
        card["device_id"] = device
    elif kind == "group":
        card["group"] = _text(raw.get("group"), "the group", 60, required=True)
    elif kind == "service":
        check = raw.get("check_id")
        if isinstance(check, bool) or not isinstance(check, int) or check < 1:
            raise ValueError("pick a service check")
        card["check_id"] = check
    elif kind == "notes":
        links = raw.get("links") or []
        if not isinstance(links, list) or len(links) > 8:
            raise ValueError("a notes card has at most 8 links")
        card["text"] = _text(raw.get("text"), "the text", 2000)
        card["links"] = []
        for link in links:
            if not isinstance(link, dict):
                raise ValueError("a link must be an object")
            url = _text(link.get("url"), "the link address", 300, required=True)
            if not LINK.match(url):
                raise ValueError("a link must start with https://, http:// or #/")
            card["links"].append({"label": _text(link.get("label"), "the link name", 40, required=True), "url": url})
        if not card["text"] and not card["links"]:
            raise ValueError("write some text or add a link")
    else:
        raise ValueError("unknown card type")
    return card


def clean_custom(custom) -> list[dict]:
    if not isinstance(custom, list) or len(custom) > MAX_CUSTOM:
        raise ValueError(f"at most {MAX_CUSTOM} cards of your own")
    out, seen = [], set()
    for raw in custom:
        card = clean_card(raw)
        if card["id"] in seen:
            raise ValueError("two cards have the same id")
        seen.add(card["id"])
        out.append(card)
    return out


def set_layout(conn: sqlite3.Connection, principal, order, custom=None) -> dict:
    from app.db import set_setting

    custom = clean_custom(custom or [])
    known = {c["id"] for c in custom}
    order = [c for c in clean_order(order) if not c.startswith("c-") or c in known]      # a card of your own that no longer exists is dropped
    set_setting(conn, _layout_key(principal), json.dumps({"order": order, "custom": custom}))
    conn.commit()
    return {"order": order, "custom": custom}


def reset_layout(conn: sqlite3.Connection, principal) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (_layout_key(principal),))
    conn.commit()
