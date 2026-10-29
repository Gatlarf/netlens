"""Everything the dashboard page needs on top of the summary: the problems worth a look, the latest events and a few small series."""
import json
import re
import sqlite3

from app.maintenance import covered
from app.stats import _ago, _pct, utcnow
from app import checkstats, sites as sites_mod, speedtest


def _site_vuln_attention(conn: sqlite3.Connection) -> list[dict]:
    """Remote sites whose scanner reports critical vulnerabilities."""
    from app import probes

    out = []
    for r in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY LOWER(name)"):
        p = probes.present(conn, r)
        crit = (p["vulns"].get("counts") or {}).get("critical", 0) if p["vulns"].get("configured") and not p["locked"] else 0
        if crit:
            out.append({"level": "bad", "text": f"{p['customer'] + ' / ' if p['customer'] else ''}{p['name']}: {crit} critical vulnerabilit{'ies' if crit != 1 else 'y'}", "href": f"#/remote-sites?id={p['id']}"})
    return out


def _network_attention(conn: sqlite3.Connection) -> list[dict]:
    """The problems the network health checks announced (and that are still there)."""
    from app import nethealth

    return [{"level": i["level"], "text": i["text"], "href": "#/network-health"} for i in nethealth.attention(conn)]


def _llm_attention(conn: sqlite3.Connection) -> list[dict]:
    """The free language model that was chosen on OpenRouter has gone away or is no longer free."""
    from app import openrouter

    state = openrouter.watch_state(conn)
    if state and state["state"] != "ok":
        return [{"level": "warn", "text": openrouter.message(state["model"], state["state"]), "href": "#/settings/engineer"}]
    return []


def _tiers(conn: sqlite3.Connection) -> dict[str, str]:
    """The importance somebody gave to devices and service checks (only the ones that are not "normal"), by the subject a problem is acknowledged with."""
    out = {f"device:{r[0]}": r[1] for r in conn.execute("SELECT id, tier FROM devices WHERE tier != 'normal'")}
    out.update({f"service:{r[0]}": r[1] for r in conn.execute("SELECT id, tier FROM service_checks WHERE tier != 'normal'")})
    return out


def _attention(s: dict, certs: list[dict], login_failed: int, down: list[str], core_down: list[dict] | None = None, down_checks: list[dict] | None = None, tiers: dict[str, str] | None = None) -> list[dict]:
    items: list[dict] = []
    tiers = tiers or {}

    def add(level: str, text: str, href: str, snooze: str | None = None) -> None:
        tier = tiers.get(snooze or "")                      # what the user said about this device or service: critical problems lead, low ones are quiet
        if tier == "critical":
            text = f"Critical: {text}"
        elif tier == "low" and level == "bad":
            level = "warn"
        item = {"level": level, "text": text, "href": href}
        if tier == "critical":
            item["critical"] = True
        if snooze:
            item["snooze"] = snooze          # the subject someone can acknowledge (see app/snooze.py)
        items.append(item)

    if down and down_checks and len(down_checks) <= 3:
        for c in down_checks:
            add("bad", f"Service {c['name']} is down", "#/services", f"service:{c['id']}")
    elif down:
        add("bad", f"{len(down)} service{'s' if len(down) != 1 else ''} down: {', '.join(down[:3])}{'…' if len(down) > 3 else ''}", "#/services")
    for p in s["plugins"]:
        if p["enabled"] and p.get("failing", p["ok"] is False):
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
    behind_root: dict[int, list[dict]] = {}
    shown_down: list[dict] = []
    for dev in core_down or []:                       # a device that is down because of the device above it is part of that one problem
        if dev.get("behind") is None:
            shown_down.append(dev)
        else:
            behind_root.setdefault(dev["behind"], []).append(dev)
    for root, kids in sorted(behind_root.items()):
        names_ = [k["name"] or f"device {k['id']}" for k in kids]
        add("bad", f"{kids[0].get('behind_name') or 'A device'} is not answering, so {len(kids)} always-on device{'s' if len(kids) != 1 else ''} behind it cannot be reached: {', '.join(names_[:3])}{'…' if len(names_) > 3 else ''}",
            f"#/device/{root}", f"device:{root}")
    core_down = shown_down
    for dev in (core_down or [])[:3]:
        add("bad", f"{dev['name']} should always be online but is not answering", f"#/device/{dev['id']}", f"device:{dev['id']}")
    if len(core_down or []) > 3:
        add("bad", f"{len(core_down) - 3} more always-on devices are not answering", "#/uptime")
    core_flap = (s.get("core") or {}).get("flapping", 0)
    other_flap = s["devices"]["flapping"] - core_flap
    if core_flap:     # the always-on devices are the ones that matter; a phone or tablet flapping is only worth a note
        add("warn", f"{core_flap} always-on device{'s' if core_flap != 1 else ''} keep going up and down", "#/uptime")
    if other_flap > 0:
        add("warn" if not core_flap and not (s.get("core") or {}).get("devices") else "info", f"{other_flap} other device{'s' if other_flap != 1 else ''} keep going up and down", "#/uptime")
    if s["devices"]["unknown"]:
        add("info", f"{s['devices']['unknown']} device{'s' if s['devices']['unknown'] != 1 else ''} not marked as known yet", "#/devices")
    if s["dns"]["conflicts"]:
        add("warn", f"{s['dns']['conflicts']} DNS name conflict{'s' if s['dns']['conflicts'] != 1 else ''}", "#/dns")
    if s["netchecks"]["untrusted"]:
        add("bad", f"{s['netchecks']['untrusted']} DHCP server{'s' if s['netchecks']['untrusted'] != 1 else ''} you do not trust", "#/settings/netchecks")
    if login_failed:
        add("warn", f"{login_failed} burst{'s' if login_failed != 1 else ''} of failed sign-ins in the last 24 hours", "#/scans")
    if s["update"]["available"]:
        add("info", f"Netlens {s['update']['latest']} is available", "#/settings/about")
    gb = s.get("guest_backups") or {}
    if gb.get("failed"):
        add("bad", f"{gb['failed']} guest backup{'s' if gb['failed'] != 1 else ''} failed", "#/backups?focus=problems")
    if gb.get("late"):
        add("warn", f"{gb['late']} guest{'s' if gb['late'] != 1 else ''} not backed up on time", "#/backups?focus=problems")
    if gb.get("stores_at_risk"):
        add("warn", f"{gb['stores_at_risk']} backup store{'s' if gb['stores_at_risk'] != 1 else ''} filling up", "#/backups?focus=problems")
    if gb.get("unprotected"):
        add("info", f"{gb['unprotected']} guest{'s' if gb['unprotected'] != 1 else ''} without a backup", "#/backups")
    st = s.get("storage") or {}
    if st.get("unhealthy"):
        add("bad", f"{st['unhealthy']} storage system{'s' if st['unhealthy'] != 1 else ''} not healthy", "#/storage?focus=problems")
    if st.get("failed_disks"):
        add("bad", f"{st['failed_disks']} failed disk{'s' if st['failed_disks'] != 1 else ''} in your storage", "#/storage?focus=problems")
    if st.get("pools_filling"):
        add("warn", f"{st['pools_filling']} storage pool{'s' if st['pools_filling'] != 1 else ''} filling up or unhealthy", "#/storage?focus=problems")
    if st.get("alerts"):
        add("warn", f"{st['alerts']} open storage alert{'s' if st['alerts'] != 1 else ''}", "#/storage?focus=problems")
    vu = s.get("vulns") or {}
    if vu.get("allowed") and vu.get("configured"):
        crit = (vu.get("counts") or {}).get("critical", 0)
        if crit:
            add("bad", f"{crit} critical vulnerabilit{'ies' if crit != 1 else 'y'}" + (f", {vu['exploited']} known to be exploited" if vu.get("exploited") else ""), "#/vulnerabilities")
        elif vu.get("exploited"):
            add("warn", f"{vu['exploited']} vulnerabilit{'ies' if vu['exploited'] != 1 else 'y'} known to be exploited", "#/vulnerabilities")
    rm = s.get("remediation") or {}
    if rm.get("pending"):
        add("warn", f"{rm['pending']} automatic fix{'es' if rm['pending'] != 1 else ''} waiting for your approval", "#/remediation")
    sh = s.get("smarthome") or {}
    if sh.get("unavailable"):
        add("warn", f"{sh['unavailable']} smart-home device{'s' if sh['unavailable'] != 1 else ''} unavailable", "#/smarthome")
    if sh.get("battery_low"):
        add("warn", f"{sh['battery_low']} smart-home device{'s' if sh['battery_low'] != 1 else ''} with a low battery", "#/smarthome")
    if s["update"].get("plugin_problems"):
        n = s["update"]["plugin_problems"]
        add("warn", f"{n} plugin{'s' if n != 1 else ''} may not work with this Netlens version", "#/settings/plugins")
    if s["update"]["plugin_updates"]:
        add("info", f"{s['update']['plugin_updates']} plugin update{'s' if s['update']['plugin_updates'] != 1 else ''} available", "#/settings/plugin-browse")
    order = {"bad": 0, "warn": 1, "info": 2}
    return sorted(items, key=lambda i: (order[i["level"]], not i.get("critical")))


def _extra_attention(conn: sqlite3.Connection) -> list[dict]:
    """What the summary does not hold: a key that cannot be read, a host reading past its limit, a disk that fills up, a remote site in trouble."""
    from app import forecast, probes as probes_mod, vault
    from app.hostmetrics import service as host_monitors

    out: list[dict] = []
    unreadable = vault.status(conn)["unreadable"]
    if unreadable:       # a restore on another machine without the key: the passwords have to be entered again, or the key put back
        out.append({"level": "bad", "text": f"{unreadable} stored password setting(s) cannot be read: the encryption key is missing or different", "href": "#/settings/backup"})
    problems = host_monitors.problems(conn)
    for p in problems[:8]:      # a disk filling up, a hot server, a UPS on battery
        where = f" on {p['label']}" if p["label"] else ""
        value = f"{p['value']:.0f}{p['unit']}" if p["unit"] else f"{p['value']:g}"
        text = f"{p['device']}: {p['title'].lower()}{where} is {value}"
        if p["metric"] == "storage_status":
            text = f"{p['device']}: {p['label'] or 'storage'} is {'degraded or needs attention' if p['level'] == 'warning' else 'failed'}"
        if p["metric"] == "service_stopped":
            text = f"{p['device']}: the service {p['label']} has stopped with an error"
        out.append({"level": "bad" if p["level"] == "critical" else "warn", "text": text, "href": f"#/device/{p['device_id']}", "snooze": p["snooze"]})
    full = {(p["device_id"], p["label"]) for p in problems if p["metric"] == "disk_pct"}
    for f in forecast.cached(conn):        # a disk that is not full yet but will be within two weeks
        days = f.get("days_to_full")
        if days is not None and days <= 14 and (f.get("device_id"), f["label"]) not in full:
            out.append({"level": "bad" if days <= 3 else "warn", "text": f"{f['device']}: {f['label']} is {f['current']:g}% full and will be full in {days:g} day{'s' if days != 1 else ''}",
                        "href": f"#/device/{f['device_id']}" if f.get("device_id") else "#/insights"})
    from app import licence, secpolicy
    from app.ingest import core as ingest

    try:        # the access token signs in as administrator with no second factor: say so once somebody has one
        if conn.execute("SELECT 1 FROM users WHERE disabled = 0 AND role = 'admin' AND (totp_enabled = 1 OR webauthn_enabled = 1) LIMIT 1").fetchone() and secpolicy.get(conn)["static_token"] == "allowed":
            import os

            if os.environ.get("NETLENS_TOKEN", "").strip():
                out.append({"level": "warn", "text": "The access token (NETLENS_TOKEN) still signs in as administrator without a second factor: remove it from the container's environment", "href": "#/settings/security"})
    except Exception:  # noqa: BLE001 - a warning must never break the dashboard
        pass

    if licence.allows(conn, "agents"):
        for p in ingest.problems(conn):          # a collector that stopped sending, a certificate that is about to end
            out.append({"level": "warn", "text": p["text"], "href": "#/settings/ingest", "snooze": f"agent:{p['agent_id']}"})
    from app import approvals, auditchain, credstore

    from app import accessreview, secpolicy as _sp

    days = _sp.get(conn)["review_days"]
    if days:
        done = accessreview.last_review(conn)
        age = accessreview._days_since(done["at"], __import__("datetime").datetime.now(__import__("datetime").timezone.utc)) if done else None
        if age is None or age >= days:
            out.append({"level": "warn", "text": ("The access review has never been done" if done is None else f"The last access review was {age} days ago") + f" (due every {days} days)", "href": "#/settings/accessreview"})
    waiting = approvals.waiting_count(conn)
    if waiting:
        out.append({"level": "warn", "text": f"{waiting} approval request{'s' if waiting != 1 else ''} waiting for an administrator", "href": "#/settings/approvals"})

    verified = auditchain.last_result(conn)
    if verified and not verified.get("ok"):       # the latest integrity check of the audit log failed
        out.append({"level": "bad", "text": f"The audit log failed its integrity check at line {verified['problem']['id']}: {verified['problem']['text']}", "href": "#/settings/audit"})
    for p in credstore.pam_problems(conn):       # the customer's PAM refused a login (nothing can use it until that is fixed)
        out.append({"level": "warn", "text": p["text"], "href": "#/settings/credentials", "snooze": f"pam:{p['id']}"})
    for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY LOWER(name)"):
        site = probes_mod.present(conn, row)
        href = f"#/remote-sites?id={site['id']}"
        if site["locked"]:
            out.append({"level": "warn", "text": f"{site['name']} is frozen: the licence takes in fewer remote sites", "href": "#/settings/licence"})
            continue
        if site["state"] == "silent":
            out.append({"level": "bad", "text": f"{site['name']} has stopped reporting", "href": href, "snooze": f"site:{site['id']}"})
            continue
        bk = site.get("backups") or {}
        if bk.get("failed") or bk.get("late"):
            out.append({"level": "bad" if bk.get("failed") else "warn", "text": f"{site['name']}: {bk.get('failed', 0)} backup(s) failed, {bk.get('late', 0)} late", "href": "#/backups"})
        down = site["devices"]["core_down"]
        if down:
            out.append({"level": "bad", "text": f"{site['name']}: {down} always-on device{'s' if down != 1 else ''} offline", "href": href})
        if site["services"]["down"]:
            out.append({"level": "bad", "text": f"{site['name']}: {site['services']['down']} service check{'s' if site['services']['down'] != 1 else ''} down", "href": href})
        if site["problems"]["count"]:
            out.append({"level": "bad" if site["problems"]["critical"] else "warn",
                        "text": f"{site['name']}: {site['problems']['count']} health problem{'s' if site['problems']['count'] != 1 else ''}", "href": href})
    return out


def current_problems(conn: sqlite3.Connection, minimum: str = "warn") -> list[dict]:
    """Everything the dashboard would list under "needs attention" right now, for the answers, the assistant and the reports: one list, so none of
    them can leave something out. What someone acknowledged (snoozed) is left out. `minimum` "info" also returns the notes."""
    from app import snooze, stats

    attention = build(conn, stats.summary(conn))["attention"]
    asleep = snooze.active(conn)
    keep = {"bad", "warn"} if minimum == "warn" else {"bad", "warn", "info"}
    return [i for i in attention if i["level"] in keep and not asleep.get(i.get("snooze"))]


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
    down_checks = [{"id": r["id"], "name": r["name"]} for r in conn.execute("SELECT id, name FROM service_checks WHERE enabled = 1 AND last_up = 0 ORDER BY LOWER(name)")]
    down = [c["name"] for c in down_checks]
    week = checkstats.totals(conn, _ago(now, days=7))
    worst = [
        {"id": d, "name": names.get(d), "pct": _pct(u, n)}
        for d, (u, n, _rs, _rn) in sorted(((d, v) for d, v in week.items() if v[0] < v[1] and d in names), key=lambda kv: (kv[1][0] / kv[1][1], kv[0]))[:5]
    ]
    from app import rootcause

    behind = rootcause.unreachable(conn)               # offline devices behind another offline device: one cause, not a list of separate outages
    core_down = [{"id": r["id"], "name": names.get(r["id"]), "behind": behind.get(r["id"]), "behind_name": names.get(behind.get(r["id"]))} for r in conn.execute("SELECT id FROM devices WHERE always_on = 1 AND online = 0 ORDER BY id")]
    since = _ago(now, days=14)[:10]
    trend = [{"day": r["day"], "devices": r["devices"], "online": r["online"], "events": r["events"]}
             for r in conn.execute("SELECT day, devices, online, events FROM stats_daily WHERE day >= ? ORDER BY day", (since,))]
    new_devices = [{"id": r["id"], "name": names.get(r["id"]), "first_seen": r["first_seen"]}
                   for r in conn.execute("SELECT id, first_seen FROM devices WHERE first_seen >= ? ORDER BY first_seen DESC LIMIT 6", (_ago(now, days=7),))]
    day = checkstats.totals(conn, _ago(now, hours=24))
    uptime = {d: [_pct(day[d][0], day[d][1]) if d in day else _pct(0, 0), _pct(v[0], v[1])] for d, v in week.items()}
    uptime.update({d: [_pct(v[0], v[1]), _pct(0, 0)] for d, v in day.items() if d not in uptime})
    from app.stats import _services

    return {
        "summary": s,
        "devices_uptime": uptime,
        "service_checks": _services(conn, now)["checks"],
        "attention": sorted(_attention(s, certs, login_failed, down, core_down, down_checks, _tiers(conn)) + _network_attention(conn) + _site_vuln_attention(conn) + _llm_attention(conn)
                            + _extra_attention(conn), key=lambda i: {"bad": 0, "warn": 1}.get(i["level"], 2)),
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


DEFAULT_KEY = "dashboard.layout.default"       # set by an administrator: what everybody sees until they arrange their own
SHARED_KEY = "dashboard.shared_cards"          # cards an administrator made available to every user (the "shared library")


def get_layout(conn: sqlite3.Connection, principal) -> dict | None:
    """{"order": [...], "custom": [...]}, or None while the user has never changed the default."""
    return _read(conn, _layout_key(principal))


def get_default(conn: sqlite3.Connection) -> dict | None:
    """The dashboard an administrator set for everybody, or None (then the built-in cards are used)."""
    return _read(conn, DEFAULT_KEY)


def get_shared(conn: sqlite3.Connection) -> list[dict]:
    """The cards an administrator shared: every user can add them to their own dashboard."""
    from app.db import get_setting

    try:
        value = json.loads(get_setting(conn, SHARED_KEY) or "[]")
    except ValueError:
        return []
    try:
        return clean_custom(value)
    except ValueError:
        return []


def set_shared(conn: sqlite3.Connection, cards) -> list[dict]:
    from app.db import set_setting

    cards = clean_custom(cards or [])
    set_setting(conn, SHARED_KEY, json.dumps(cards))
    conn.commit()
    return cards


def _read(conn: sqlite3.Connection, key: str) -> dict | None:
    from app.db import get_setting

    try:
        value = json.loads(get_setting(conn, key) or "null")
    except ValueError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("order"), list):
        return None
    return {"order": value["order"], "custom": value.get("custom") if isinstance(value.get("custom"), list) else [],
            "sizes": value.get("sizes") if isinstance(value.get("sizes"), dict) else {}}


SIZES = ("s", "w", "f")      # one column, two columns, the whole row


def clean_sizes(sizes) -> dict[str, str]:
    """The width a user gave to cards: {card id: s | w | f}. Unknown values are dropped, not refused."""
    if not isinstance(sizes, dict):
        return {}
    return {k: v for k, v in list(sizes.items())[:MAX_CARDS] if isinstance(k, str) and CARD_ID.match(k) and v in SIZES}


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


def set_layout(conn: sqlite3.Connection, principal, order, custom=None, sizes=None) -> dict:
    return _write(conn, _layout_key(principal), order, custom, sizes)


def set_default(conn: sqlite3.Connection, order, custom=None, sizes=None) -> dict:
    return _write(conn, DEFAULT_KEY, order, custom, sizes)


def _write(conn: sqlite3.Connection, key: str, order, custom=None, sizes=None) -> dict:
    from app.db import set_setting

    custom = clean_custom(custom or [])
    known = {c["id"] for c in custom} | {c["id"] for c in get_shared(conn)}      # your own cards and the shared ones
    order = [c for c in clean_order(order) if not c.startswith("c-") or c in known]      # a card of your own that no longer exists is dropped
    sizes = {k: v for k, v in clean_sizes(sizes).items() if k in order}
    set_setting(conn, key, json.dumps({"order": order, "custom": custom, "sizes": sizes}))
    conn.commit()
    return {"order": order, "custom": custom, "sizes": sizes}


def reset_layout(conn: sqlite3.Connection, principal) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (_layout_key(principal),))
    conn.commit()


def reset_default(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (DEFAULT_KEY,))
    conn.commit()
