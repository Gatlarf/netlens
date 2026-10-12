"""Everything the dashboard page needs on top of the summary: the problems worth a look, the latest events and a few small series."""
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
    return {
        "summary": s,
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
