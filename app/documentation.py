"""Network documentation: one self-contained page about a network, ready to hand to a customer (or to keep for yourself).

It is made from what Netlens already knows, at the moment you ask: the devices and where they are, the subnets, the gateway, DNS and DHCP, the checks that run,
the certificates, the backups, the vulnerabilities and the open points of the network health checks. The result is a single HTML file without anything external
(no scripts, no fonts, no images except the logo you uploaded), so it can be mailed, archived, or printed to PDF from the browser. Everything that comes
from the network is escaped; the logo is only accepted as a small PNG, JPEG, GIF or WebP data address.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY = "docs.settings"
SECTIONS = (("summary", "Summary"), ("network", "Network"), ("devices", "Devices"), ("services", "Monitored services"), ("certificates", "Certificates"),
            ("backups", "Backups"), ("security", "Security"), ("points", "Open points"))
DEFAULTS = {"company": "", "customer": "", "prepared_by": "", "contact": "", "accent": "#1f6feb", "footer": "", "logo": "", "sections": [s for s, _ in SECTIONS]}
LOGO_RE = re.compile(r"^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$")
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
MAX_LOGO = 200_000


class DocError(ValueError):
    pass


def get_settings(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        raw = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        raw = {}
    raw = raw if isinstance(raw, dict) else {}
    out = {**DEFAULTS, **{k: raw[k] for k in DEFAULTS if k in raw}}
    out["sections"] = [s for s, _ in SECTIONS if s in (out["sections"] if isinstance(out["sections"], list) else DEFAULTS["sections"])]
    return out


def save_settings(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    cur = get_settings(conn)
    for key in ("company", "customer", "prepared_by", "contact", "footer"):
        if key in data:
            value = " ".join(str(data[key] or "").split())
            if len(value) > (300 if key == "footer" else 100):
                raise DocError(f"{key.replace('_', ' ')} is too long")
            cur[key] = value
    if "accent" in data:
        if not COLOR_RE.match(str(data["accent"] or "")):
            raise DocError("the colour must look like #1f6feb")
        cur["accent"] = str(data["accent"]).lower()
    if "logo" in data:
        logo = str(data["logo"] or "")
        if logo and (len(logo) > MAX_LOGO or not LOGO_RE.match(logo)):
            raise DocError("the logo must be a PNG, JPEG, GIF or WebP image of at most 150 KB")
        cur["logo"] = logo
    if "sections" in data:
        if not isinstance(data["sections"], list) or any(s not in dict(SECTIONS) for s in data["sections"]):
            raise DocError("unknown section")
        cur["sections"] = [s for s, _ in SECTIONS if s in data["sections"]]
    set_setting(conn, KEY, json.dumps(cur))
    return cur


# ----------------------------------------------------------------------------- collecting
def _ip_key(ip: str | None):
    try:
        return (0, int(ipaddress.ip_address(ip or "")))
    except ValueError:
        return (1, 0)


def collect(conn: sqlite3.Connection, ranges: list[str], now: datetime | None = None) -> dict[str, Any]:
    from app import guestbackups, ipv4health, ipv6health, licence, sites, vulns

    now = now or datetime.now(timezone.utc)
    groups = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM device_groups")}
    devices = []
    for r in conn.execute("SELECT id, primary_ip, mac, hostname, custom_name, vendor, os_name, device_type, type_override, notes, online, last_seen, group_id, report_exclude FROM devices"):
        if r["report_exclude"]:
            continue
        devices.append({"name": r["custom_name"] or r["hostname"] or r["primary_ip"] or "", "ip": r["primary_ip"] or "", "mac": r["mac"] or "", "vendor": r["vendor"] or "", "os": r["os_name"] or "",
                        "type": (r["type_override"] or r["device_type"] or "unknown"), "group": groups.get(r["group_id"], ""), "notes": r["notes"] or "", "online": bool(r["online"]), "last_seen": r["last_seen"]})
    devices.sort(key=lambda d: _ip_key(d["ip"]))
    v4, v6 = ipv4health.last(conn), ipv6health.last(conn)
    checks = [{"name": r["name"], "kind": r["kind"], "target": f"{r['host']}{':' + str(r['port']) if r['port'] else ''}{r['path'] or ''}", "up": r["last_up"]}
              for r in conn.execute("SELECT name, kind, host, port, path, last_up FROM service_checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE")]
    backups = guestbackups.overview(conn, now) if conn.execute("SELECT 1 FROM backup_servers LIMIT 1").fetchone() else None
    allowed = licence.allows(conn, "vulnerabilities")
    return {"generated": now.strftime("%Y-%m-%d %H:%M UTC"), "devices": devices, "ranges": ranges, "v4": v4, "v6": v6, "services": checks, "certificates": sites.certificates(conn), "backups": backups,
            "vulns": ({"summary": vulns.summary(conn), "top": vulns.top_devices(conn, 10), "critical": vulns.findings(conn, severity="critical", limit=25)} if allowed and vulns.summary(conn)["configured"] else None)}


# ----------------------------------------------------------------------------- rendering
def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(head: list[str], rows: list[list[Any]], empty: str = "Nothing to show.") -> str:
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    return "<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in head) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{c if isinstance(c, _Raw) else esc(c)}</td>" for c in row) + "</tr>" for row in rows) + "</tbody></table>"


class _Raw(str):
    """A piece of markup that is already safe (made here from escaped parts)."""


def _badge(text: str, tone: str) -> _Raw:
    return _Raw(f'<span class="b {esc(tone)}">{esc(text)}</span>')


def _facts(items: list[tuple[str, Any]]) -> str:
    return '<div class="facts">' + "".join(f'<div><strong>{esc(v)}</strong><span>{esc(k)}</span></div>' for k, v in items) + "</div>"


def _points(doc: dict) -> list[tuple[str, str, str]]:
    """What is not in order, worst first: (level, where, text)."""
    out = []
    for family, res in (("IPv4", doc["v4"]), ("IPv6", doc["v6"])):
        for f in (res or {}).get("findings", []):
            if f["level"] in ("bad", "warn"):
                out.append((f["level"], family, f"{f['title']}. {f['text']}"))
    if doc["vulns"]:
        c = doc["vulns"]["summary"]["counts"]
        if c.get("critical"):
            out.append(("bad", "Security", f"{c['critical']} critical vulnerabilit{'ies' if c['critical'] != 1 else 'y'} found by the scanner."))
    for cert in doc["certificates"]:
        if cert["days"] <= 14:
            out.append(("bad" if cert["days"] < 0 else "warn", "Certificates", f"The certificate {cert['name']} " + ("has expired." if cert["days"] < 0 else f"ends in {cert['days']} days.")))
    down = [c["name"] for c in doc["services"] if c["up"] == 0]
    if down:
        out.append(("bad", "Services", f"{len(down)} monitored service{'s are' if len(down) != 1 else ' is'} down: {', '.join(down[:5])}."))
    b = (doc["backups"] or {}).get("summary") or {}
    if b.get("failed"):
        out.append(("bad", "Backups", f"{b['failed']} backup{'s' if b['failed'] != 1 else ''} failed."))
    if b.get("late"):
        out.append(("warn", "Backups", f"{b['late']} guest{'s are' if b['late'] != 1 else ' is'} not backed up on time."))
    return sorted(out, key=lambda p: p[0] != "bad")


def render(doc: dict[str, Any], settings: dict[str, Any]) -> str:
    sections = settings["sections"]
    devices = doc["devices"]
    online = sum(1 for d in devices if d["online"])
    parts: list[str] = []
    if "summary" in sections:
        points = _points(doc)
        verdict = "No open points." if not points else f"{len(points)} open point{'s' if len(points) != 1 else ''}."
        parts.append(f"<section><h2>Summary</h2>{_facts([('devices', len(devices)), ('online now', online), ('subnets', len(doc['ranges'])), ('monitored services', len(doc['services']))])}<p>{esc(verdict)}</p></section>")
    if "network" in sections:
        rows = []
        for res, label in ((doc["v4"], "IPv4"), (doc["v6"], "IPv6")):
            for s in (res or {}).get("subnets", []):
                rows.append([label, s.get("range") or s.get("prefix"), s.get("known", s.get("devices", "")), s.get("usage", "") if "usage" in s else ""])
        net = [f"<section><h2>Network</h2><p>Scanned ranges: {esc(', '.join(doc['ranges']) or 'detected from the network cards')}.</p>"]
        net.append(_table(["", "Range", "Devices", "Used %"], rows, "No subnet information yet (run Network health)."))
        v4 = doc["v4"]
        if v4:
            net.append("<h3>Findings at the last check</h3>" + _table(["", "What", "Meaning"], [[_badge({"good": "OK", "warn": "Look", "bad": "Problem", "info": "Info"}[f["level"]], f["level"]), f["title"], f["text"]] for f in v4["findings"]], ""))
        net.append("</section>")
        parts.append("".join(net))
    if "devices" in sections:
        rows = [[d["name"], d["ip"], d["mac"], d["vendor"], d["type"], d["os"], d["group"], d["notes"]] for d in devices]
        parts.append(f"<section><h2>Devices ({len(devices)})</h2>" + _table(["Name", "Address", "MAC", "Vendor", "Type", "System", "Group", "Notes"], rows, "No devices yet.") + "</section>")
    if "services" in sections:
        rows = [[c["name"], c["kind"], c["target"], _badge("up", "good") if c["up"] else _badge("down", "bad") if c["up"] == 0 else _badge("not checked", "info")] for c in doc["services"]]
        parts.append("<section><h2>Monitored services</h2>" + _table(["Name", "Kind", "Target", "State"], rows, "No service checks are set up.") + "</section>")
    if "certificates" in sections:
        rows = [[c["name"], c["proxy"], (c["expires"] or "")[:10], f"{c['days']} days" if c["days"] >= 0 else "expired"] for c in doc["certificates"]]
        parts.append("<section><h2>Certificates</h2>" + _table(["Certificate", "Published by", "Ends", "Left"], rows, "No certificates are watched.") + "</section>")
    if "backups" in sections:
        b = doc["backups"]
        if b:
            rows = [[t["name"], t["type"], t["last_backup"] or "never", _badge(t["last_state"], "good" if t["last_state"] == "ok" else "bad" if t["last_state"] == "failed" else "info")] for t in b["targets"]]
            body = _facts([("backed up", b["summary"]["protected"]), ("without backup", b["summary"]["unprotected"]), ("failed", b["summary"]["failed"]), ("late", b["summary"]["late"])]) + _table(["Guest", "Type", "Last backup", "State"], rows)
        else:
            body = '<p class="muted">No backup server is connected to Netlens.</p>'
        parts.append(f"<section><h2>Backups</h2>{body}</section>")
    if "security" in sections:
        v = doc["vulns"]
        if v:
            c = v["summary"]["counts"]
            rows = [[d["device"], d["critical"], d["high"], d["medium"], d["low"]] for d in v["top"]]
            body = _facts([("critical", c["critical"]), ("high", c["high"]), ("medium", c["medium"]), ("known exploited", v["summary"]["exploited"])]) + _table(["Device", "Critical", "High", "Medium", "Low"], rows, "")
            crit = [[f["device"], f["title"], ", ".join(f["cve"]), f["port"] or ""] for f in v["critical"]]
            if crit:
                body += "<h3>Critical findings</h3>" + _table(["Device", "Finding", "CVE", "Port"], crit)
        else:
            body = '<p class="muted">No vulnerability scanner is connected to Netlens.</p>'
        parts.append(f"<section><h2>Security</h2>{body}</section>")
    if "points" in sections:
        pts = _points(doc)
        parts.append("<section><h2>Open points</h2>" + _table(["", "Area", "What"], [[_badge("Problem" if lvl == "bad" else "Look", lvl), where, text] for lvl, where, text in pts], "Everything Netlens checks is in order.") + "</section>")
    title = f"{settings['customer']} · Network documentation" if settings["customer"] else "Network documentation"
    logo = f'<img class="logo" alt="" src="{esc(settings["logo"])}">' if settings["logo"] and LOGO_RE.match(settings["logo"]) else ""
    prepared = " · ".join(x for x in (f"Prepared by {settings['prepared_by']}" if settings["prepared_by"] else "", settings["company"], settings["contact"]) if x)
    accent = settings["accent"] if COLOR_RE.match(settings["accent"]) else "#1f6feb"
    css = (f":root{{--a:{accent}}}*{{box-sizing:border-box}}body{{font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;color:#1b1f24;margin:0;background:#f3f4f6}}"
           "main{max-width:980px;margin:0 auto;background:#fff;padding:36px 44px}.cover{border-bottom:4px solid var(--a);padding-bottom:18px;margin-bottom:22px}"
           ".logo{max-height:64px;max-width:220px;display:block;margin-bottom:14px}h1{margin:0 0 4px;font-size:28px}h2{color:var(--a);border-bottom:1px solid #d8dde3;padding-bottom:4px;margin-top:30px}h3{margin:18px 0 6px}"
           ".muted{color:#667}table{border-collapse:collapse;width:100%;margin:8px 0 14px;font-size:13px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #e3e6ea;vertical-align:top}th{background:#f3f5f7}"
           ".facts{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0}.facts div{border:1px solid #d8dde3;border-radius:6px;padding:8px 14px;min-width:110px}.facts strong{display:block;font-size:22px}.facts span{color:#667;font-size:12px}"
           ".b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;background:#667}.b.good{background:#1a7f37}.b.warn{background:#b7791f}.b.bad{background:#c62828}"
           "footer{margin-top:34px;color:#667;font-size:12px;border-top:1px solid #d8dde3;padding-top:8px}section{break-inside:auto}tr{break-inside:avoid}"
           "@media print{body{background:#fff}main{padding:0;max-width:none}h2{break-after:avoid}}")
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style>{css}</style></head><body><main>'
            f'<div class="cover">{logo}<h1>{esc(title)}</h1><p class="muted">{esc(doc["generated"])}{" · " + esc(prepared) if prepared else ""}</p></div>' + "".join(parts)
            + f'<footer>{esc(settings["footer"]) + " · " if settings["footer"] else ""}Made with Netlens on {esc(doc["generated"])}.</footer></main></body></html>')
