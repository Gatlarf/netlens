"""Sites published by a reverse proxy plugin (Nginx Proxy Manager ...): which domain leads to which device or container.

A proxy plugin reports its proxies and the sites they publish (domains, upstream host and port, certificate). Netlens finds the
device or Docker container behind every upstream, stores the result in `proxy_sites`, warns when a certificate is about to expire
and, when the plugin asks for it, keeps one HTTPS service check per site (sent through the proxy, so it does not depend on DNS).
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app.db import add_event, get_setting, set_setting, utcnow

ALL_BINDS = {"", "0.0.0.0", "::"}
LOCAL_NAMES = {"localhost", "host.docker.internal", "gateway.docker.internal", "127.0.0.1", "::1"}
MAX_CHECKS = 100                  # a plugin never adds more than this many checks
CERT_LEVELS = (14, 7, 3, 1)       # days before expiry at which a certificate is reported (the first is the plugin's setting)
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _json(raw: Any, default: Any) -> Any:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------------------- what a site points at
class Context:
    """The devices and guests a site can lead to, loaded once per sync."""

    def __init__(self, conn: sqlite3.Connection):
        self.by_ip: dict[str, int] = {}
        for r in conn.execute("SELECT device_id, ip FROM device_ips"):
            self.by_ip.setdefault(r["ip"], r["device_id"])
        self.names: dict[str, set[int]] = {}
        self.device_name: dict[int, str] = {}
        for r in conn.execute("SELECT id, primary_ip, hostname, custom_name, dns_name FROM devices"):
            if r["primary_ip"]:
                self.by_ip[r["primary_ip"]] = r["id"]
            self.device_name[r["id"]] = r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}"
            for text in (r["hostname"], r["custom_name"], r["dns_name"]):
                if text:
                    for key in {text.lower(), text.lower().split(".")[0]}:
                        self.names.setdefault(key, set()).add(r["id"])
        self.guests: list[dict] = []
        for r in conn.execute("SELECT plugin_id, guest_id, name, kind, status, ips, device_id, host_device_id, details FROM hypervisor_guests"):
            g = dict(r)
            g["ips"] = _json(g["ips"], [])
            g["details"] = _json(g["details"], {})
            self.guests.append(g)
        self.on_host: dict[int, list[dict]] = {}
        for g in self.guests:
            if g["host_device_id"] is not None:
                self.on_host.setdefault(g["host_device_id"], []).append(g)

    def hit(self, g: dict, how: str) -> dict:
        return {"device_id": g["device_id"] or g["host_device_id"], "plugin_id": g["plugin_id"], "guest_id": g["guest_id"], "name": g["name"], "how": how}

    def at_host(self, host_device_id: int, port: int | None, ip: str | None = None) -> dict | None:
        """A container on that Docker host that publishes `port`, else the host itself."""
        if port:
            for g in self.on_host.get(host_device_id, []):
                if g["kind"] != "container" or g["status"] != "running":
                    continue
                for p in g["details"].get("ports") or []:
                    if p.get("host_port") == port and (p.get("bind") or "") in ALL_BINDS | {ip}:
                        return self.hit(g, f"published port {port}")
        return {"device_id": host_device_id, "plugin_id": None, "guest_id": None, "name": self.device_name.get(host_device_id, ""), "how": "address"}

    def by_address(self, ip: str, port: int | None) -> dict | None:
        for g in self.guests:        # a guest with an address of its own (macvlan container, virtual machine)
            if ip in g["ips"]:
                return self.hit(g, "own address")
        host = self.by_ip.get(ip)
        return self.at_host(host, port, ip) if host is not None else None


def match_site(site: dict, proxy_device_id: int | None, ctx: Context) -> dict | None:
    """{device_id, plugin_id, guest_id, name, how} for the upstream of a site, or None when Netlens does not know it."""
    host = (site.get("forward_host") or "").lower()
    port = site.get("forward_port")
    if site["type"] not in ("proxy", "stream") or not host:
        return None
    if host in LOCAL_NAMES:                                    # the proxy's own machine
        return ctx.at_host(proxy_device_id, port) if proxy_device_id is not None else None
    if not _is_ip(host):
        if proxy_device_id is not None:                        # a container name on the proxy's Docker network
            for g in ctx.on_host.get(proxy_device_id, []):
                aliases = {g["name"].lower(), str(g["details"].get("service") or "").lower()} - {""}     # the container's name and its compose service name
                if g["kind"] == "container" and host in aliases:
                    ports = [p.get("container_port") for p in g["details"].get("ports") or []]
                    return ctx.hit(g, "container name" if not port or not ports or port in ports else "container name (port not listed)")
        for ip in site.get("forward_ips") or []:               # the plugin resolved the name
            found = ctx.by_address(ip, port)
            if found:
                return {**found, "how": "name " + found["how"]}
        ids = ctx.names.get(host) or ctx.names.get(host.split(".")[0])
        if ids and len(ids) == 1:
            device_id = next(iter(ids))
            return {"device_id": device_id, "plugin_id": None, "guest_id": None, "name": ctx.device_name.get(device_id, ""), "how": "name"}
        return None
    return ctx.by_address(host, port)


# ----------------------------------------------------------------------------- storing a sync
def _cert_days(expires: str | None, now: datetime) -> int | None:
    if not expires:
        return None
    try:
        return int((datetime.strptime(expires, STAMP).replace(tzinfo=timezone.utc) - now).total_seconds() // 86400)
    except ValueError:
        return None


def _cert_events(conn: sqlite3.Connection, plugin_id: str, data: dict, devices: dict[str, int | None], warn_days: int, now: datetime) -> int:
    """One event per certificate that is used by a site and gets close to its end (and again at 7, 3, 1 days and when it has expired)."""
    key = f"plugin.{plugin_id}.certalerts"
    state = _json(get_setting(conn, key), {})
    levels = sorted({warn_days, *(l for l in CERT_LEVELS if l < warn_days)})
    used: dict[tuple[str, str], list[str]] = {}
    for s in data["sites"]:
        if s["certificate_id"] and s["enabled"]:
            used.setdefault((s["proxy_id"], s["certificate_id"]), []).extend(d for d in s["domains"] if d not in used.get((s["proxy_id"], s["certificate_id"]), []))
    fresh, keep = 0, {}
    for cert in data["certificates"]:
        ident = (cert["proxy_id"] or (data["proxies"][0]["id"] if data["proxies"] else ""), cert["id"])
        days = _cert_days(cert["expires"], now)
        if ident not in used or days is None:
            continue
        level = 0 if days < 0 else next((l for l in levels if l >= days), None)
        text_key = f"{ident[0]}:{ident[1]}"
        if level is None:
            continue
        keep[text_key] = level
        if text_key in state and state[text_key] <= level:
            continue
        label = cert["name"] or ", ".join(cert["domains"][:2]) or f"certificate {cert['id']}"
        where = ", ".join(used[ident][:3]) + (f" and {len(used[ident]) - 3} more" if len(used[ident]) > 3 else "")
        when = "has expired" if days < 0 else "expires today" if days == 0 else f"expires in {days} day{'s' if days != 1 else ''}"
        add_event(conn, "cert_expiring", f"The certificate {label} {when} (used by {where})", device_id=devices.get(ident[0]), now=now.strftime(STAMP))
        fresh += 1
    set_setting(conn, key, json.dumps(keep))
    return fresh


def _site_check(site: dict, proxy_ip: str | None, device_id: int | None, interval: int) -> dict | None:
    """The service check that asks the proxy for this site, or None when it cannot be checked (no address, wildcard, disabled ...)."""
    domain = next((d for d in site["domains"] if d and not d.startswith("*")), None)
    if site["type"] != "proxy" or not site["enabled"] or not domain or not proxy_ip:
        return None
    return {"name": f"Site {domain}", "kind": "http", "host": domain, "via": proxy_ip, "port": 443 if site["ssl"] else 80, "path": "/", "expect": "alive",
            "interval_s": interval, "timeout_s": 10, "device_id": device_id}


def _sync_checks(conn: sqlite3.Connection, plugin_id: str, wanted: dict[str, dict], now: str) -> int:
    existing = {r["source"]: dict(r) for r in conn.execute("SELECT * FROM service_checks WHERE source LIKE ?", (f"{plugin_id}:%",))}
    for source, row in existing.items():
        if source not in wanted:
            conn.execute("DELETE FROM service_checks WHERE id = ?", (row["id"],))
    for source, c in list(wanted.items())[:MAX_CHECKS]:
        if source in existing:        # keep what the user may have changed (interval, timeout, on/off)
            row = existing[source]
            conn.execute("UPDATE service_checks SET name = ?, host = ?, via = ?, port = ?, path = ?, expect = ?, device_id = ? WHERE id = ?",
                         (c["name"], c["host"], c["via"], c["port"], c["path"], c["expect"], c["device_id"], row["id"]))
            if (row["host"], row["via"], row["port"]) != (c["host"], c["via"], c["port"]):     # another target: the old state says nothing about it
                conn.execute("UPDATE service_checks SET last_ts = NULL, last_up = NULL, last_ms = NULL, last_detail = NULL, since = NULL WHERE id = ?", (row["id"],))
                conn.execute("DELETE FROM service_results WHERE check_id = ?", (row["id"],))
        else:
            conn.execute(
                "INSERT INTO service_checks (device_id, name, kind, host, port, path, expect, interval_s, timeout_s, enabled, created, source, via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (c["device_id"], c["name"], c["kind"], c["host"], c["port"], c["path"], c["expect"], c["interval_s"], c["timeout_s"], now, source, c["via"]))
    return min(len(wanted), MAX_CHECKS)


def remove_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    conn.execute("DELETE FROM proxy_sites WHERE plugin_id = ?", (plugin_id,))
    conn.execute("DELETE FROM service_checks WHERE source LIKE ?", (f"{plugin_id}:%",))


def apply_proxy(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict | None = None, now: datetime | None = None) -> dict:
    """Store a proxy plugin's output: match every site to a device, report certificates, keep the site checks. Returns the summary."""
    config = config or {}
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime(STAMP)
    ctx = Context(conn)
    proxy_device = {p["id"]: (ctx.by_ip.get(p["ip"]) if p["ip"] else None) for p in data["proxies"]}
    proxies = {p["id"]: p for p in data["proxies"]}
    conn.execute("DELETE FROM proxy_sites WHERE plugin_id = ?", (plugin_id,))
    wanted, matched = {}, 0
    certs = {(c["proxy_id"] or "", c["id"]): c for c in data["certificates"]}
    for s in data["sites"]:
        proxy = proxies[s["proxy_id"]]
        target = match_site(s, proxy_device[s["proxy_id"]], ctx)
        matched += 1 if target else 0
        cert = certs.get((s["proxy_id"], s["certificate_id"] or "")) or certs.get(("", s["certificate_id"] or ""))
        details = {k: s[k] for k in ("name", "ssl", "ssl_forced", "websockets", "certificate_id", "cert_name", "cert_provider", "cert_expires", "access_list", "redirect_to", "incoming_port", "protocols") if s.get(k) not in (None, "", [], False)}
        if cert and not details.get("cert_expires"):
            details.update({"cert_name": cert["name"], "cert_provider": cert["provider"], "cert_expires": cert["expires"]})
        conn.execute(
            """INSERT INTO proxy_sites (plugin_id, site_id, proxy_id, proxy_name, proxy_device_id, type, domains, enabled, scheme, forward_host, forward_port,
                                        target_device_id, target_plugin_id, target_guest_id, target_name, target_how, details, updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_id, s["id"], s["proxy_id"], proxy["name"], proxy_device[s["proxy_id"]], s["type"], json.dumps(s["domains"]), int(s["enabled"]), s["scheme"],
             s["forward_host"], s["forward_port"], target["device_id"] if target else None, target["plugin_id"] if target else None,
             target["guest_id"] if target else None, target["name"] if target else "", target["how"] if target else "", json.dumps(details), stamp))
        if config.get("create_checks", True):
            check = _site_check(s, proxy["ip"], (target or {}).get("device_id") or proxy_device[s["proxy_id"]], int(config.get("check_interval") or 300))
            if check:
                wanted[f"{plugin_id}:{s['proxy_id']}:{s['id']}"] = check
    checks = _sync_checks(conn, plugin_id, wanted, stamp)
    warn = int(config.get("cert_warn_days") or 14)
    fresh = _cert_events(conn, plugin_id, data, proxy_device, max(1, min(warn, 90)), now)
    conn.commit()
    expiring = sum(1 for c in data["certificates"] if (d := _cert_days(c["expires"], now)) is not None and d <= warn)
    return {"proxies": len(data["proxies"]), "sites": len(data["sites"]), "sites_matched": matched, "certificates": len(data["certificates"]),
            "expiring": expiring, "checks": checks, "alerts": fresh, "warnings": [w for p in data["proxies"] for w in p["warnings"]][:10]}


# ----------------------------------------------------------------------------- for the API
def _present(conn: sqlite3.Connection, r: sqlite3.Row, names: dict[int, str], now: datetime) -> dict:
    details = _json(r["details"], {})
    check = conn.execute("SELECT id, last_up FROM service_checks WHERE source = ?", (f"{r['plugin_id']}:{r['proxy_id']}:{r['site_id']}",)).fetchone()
    days = _cert_days(details.get("cert_expires"), now)
    return {
        "plugin_id": r["plugin_id"], "id": r["site_id"], "type": r["type"], "domains": _json(r["domains"], []), "enabled": bool(r["enabled"]),
        "proxy": r["proxy_name"], "proxy_device_id": r["proxy_device_id"], "proxy_device": names.get(r["proxy_device_id"]),
        "scheme": r["scheme"], "forward_host": r["forward_host"], "forward_port": r["forward_port"],
        "target_device_id": r["target_device_id"], "target_device": names.get(r["target_device_id"]), "target_name": r["target_name"], "target_how": r["target_how"],
        "target_container": bool(r["target_guest_id"]),
        "ssl": bool(details.get("ssl")), "cert_expires": details.get("cert_expires"), "cert_days": days, "cert_name": details.get("cert_name"),
        "access_list": details.get("access_list"), "redirect_to": details.get("redirect_to"), "incoming_port": details.get("incoming_port"),
        "protocols": details.get("protocols"), "websockets": bool(details.get("websockets")), "name": details.get("name"),
        "check_id": check["id"] if check else None, "check_state": None if not check or check["last_up"] is None else ("up" if check["last_up"] else "down"),
    }


def list_sites(conn: sqlite3.Connection, device_id: int | None = None) -> list[dict]:
    """Every site; with a device id only the sites that lead to it or are published by it."""
    names = {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    now = datetime.now(timezone.utc)
    sql, args = "SELECT * FROM proxy_sites", ()
    if device_id is not None:
        sql, args = sql + " WHERE target_device_id = ? OR proxy_device_id = ?", (device_id, device_id)
    rows = conn.execute(sql + " ORDER BY proxy_name, domains", args).fetchall()
    return [_present(conn, r, names, now) for r in rows]


def device_sites(conn: sqlite3.Connection, device_id: int) -> dict[str, list[dict]] | None:
    """{"published": sites that lead to this device, "serves": sites this device's proxy publishes}, or None when it has neither."""
    sites = list_sites(conn, device_id)
    published = [s for s in sites if s["target_device_id"] == device_id]
    serves = [s for s in sites if s["proxy_device_id"] == device_id]
    if not published and not serves:
        return None
    return {"published": published, "serves": serves}


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    sites = list_sites(conn)
    return {"total": len(sites), "enabled": sum(1 for s in sites if s["enabled"]),
            "unmatched": sum(1 for s in sites if s["type"] == "proxy" and s["enabled"] and s["target_device_id"] is None),
            "expiring": sum(1 for s in sites if s["cert_days"] is not None and s["cert_days"] <= 14),
            "down": sum(1 for s in sites if s["check_state"] == "down")}
