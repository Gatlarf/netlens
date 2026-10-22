"""A light check of the services Netlens found against the public CVE list (NVD), by version number.

Netlens' deep scan already records the product and version of every open port, and (from this version on) the CPE name nmap derives from them
(`cpe:/a:openbsd:openssh:8.4p1`). For each distinct CPE this module asks the National Vulnerability Database which CVEs name that product, keeps those whose
affected version range really contains the version, and stores them as findings of the plugin `cvecheck`, next to what a scanner plugin (Greenbone, Nessus ...)
reports. It is a first look, not a scan: nothing is sent to the device, and the answer is only as good as the version string. Two limits are stated in
every finding: a distribution (Debian, Ubuntu, Red Hat ...) often fixes a hole without changing the version number, and a service that hides its version is not
checked at all.

Only the product name and version go to the NVD (a public service), never an address or a name from the network. Results are cached for a week.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app import vulns
from app.db import get_setting, set_setting

PLUGIN_ID = "cvecheck"
SETTINGS_KEY = "cvecheck.settings"
KEY_KEY = "cvecheck.api_key"          # kept apart: settings under this name are stored encrypted (app/vault.py)
LAST_KEY = "cvecheck.last"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DAYS = 7
MAX_QUERIES = 60            # new questions to the NVD in one run (without an API key that takes about seven minutes); the rest follows at the next run
PER_SERVICE = 15            # findings kept per service, the most serious first
STAMP = "%Y-%m-%dT%H:%M:%SZ"
SEVERITIES = ("critical", "high", "medium", "low")
DISTRIBUTION = re.compile(r"debian|ubuntu|\+deb\d|raspbian|el\d|\.fc\d|centos|red ?hat|rhel|alpine|suse|fedora|amazon", re.I)
DEFAULTS = {"enabled": False, "min_severity": "medium"}


class NvdError(Exception):
    """The NVD did not answer as it should (rate limit, outage, bad request)."""


# ----------------------------------------------------------------------------- settings and state
def get_settings(conn: sqlite3.Connection) -> dict:
    try:
        saved = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        saved = {}
    out = {**DEFAULTS, **{k: saved[k] for k in DEFAULTS if k in saved}}
    out["min_severity"] = out["min_severity"] if out["min_severity"] in SEVERITIES else DEFAULTS["min_severity"]
    out["api_key"] = get_setting(conn, KEY_KEY) or ""
    return out


def save_settings(conn: sqlite3.Connection, changes: dict) -> dict:
    current = get_settings(conn)
    if "enabled" in changes:
        current["enabled"] = bool(changes["enabled"])
    if changes.get("min_severity") in SEVERITIES:
        current["min_severity"] = changes["min_severity"]
    if isinstance(changes.get("api_key"), str) and changes["api_key"].strip():
        set_setting(conn, KEY_KEY, changes["api_key"].strip()[:100])
    if changes.get("clear_api_key"):
        conn.execute("DELETE FROM settings WHERE key = ?", (KEY_KEY,))
    set_setting(conn, SETTINGS_KEY, json.dumps({k: current[k] for k in DEFAULTS}))
    conn.commit()
    return get_settings(conn)


def get_last(conn: sqlite3.Connection) -> dict | None:
    try:
        return json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None


def public_state(conn: sqlite3.Connection) -> dict:
    s = get_settings(conn)
    return {"enabled": s["enabled"], "min_severity": s["min_severity"], "has_api_key": bool(s["api_key"]), "last": get_last(conn),
            "services": len(candidates(conn)), "waiting_for_scan": waiting(conn)}


# ----------------------------------------------------------------------------- what to look up
def parse_cpe(cpe: str) -> tuple[str, str, str, str] | None:
    """(vendor, product, version, update) of an nmap CPE for an application (`cpe:/a:vendor:product:version[:update]`); None for anything else.

    nmap writes OpenSSH 8.4p1 as version `8.4p1`; the NVD writes version `8.4` with update `p1`."""
    if not isinstance(cpe, str) or not cpe.startswith("cpe:/a:"):
        return None
    parts = [urllib.parse.unquote(p).lower() for p in cpe[len("cpe:/a:"):].split(":")]
    if len(parts) < 3 or not all(parts[:3]):
        return None
    vendor, product, version = parts[0], parts[1], parts[2]
    update = parts[3] if len(parts) > 3 and parts[3] else ""
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(p\d+)", version)
    if match and not update:
        version, update = match.group(1), match.group(2)
    if not re.search(r"\d", version):
        return None
    return vendor, product, version, update


def cpe23(vendor: str, product: str, version: str, update: str) -> str:
    """The question for the NVD. The update (the p1 of OpenSSH 8.4p1) is left out: the NVD matches ranges on the version. The vendor is a wildcard on purpose: nmap says nginx:nginx where the NVD says f5:nginx; condense() sorts the vendors out."""
    esc = lambda text: re.sub(r"([^A-Za-z0-9_.\-])", r"\\\1", text)
    return f"cpe:2.3:a:*:{esc(product)}:{esc(version)}:*:*:*:*:*:*:*"


def candidates(conn: sqlite3.Connection) -> list[dict]:
    """Every open service whose CPE says what it is and which version it runs."""
    out = []
    for r in conn.execute(
        "SELECT p.device_id, p.proto, p.port, p.product, p.version, p.cpe, d.mac, d.primary_ip, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name "
        "FROM ports p JOIN devices d ON d.id = p.device_id WHERE p.state LIKE 'open%' AND p.cpe IS NOT NULL AND p.cpe != ''"
    ):
        parsed = None
        for one in str(r["cpe"]).split():                     # a service can carry several CPE names
            parsed = parse_cpe(one)
            if parsed:
                break
        if parsed:
            out.append({**dict(r), "parsed": parsed})
    return out


def waiting(conn: sqlite3.Connection) -> bool:
    """True when open ports exist but none carries a CPE yet: the next deep scan fills them in."""
    return conn.execute("SELECT COUNT(*) FROM ports WHERE state LIKE 'open%' AND version IS NOT NULL AND version != ''").fetchone()[0] > 0 and not candidates(conn)


# ----------------------------------------------------------------------------- versions
def vkey(version: str) -> tuple:
    """Order key for version strings: 8.4 < 8.10, 1.1.1 < 1.1.1k < 1.1.1l, 2.4.41 < 2.4.41-3."""
    return tuple((0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.findall(r"\d+|[a-z]+", version.lower()))


def in_range(version: str, match: dict) -> bool | None:
    """Does one affected-version entry of a CVE contain `version`? None when the entry says nothing useful (all versions, or not a version at all)."""
    parts = str(match.get("criteria", "")).split(":")
    listed = parts[5] if len(parts) > 5 else "*"
    low_incl, low_excl = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    high_incl, high_excl = match.get("versionEndIncluding"), match.get("versionEndExcluding")
    bounded = any((low_incl, low_excl, high_incl, high_excl))
    mine = vkey(version)
    if listed in ("*", "-", ""):
        if listed == "-" or not bounded:
            return None
        if low_incl and mine < vkey(low_incl):
            return False
        if low_excl and mine <= vkey(low_excl):
            return False
        if high_incl and mine > vkey(high_incl):
            return False
        if high_excl and mine >= vkey(high_excl):
            return False
        return True
    return vkey(listed) == mine


def _severity(score: float | None, given: str | None) -> str:
    if given and given.lower() in SEVERITIES:
        return given.lower()
    if score is None:
        return "medium"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _metric(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score), m.get("baseSeverity") or data.get("baseSeverity")
    return None, None


def condense(raw: list[dict], vendor: str, product: str, version: str) -> dict:
    """Keep the CVEs whose affected range really contains `version`; count the ones that only claim 'every version' (too vague to report)."""
    vendors = {str(m.get("criteria", "")).split(":")[3] for item in raw for config in (item.get("cve") or item).get("configurations") or [] for node in config.get("nodes") or []
               for m in node.get("cpeMatch") or [] if len(str(m.get("criteria", "")).split(":")) > 5 and str(m["criteria"]).split(":")[4] == product}
    if vendor not in vendors:                       # the NVD names the vendor differently (nginx -> f5): fine when it is the only one for this product, too vague otherwise
        if len(vendors) != 1:
            return {"cves": [], "vague": 0}
        vendor = next(iter(vendors))
    found, vague = [], 0
    for item in raw:
        cve = item.get("cve") or item
        verdicts = []
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    parts = str(match.get("criteria", "")).split(":")
                    if not match.get("vulnerable", True) or len(parts) < 6 or parts[3] != vendor or parts[4] != product:
                        continue
                    verdicts.append(in_range(version, match))
        if True in verdicts:
            score, given = _metric(cve)
            text = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
            found.append({"id": cve.get("id"), "score": score, "severity": _severity(score, given), "summary": text[:300], "published": (cve.get("published") or "")[:10]})
        elif verdicts and all(v is None for v in verdicts):
            vague += 1
    found.sort(key=lambda c: (-(c["score"] or 0), c["id"] or ""))
    return {"cves": [c for c in found if c["id"]], "vague": vague}


# ----------------------------------------------------------------------------- the NVD
def http_json(url: str, api_key: str = "", timeout: float = 40.0) -> dict:
    headers = {"User-Agent": "Netlens-CVE-check", "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:      # noqa: S310 - a fixed https address
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise NvdError("the NVD asked to slow down (rate limit); the check continues at the next run") from exc
        if exc.code == 404:
            return {"vulnerabilities": []}
        raise NvdError(f"the NVD answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise NvdError(f"cannot reach the NVD: {getattr(exc, 'reason', exc)}") from exc


def query(cpe_name: str, api_key: str = "", fetch: Callable[[str, str], dict] = http_json) -> list[dict]:
    out, start = [], 0
    while True:
        url = f"{NVD_URL}?" + urllib.parse.urlencode({"virtualMatchString": cpe_name, "resultsPerPage": 500, "startIndex": start})
        page = fetch(url, api_key)
        rows = page.get("vulnerabilities") or []
        out.extend(rows)
        start += len(rows)
        if not rows or start >= int(page.get("totalResults") or 0) or start >= 5000:
            return out


def _cached(conn: sqlite3.Connection, cpe_name: str, now: datetime) -> dict | None:
    row = conn.execute("SELECT fetched, data FROM cve_cache WHERE cpe = ?", (cpe_name,)).fetchone()
    if not row:
        return None
    try:
        age = now - datetime.strptime(row["fetched"], STAMP).replace(tzinfo=timezone.utc)
        return json.loads(row["data"]) if age < timedelta(days=CACHE_DAYS) else None
    except ValueError:
        return None


# ----------------------------------------------------------------------------- a run
def run(conn: sqlite3.Connection, *, fetch: Callable[[str, str], dict] = http_json, sleep: Callable[[float], None] = time.sleep, now: datetime | None = None,
        max_queries: int = MAX_QUERIES) -> dict:
    """Look up every distinct service version (new questions only; the rest comes from the cache), then replace the findings of this check.
    A run that the NVD cuts short keeps what it has: the services not looked up yet are tried at the next run."""
    now = now or datetime.now(timezone.utc)
    settings = get_settings(conn)
    floor = SEVERITIES.index(settings["min_severity"])
    delay = 0.8 if settings["api_key"] else 6.5          # the NVD allows 5 questions per 30 seconds without a key, 50 with one
    services = candidates(conn)
    distinct: dict[tuple, str] = {}
    for s in services:
        distinct.setdefault(s["parsed"], cpe23(*s["parsed"]))
    results: dict[tuple, dict] = {}
    asked, error = 0, None
    for key, name in distinct.items():
        hit = _cached(conn, name, now)
        if hit is None:
            if asked >= max_queries:
                continue
            try:
                if asked:
                    sleep(delay)
                asked += 1
                hit = condense(query(name, settings["api_key"], fetch), key[0], key[1], key[2])
            except NvdError as exc:
                error = str(exc)
                break
            conn.execute("INSERT INTO cve_cache (cpe, fetched, data) VALUES (?, ?, ?) ON CONFLICT(cpe) DO UPDATE SET fetched = excluded.fetched, data = excluded.data",
                         (name, now.strftime(STAMP), json.dumps(hit)))
            conn.commit()
        results[key] = hit
    conn.execute("DELETE FROM cve_cache WHERE fetched < ?", ((now - timedelta(days=CACHE_DAYS * 4)).strftime(STAMP),))

    stamp = now.strftime(STAMP)
    earlier = {r["finding_id"]: r["first_seen"] for r in conn.execute("SELECT finding_id, first_seen FROM vuln_findings WHERE plugin_id = ?", (PLUGIN_ID,))}
    findings, vague = [], 0
    for s in services:
        hit = results.get(s["parsed"])
        if hit is None:
            continue
        vague += hit["vague"]
        shown = [c for c in hit["cves"] if SEVERITIES.index(c["severity"]) <= floor][:PER_SERVICE]
        distro = bool(DISTRIBUTION.search(f"{s['version'] or ''} {s['cpe'] or ''}"))
        label = " ".join(x for x in (s["product"], s["version"]) if x) or "service"
        for c in shown:
            fid = f"{s['device_id']}-{s['proto']}{s['port']}-{c['id']}"
            findings.append({
                "id": fid, "server_id": "nvd", "host_ip": s["primary_ip"], "host_mac": (s["mac"] or "").lower() or None, "host_name": s["name"] or "",
                "title": f"{label}: {c['id']}" + (f" - {c['summary'][:110]}" if c["summary"] else ""), "cve": [c["id"]], "severity": c["severity"], "score": c["score"],
                "port": s["port"], "proto": s["proto"], "first_seen": earlier.get(fid) or stamp, "last_seen": stamp, "exploited": False,
                "solution": "Found by the version number only: nothing was sent to the device. Update the software, or check that this version is not already patched" +
                            (" (this looks like a distribution package, and distributions often fix a hole without changing the version number: look the CVE up in the distribution's security tracker)." if distro else "."),
                "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}",
            })
    findings = [f for f in findings if f["host_ip"] or f["host_mac"]]
    plan = {"servers": [{"id": "nvd", "name": "Version check against the NVD", "version": "", "online": error is None, "last_scan": stamp,
                         "warnings": [error] if error else []}], "findings": findings}
    from app.plugins.contract import validate_output

    summary = vulns.apply_vulns(conn, PLUGIN_ID, validate_output("vulnerability", plan), now=now)
    last = {"at": stamp, "ok": error is None, "error": error, "services": len(services), "versions": len(distinct), "asked": asked,
            "left": len(distinct) - len(results), "findings": len(findings), "events": summary["events"], "vague_cves_ignored": vague}
    set_setting(conn, LAST_KEY, json.dumps(last))
    return last


def due(conn: sqlite3.Connection, now: datetime | None = None) -> bool:
    """Once a day, and again soon when a run was cut short or no scan has filled in the CPE names yet."""
    if not get_settings(conn)["enabled"]:
        return False
    last = get_last(conn)
    now = now or datetime.now(timezone.utc)
    if not last:
        return True
    try:
        age = now - datetime.strptime(last["at"], STAMP).replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return True
    return age >= (timedelta(minutes=30) if last.get("left") else timedelta(hours=24))


def remove(conn: sqlite3.Connection) -> None:
    """Switched off: the findings of this check go away (the cache stays)."""
    vulns.remove_plugin(conn, PLUGIN_ID)
    conn.execute("DELETE FROM settings WHERE key = ?", (LAST_KEY,))
    conn.commit()
