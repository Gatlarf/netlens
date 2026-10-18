"""The CISA list of known exploited vulnerabilities (KEV), used to mark the findings of a vulnerability scanner.

A scanner says "CVE-2024-6387, score 8.1"; the CISA list says whether that vulnerability is being used by attackers right now. Netlens fetches the list (one small
JSON file) once a day, but only while a vulnerability scanner plugin is connected and the licence allows it, keeps the CVE numbers, and marks every finding that
has one of them as *known to be exploited*. Netlens never guesses a vulnerability from a service name: the list has no versions, so that would flag every
OpenSSH on the network. The list is public; nothing about your network is sent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable

from app.db import get_setting, set_setting

log = logging.getLogger(__name__)
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEY, STAMP_KEY = "kev.cves", "kev.fetched"
MAX_BYTES = 8_000_000
EVERY = timedelta(hours=24)
CVE = re.compile(r"^CVE-\d{4}-\d{4,9}$")


def parse(text: str) -> set[str]:
    """The CVE numbers of a KEV catalogue (the CISA JSON file); an empty set when it is not one."""
    try:
        doc = json.loads(text)
    except ValueError:
        return set()
    rows = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    return {str(r["cveID"]).upper() for r in rows or [] if isinstance(r, dict) and CVE.match(str(r.get("cveID") or "").upper())}


def known(conn: sqlite3.Connection) -> set[str]:
    try:
        return set(json.loads(get_setting(conn, KEY) or "[]"))
    except ValueError:
        return set()


def fetch(url: str = URL, timeout: float = 25.0) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "Netlens", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as resp:        # noqa: S310 - a fixed https address
        return resp.read(MAX_BYTES).decode("utf-8", "replace")


def due(conn: sqlite3.Connection, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    stamp = get_setting(conn, STAMP_KEY)
    try:
        return not stamp or now - datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) >= EVERY
    except ValueError:
        return True


def mark(conn: sqlite3.Connection, cves: set[str]) -> int:
    """Flag the stored findings that have a CVE of the list as exploited; returns how many changed."""
    changed = 0
    for r in conn.execute("SELECT plugin_id, finding_id, cves FROM vuln_findings WHERE exploited = 0 AND cves != '[]'").fetchall():
        if any(c in cves for c in json.loads(r["cves"] or "[]")):
            conn.execute("UPDATE vuln_findings SET exploited = 1 WHERE plugin_id = ? AND finding_id = ?", (r["plugin_id"], r["finding_id"]))
            changed += 1
    conn.commit()
    return changed


def refresh(conn: sqlite3.Connection, fetcher: Callable[[], str] = fetch, now: datetime | None = None) -> dict:
    """Fetch the list and mark the findings. A failed or odd answer keeps the list we have."""
    now = now or datetime.now(timezone.utc)
    cves = parse(fetcher())
    if len(cves) < 100:                         # the real list has over a thousand: anything much smaller is not it
        raise ValueError("the answer is not the CISA list of known exploited vulnerabilities")
    set_setting(conn, KEY, json.dumps(sorted(cves)))
    set_setting(conn, STAMP_KEY, now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return {"cves": len(cves), "marked": mark(conn, cves)}


def wanted(conn: sqlite3.Connection) -> bool:
    from app import licence

    return licence.allows(conn, "vulnerabilities") and conn.execute("SELECT 1 FROM vuln_servers LIMIT 1").fetchone() is not None


async def loop(db_path: str) -> None:
    from app.db import connect

    await asyncio.sleep(75)
    while True:
        try:
            conn = connect(db_path)
            try:
                if wanted(conn) and due(conn):
                    log.info("KEV list: %s", await asyncio.to_thread(refresh, conn))
            finally:
                conn.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a missing list only means fewer "exploited" marks
            log.warning("KEV list not updated: %s", exc)
        await asyncio.sleep(3600)
