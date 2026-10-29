"""Networks: the ranges Netlens scans, as things with a name, a state and the devices that live in them.

A scan covers all ranges in one run, so a range that becomes unreachable (a firewall rule, a VPN that went down, a routing change) does not fail the
scan: it just stops delivering hosts, and its devices go offline one by one. Every scan records how many hosts answered in each range. A range
that had hosts and now has none (or far fewer) for two scans in a row is *quiet*: `network_quiet` is raised, `network_back` when it recovers.

The state is kept per range in `networks`; which network a device belongs to is worked out from its address (the most specific range wins).
Nothing here depends on VLANs: a network is whatever range you scan.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from typing import Any

from app.db import add_event, insert_id, utcnow

MAX_TRACKED_PREFIX = 30       # a /31 or a single address is not a network: a host that stops answering is a device that went offline
QUIET_SCANS = 2               # scans in a row that look wrong before anything is said
MIN_BASELINE = 1.5            # a range that never had more than a host or two has nothing to lose
FEW_BASELINE = 8              # from this many hosts "far fewer" is meaningful
FAR_FEWER = 0.25              # less than a quarter of the usual number of hosts
RECOVERED = 0.6               # a quiet range is back when this share of the usual number answers again
SMOOTHING = 0.1               # how fast the usual number follows the real one


def parse(targets) -> list[ipaddress.IPv4Network]:
    """The networks among the scan targets (single addresses and unparseable entries are not networks)."""
    out = []
    for t in targets or []:
        try:
            net = ipaddress.ip_network(str(t).strip(), strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen <= MAX_TRACKED_PREFIX and net not in out:
            out.append(net)
    return out


def _containing(nets: list[ipaddress.IPv4Network], ip: str | None) -> ipaddress.IPv4Network | None:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    best = None
    for n in nets:
        if addr in n and (best is None or n.prefixlen > best.prefixlen):
            best = n
    return best


def _rows(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    return {r["cidr"]: r for r in conn.execute("SELECT * FROM networks")}


def record_scan(conn: sqlite3.Connection, targets, host_ips: list[str], now: str | None = None) -> list[str]:
    """After a quick or deep scan: how many hosts answered in each scanned range. Returns the events that were raised."""
    now = now or utcnow()
    nets = parse(targets)
    known = _rows(conn)
    raised: list[str] = []
    counts = {str(n): 0 for n in nets}
    for ip in host_ips:
        n = _containing(nets, ip)
        if n is not None:
            counts[str(n)] += 1
    wanted = {str(n) for n in nets}
    for cidr in known:
        if cidr not in wanted and known[cidr]["active"]:
            conn.execute("UPDATE networks SET active = 0 WHERE cidr = ?", (cidr,))
    for cidr in sorted(wanted, key=lambda c: ipaddress.ip_network(c)):
        count = counts[cidr]
        row = known.get(cidr)
        if row is None:
            insert_id(conn, "INSERT INTO networks (cidr, active, status, first_seen, last_scan, last_hosts, baseline, low_scans) VALUES (?, 1, ?, ?, ?, ?, ?, 0)",
                      (cidr, "ok" if count else "empty", now, now, count, float(count) if count else None))
            continue
        base = row["baseline"] or 0.0
        low = (count == 0 and base >= MIN_BASELINE) or (base >= FEW_BASELINE and count < FAR_FEWER * base)
        low_scans = row["low_scans"] + 1 if low else 0
        status, since = row["status"], row["quiet_since"]
        name = row["name"] or cidr
        if low and low_scans >= QUIET_SCANS and status != "quiet":
            status, since = "quiet", now
            what = "no host answers" if count == 0 else f"only {count} of the usual {round(base)} hosts answer"
            add_event(conn, "network_quiet", f"{name}: {what} in this range any more. Check the route, the firewall rules and the VPN towards it", now=now, subject=f"network:{row['id']}")
            raised.append("network_quiet")
        elif status == "quiet" and not low and count >= max(1, RECOVERED * base):
            status, since = "ok", None
            add_event(conn, "network_back", f"{name}: {count} hosts answer again in this range", now=now, subject=f"network:{row['id']}")
            raised.append("network_back")
        elif status != "quiet":
            status = "ok" if (count or base) else "empty"
        if not low and status != "quiet":
            base = float(count) if not base else (1 - SMOOTHING) * base + SMOOTHING * count      # while quiet the usual number stays what it was
        conn.execute("UPDATE networks SET active = 1, status = ?, quiet_since = ?, last_scan = ?, last_hosts = ?, baseline = ?, low_scans = ? WHERE cidr = ?",
                     (status, since, now, count, base if base else None, low_scans, cidr))
    conn.commit()
    return raised


def listing(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every network with what is in it now."""
    rows = [r for r in conn.execute("SELECT * FROM networks WHERE active = 1")]
    nets = {str(n): n for n in parse([r["cidr"] for r in rows])}
    parsed = list(nets.values())
    stats = {c: {"devices": 0, "online": 0, "no_mac": 0} for c in nets}
    for d in conn.execute("SELECT primary_ip, mac, online FROM devices"):
        n = _containing(parsed, d["primary_ip"])
        if n is not None:
            s = stats[str(n)]
            s["devices"] += 1
            s["online"] += 1 if d["online"] else 0
            s["no_mac"] += 0 if d["mac"] else 1
    out = []
    for r in sorted(rows, key=lambda r: ipaddress.ip_network(r["cidr"])):
        s = stats.get(r["cidr"], {"devices": 0, "online": 0, "no_mac": 0})
        out.append({"id": r["id"], "cidr": r["cidr"], "name": r["name"] or "", "label": r["name"] or r["cidr"], "status": r["status"] or "empty", "since": r["quiet_since"],
                    "last_scan": r["last_scan"], "last_hosts": r["last_hosts"], "usual_hosts": round(r["baseline"]) if r["baseline"] else 0, **s})
    return out


def rename(conn: sqlite3.Connection, network_id: int, name: str) -> bool:
    name = " ".join((name or "").split())
    if len(name) > 60:
        raise ValueError("a name has at most 60 characters")
    cur = conn.execute("UPDATE networks SET name = ? WHERE id = ?", (name or None, network_id))
    conn.commit()
    return cur.rowcount > 0


def assign(conn: sqlite3.Connection, devices: list[dict[str, Any]]) -> None:
    """Add `network` ({id, label}, or None) to device dicts that have a primary_ip."""
    rows = [r for r in conn.execute("SELECT id, cidr, name FROM networks WHERE active = 1")]
    by_cidr = {r["cidr"]: r for r in rows}
    parsed = parse(by_cidr)
    for d in devices:
        n = _containing(parsed, d.get("primary_ip"))
        r = by_cidr.get(str(n)) if n is not None else None
        d["network"] = {"id": r["id"], "label": r["name"] or r["cidr"]} if r is not None else None


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    rows = conn.execute("SELECT cidr, name, status FROM networks WHERE active = 1 ORDER BY cidr").fetchall()
    quiet = [r["name"] or r["cidr"] for r in rows if r["status"] == "quiet"]
    return {"tracked": len(rows), "quiet": len(quiet), "quiet_names": quiet[:5]}
