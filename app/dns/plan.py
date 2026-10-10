"""What should be in DNS, compared with what is there: the plan Netlens shows (and, once approved, applies).

Pure functions, no network and no database, so every rule can be tested. The rules that keep other people's DNS safe:

* A record that Netlens did not create ("foreign") is never changed or removed. Only records carrying the marker comment
  (or that Netlens remembers writing) count as its own.
* A device that registers itself (a Windows machine doing dynamic updates) is recognised by the record it left, and left alone,
  whatever name Netlens would have chosen: an address that already has a name is "registered", not "missing".
* A device without a record waits for a grace period before Netlens registers it, so a client that registers itself on boot
  gets there first. Windows machines can be skipped altogether.
* Only devices you marked as known are registered (a stranger cannot claim a name by announcing a hostname), and
  never a name that is already used by a record pointing elsewhere: that is a conflict you resolve by hand.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.dns import names

MARKER = "managed by Netlens"
STATES = ("add", "update", "delete", "conflict", "wait", "self", "ok", "skip", "orphan")
ACTIONABLE = ("add", "update", "delete")


@dataclass
class DnsDevice:
    id: int
    ip: str | None
    mac: str | None = None
    vendor: str | None = None
    type: str | None = None
    hostname: str | None = None
    custom_name: str | None = None
    dns_name: str | None = None          # the user's own choice for the DNS name
    dns_mode: str = "auto"               # auto | always | never
    trusted: bool = True
    last_seen: str | None = None
    windows: bool = False
    auto_name: str | None = None         # a generated name kept from an earlier run, so names stay stable
    first_missing: str | None = None     # since when the device has had no record


@dataclass
class DnsAlias:
    """A container that shares its host's address (bridge or host network) and publishes ports: it gets a CNAME to its host."""
    key: str            # unique, no colon
    label: str          # the container's name
    host_id: int        # the host's device
    host_ip: str


@dataclass
class DnsSettings:
    networks: list = field(default_factory=list)       # [(ip_network, zone)]
    grace_hours: float = 2
    only_known: bool = True
    skip_windows: bool = True
    template: str = names.DEFAULT_TEMPLATE
    max_offline_days: int = 7
    remove: bool = False
    marker: str = MARKER
    register_containers: bool = False


def parse_networks(text: str | None) -> list[tuple[Any, str]]:
    """"192.168.0.0/24 = home.example.com" per line (or just a zone name for every network)."""
    out = []
    for raw in str(text or "").replace(",", "\n").replace(";", "\n").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            net_text, _, zone = line.partition("=")
            try:
                net = ipaddress.ip_network(net_text.strip(), strict=False)
            except ValueError:
                raise ValueError(f"{net_text.strip()!r} is not a network such as 192.168.0.0/24")
        else:
            net, zone = ipaddress.ip_network("0.0.0.0/0"), line
        zone = zone.strip().rstrip(".").lower()
        if not zone or " " in zone:
            raise ValueError(f"{line!r}: the zone name is missing or invalid")
        out.append((net, zone))
    return sorted(out, key=lambda t: -t[0].prefixlen)   # the most specific network wins


def zone_for(ip: str, networks: list) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return next((zone for net, zone in networks if addr in net), None)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _label_for(d: DnsDevice, template: str) -> tuple[str | None, str, bool]:
    """(label, where it came from, generated?). None as label means the user's own name is not usable."""
    if d.dns_name:
        return names.clean_label(d.dns_name), "your DNS name", False
    label = names.first_label(d.hostname)
    if label:
        return label, "its hostname", False
    label = names.clean_label(d.custom_name)
    if label:
        return label, "its name in Netlens", False
    if d.auto_name:
        return d.auto_name, "a generated name", True
    return names.generated_name(template, d.type, d.vendor, d.mac, d.ip), "a generated name", True


def build_plan(devices: list[DnsDevice], snapshot: dict, settings: DnsSettings, now: str, tracked: frozenset = frozenset(), aliases: list[DnsAlias] | None = None) -> dict:
    """The plan: one item per device (and per leftover record), plus bookkeeping for the caller to store."""
    records = snapshot["records"]
    zones = {z["name"]: z for z in snapshot["zones"]}
    now_dt = _parse(now) or datetime.now(timezone.utc)

    def ours(r) -> bool:
        return bool(r["managed"]) or (r["zone"], r["name"], r["type"], r["value"]) in tracked

    by_name = defaultdict(list)       # (name, type) -> records
    a_by_value = defaultdict(list)    # ip -> A records
    for r in records:
        by_name[(r["name"], r["type"])].append(r)
        if r["type"] == "A":
            a_by_value[r["value"]].append(r)

    def reverse_zone(ip: str):
        reverse = names.reverse_name(ip)
        best = None
        for z in snapshot["zones"]:
            if z["kind"] == "reverse" and (reverse == z["name"] or reverse.endswith("." + z["name"])):
                if best is None or len(z["name"]) > len(best["name"]):
                    best = z
        return best

    items: list[dict] = []
    claimed: set[tuple] = set()
    first_missing: dict[int, str | None] = {}
    auto_names: dict[int, str] = {}

    # ---- who is eligible, and under which name
    eligible: list[tuple[DnsDevice, str, str, str, bool]] = []     # device, zone, label, source, generated
    for d in sorted(devices, key=lambda x: x.id):
        def skip(reason: str, zone: str | None = None, state: str = "skip", label: str | None = None) -> None:
            items.append({"id": f"d{d.id}", "device_id": d.id, "name": names.fqdn(label, zone) if label and zone else (label or ""), "zone": zone, "ip": d.ip, "state": state, "reason": reason, "changes": []})
            first_missing[d.id] = None

        if not d.ip:
            continue
        zone = zone_for(d.ip, settings.networks)
        if zone is None:
            continue          # not in a network that has a zone: not this plugin's business, and not listed
        if d.dns_mode == "never":
            skip("set to never register in DNS", zone)
            continue
        if settings.only_known and not d.trusted and d.dns_mode != "always":
            skip("not marked as known yet (only known devices are registered)", zone)
            continue
        seen = _parse(d.last_seen)
        if seen and now_dt - seen > timedelta(days=settings.max_offline_days) and d.dns_mode != "always":
            skip(f"not seen for more than {settings.max_offline_days} days", zone)
            continue
        label, source, generated = _label_for(d, settings.template)
        if label is None:
            skip("the DNS name you entered is not a valid host name", zone)
            continue
        eligible.append((d, zone, label, source, generated))

    # ---- unique labels per zone (devices that already own their record keep it)
    resolved: dict[int, str] = {}
    for zone in {z for _, z, *_ in eligible}:
        wanted, keep = {}, {}
        for d, z, label, _, _ in eligible:
            if z != zone:
                continue
            wanted[d.id] = label
            mine = [r for r in a_by_value.get(d.ip, []) if r["zone"] == zone and ours(r)]
            if mine:
                keep[d.id] = mine[0]["name"][: -(len(zone) + 1)] if mine[0]["name"].endswith("." + zone) else mine[0]["name"]
        resolved.update(names.resolve_collisions(wanted, keep))

    # ---- one item per eligible device
    for d, zone, _label, source, generated in eligible:
        label = resolved[d.id]
        host = names.fqdn(label, zone)
        if generated:
            auto_names[d.id] = label

        def item(state: str, reason: str, changes: list[dict] | None = None) -> None:
            items.append({"id": f"d{d.id}", "device_id": d.id, "name": host, "zone": zone, "ip": d.ip, "state": state, "reason": reason, "changes": changes or []})

        def change(action: str, rzone: str, name: str, rtype: str, value: str, old: str | None = None) -> dict:
            return {"id": f"{d.id}:{action}:{rtype}:{name}", "action": action, "zone": rzone, "name": name, "type": rtype, "value": value, "old_value": old, "comment": settings.marker}

        zone_info = zones.get(zone)
        if zone_info is None:
            item("skip", f"the zone {zone} does not exist on the DNS server")
            first_missing[d.id] = None
            continue

        a_here = by_name.get((host, "A"), [])
        mine = [r for r in a_here if ours(r)]
        foreign = [r for r in a_here if not ours(r)]
        cname = by_name.get((host, "CNAME"), [])
        other_names = [r for r in a_by_value.get(d.ip, []) if r["name"] != host]
        foreign_ptr = [r for r in by_name.get((names.reverse_name(d.ip), "PTR"), []) if not ours(r)]

        def done(state: str, reason: str, changes=None) -> None:
            first_missing[d.id] = None
            item(state, reason, changes)

        # a record under our name that someone else made
        if any(r["value"] == d.ip for r in foreign):
            done("self", "registered by the device itself or someone else; Netlens leaves it alone")
            continue
        if cname:
            done("conflict", f"{host} is a CNAME to {cname[0]['value']}, not an address record")
            continue
        if foreign and not any(r["value"] == d.ip for r in mine):
            done("conflict", f"{host} already points to {', '.join(sorted({r['value'] for r in foreign}))} (a record Netlens did not create). It is left alone: choose another DNS name for this device or take the record over by hand")
            continue
        # this address already has a name from someone else (a Windows machine that registered itself under its own name)
        foreign_elsewhere = [r for r in other_names if not ours(r)]
        if not mine and (foreign_elsewhere or foreign_ptr):
            existing = (foreign_elsewhere[0]["name"] if foreign_elsewhere else foreign_ptr[0]["value"])
            done("self", f"this address is already registered as {existing}; Netlens leaves it alone")
            continue

        if not zone_info["writable"]:
            done("skip", f"the zone {zone} is read-only for the plugin's account (or on a secondary server)")
            continue

        changes: list[dict] = []
        reasons: list[str] = []
        if mine:
            correct = [r for r in mine if r["value"] == d.ip]
            if correct:
                claimed.add((correct[0]["zone"], correct[0]["name"], "A", correct[0]["value"]))
            else:
                changes.append(change("update", zone, host, "A", d.ip, mine[0]["value"]))
                claimed.add((mine[0]["zone"], mine[0]["name"], "A", mine[0]["value"]))
                reasons.append(f"the address changed from {mine[0]['value']} to {d.ip}")
        else:
            # missing: Windows machines and the grace period first
            if d.windows and settings.skip_windows and d.dns_mode != "always":
                done("skip", "Windows registers itself; set the device to \"Always register\" to register it anyway")
                continue
            if d.dns_mode != "always" and settings.grace_hours > 0:
                since = _parse(d.first_missing) or now_dt
                first_missing[d.id] = _iso(since)
                waited = (now_dt - since).total_seconds() / 3600
                if waited < settings.grace_hours:
                    left = settings.grace_hours - waited
                    item("wait", f"no record yet; waiting {left:.1f} h more in case the device registers itself ({source})")
                    continue
            changes.append(change("add", zone, host, "A", d.ip))
            reasons.append(f"not in DNS yet ({source})")

        # the reverse record
        rz = reverse_zone(d.ip)
        if rz is not None and rz["writable"]:
            rname = names.reverse_name(d.ip)
            existing = by_name.get((rname, "PTR"), [])
            right = [r for r in existing if r["value"] == host]
            mine_ptr = [r for r in existing if ours(r)]
            if right:
                claimed.add((right[0]["zone"], right[0]["name"], "PTR", right[0]["value"]))
            elif not foreign_ptr:
                if mine_ptr:
                    changes.append(change("update", rz["name"], rname, "PTR", host, mine_ptr[0]["value"]))
                    claimed.add((mine_ptr[0]["zone"], mine_ptr[0]["name"], "PTR", mine_ptr[0]["value"]))
                else:
                    changes.append(change("add", rz["name"], rname, "PTR", host))
                if not reasons:
                    reasons.append("the reverse record is missing or wrong")
        if not changes:
            done("ok", "registered by Netlens")
            continue
        first_missing[d.id] = None
        state = "add" if any(c["action"] == "add" and c["type"] == "A" for c in changes) else "update"
        item(state, "; ".join(reasons), changes)

    # ---- containers that share their host's address: a CNAME to the host (only when the host itself is registered)
    if settings.register_containers:
        device_names = {names.fqdn(resolved[d.id], z): d.id for d, z, *_ in eligible}
        # the name to point at: the host's existing address record (made by Netlens or not, e.g. a Windows host's own), else the one being added
        planned = {i["device_id"]: i for i in items if i["device_id"] is not None}
        targets = {}
        for d, z, *_ in eligible:
            existing = sorted(a_by_value.get(d.ip, []), key=lambda r: (not ours(r), r["name"]))
            if existing:
                targets[d.id] = existing[0]["name"]
            elif planned.get(d.id, {}).get("state") == "add":
                targets[d.id] = names.fqdn(resolved[d.id], z)
        taken: set[str] = set(device_names)
        for a in sorted(aliases or [], key=lambda x: x.key):
            zone = zone_for(a.host_ip, settings.networks)
            label = names.clean_label(a.label)
            if zone is None or not label:
                continue
            fq = names.fqdn(label, zone)
            alias_item_id = f"c:{a.key}"

            def alias_item(state: str, reason: str, changes: list[dict] | None = None) -> None:
                items.append({"id": alias_item_id, "device_id": None, "device": f"container {a.label}", "name": fq, "zone": zone, "ip": None, "state": state, "reason": reason, "changes": changes or []})

            def alias_change(action: str, value: str, old: str | None = None) -> dict:
                return {"id": f"{alias_item_id}:{action}:CNAME:{fq}", "action": action, "zone": zone, "name": fq, "type": "CNAME", "value": value, "old_value": old, "comment": settings.marker}

            target = targets.get(a.host_id)
            zone_info = zones.get(zone)
            if target is None:
                alias_item("skip", "its host is not registered in DNS by Netlens (a host that registers itself, or is skipped, gets no alias)")
                continue
            if zone_info is None or not zone_info["writable"]:
                alias_item("skip", f"the zone {zone} is missing or read-only for the plugin's account")
                continue
            if fq in taken:
                alias_item("conflict", f"{fq} is already the name of a device or of another container")
                continue
            taken.add(fq)
            cnames, address = by_name.get((fq, "CNAME"), []), by_name.get((fq, "A"), [])
            mine = [r for r in cnames if ours(r)]
            if address or [r for r in cnames if not ours(r)]:
                other = (address or cnames)[0]
                alias_item("conflict", f"{fq} already exists ({other['type']} {other['value']}) and was not made by Netlens; it is left alone")
                continue
            if mine and mine[0]["value"] == target:
                claimed.add((mine[0]["zone"], mine[0]["name"], "CNAME", mine[0]["value"]))
                alias_item("ok", "registered by Netlens")
            elif mine:
                claimed.add((mine[0]["zone"], mine[0]["name"], "CNAME", mine[0]["value"]))
                alias_item("update", f"its host is now called {target}", [alias_change("update", target, mine[0]["value"])])
            else:
                alias_item("add", f"a container on {target} that publishes ports", [alias_change("add", target)])

    # ---- records Netlens made that nobody wants any more
    for r in records:
        key = (r["zone"], r["name"], r["type"], r["value"])
        if r["type"] in ("A", "PTR", "CNAME") and ours(r) and key not in claimed:
            delete = settings.remove and zones.get(r["zone"], {}).get("writable")
            items.append({
                "id": f"o:{r['type']}:{r['name']}:{r['value']}", "device_id": None, "name": r["name"], "zone": r["zone"], "ip": r["value"] if r["type"] == "A" else None,
                "state": "delete" if delete else "orphan",
                "reason": "Netlens made this record, but no device wants it any more" + ("" if delete else " (removing records is off)"),
                "changes": [{"id": f"o:delete:{r['type']}:{r['name']}:{r['value']}", "action": "delete", "zone": r["zone"], "name": r["name"], "type": r["type"], "value": r["value"], "old_value": None, "comment": settings.marker}] if delete else [],
            })

    order = {s: i for i, s in enumerate(("conflict", "add", "update", "delete", "wait", "orphan", "skip", "self", "ok"))}
    items.sort(key=lambda i: (order[i["state"]], i["name"]))
    counts: dict[str, int] = defaultdict(int)
    for i in items:
        counts[i["state"]] += 1
    return {"items": items, "first_missing": first_missing, "auto_names": auto_names, "counts": dict(counts)}
