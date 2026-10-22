"""What Netlens learns from a topology plugin besides the links: names from the router, Wi-Fi signal samples, roaming."""

from __future__ import annotations

import sqlite3

from app.db import add_event, utcnow
from app.plugins.matching import norm_mac

WIFI_RETENTION_DAYS = 14
ROAM_WINDOW_HOURS = 24  # a node change counts as roaming only when the previous sample is this recent
ALIAS_PRIORITY = ("ptr", "upnp", "mdns", "dhcp", "router", "smb", "netbios", "docker")  # which name wins as a device's hostname when it has none
MAX_NAME = 80


def device_lookup(conn: sqlite3.Connection) -> tuple[dict[str, int], dict[str, int]]:
    """(device id by MAC, device id by IP); the newest device wins a clash."""
    by_mac: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for row in conn.execute("SELECT id, mac, primary_ip FROM devices ORDER BY id DESC"):
        if row["mac"]:
            by_mac[norm_mac(row["mac"])] = row["id"]
        if row["primary_ip"]:
            by_ip[row["primary_ip"]] = row["id"]
    for row in conn.execute("SELECT device_id, ip FROM device_ips ORDER BY device_id DESC"):
        by_ip[row["ip"]] = row["device_id"]
    return by_mac, by_ip


def refresh_hostname(conn: sqlite3.Connection, device_id: int) -> None:
    """A device without a hostname takes its best alias (PTR, UPnP, mDNS, router name, in that order)."""
    row = conn.execute("SELECT hostname FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None or (row["hostname"] or "").strip():
        return
    names = conn.execute("SELECT name, source FROM device_names WHERE device_id = ?", (device_id,)).fetchall()
    for source in ALIAS_PRIORITY:
        for n in names:
            if n["source"] == source and n["name"].strip():
                conn.execute("UPDATE devices SET hostname = ? WHERE id = ?", (n["name"].strip(), device_id))
                return


def record_guest_names(conn: sqlite3.Connection, plugin_id: str, guests: list[dict], now: str | None = None) -> int:
    """A container that has its own address on the network is a device: its container name becomes one of the device's names
    (source 'docker'), and the device's hostname when it has none, so it is not shown by its address only."""
    now = now or utcnow()
    count = 0
    for g in guests:
        name = (g.get("name") or "").strip()[:MAX_NAME]
        if g.get("kind") != "container" or g.get("device_id") is None or not name:
            continue
        conn.execute(
            """
            INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, 'docker', ?, ?)
            ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (g["device_id"], name, now, now),
        )
        refresh_hostname(conn, g["device_id"])
        count += 1
    return count


def record_router_names(conn: sqlite3.Connection, data: dict, now: str | None = None) -> int:
    """Store the names a router knows its clients by (source 'router'). Returns how many were recorded."""
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    count = 0
    for client in data.get("clients", []):
        name = (client.get("name") or "").strip()[:MAX_NAME]
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if not name or device_id is None or name == client.get("ip"):
            continue
        conn.execute(
            """
            INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, 'router', ?, ?)
            ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (device_id, name, now, now),
        )
        refresh_hostname(conn, device_id)
        count += 1
    conn.commit()
    return count


def record_client_hints(conn: sqlite3.Connection, data: dict) -> int:
    """What the router / controller worked out about its clients (manufacturer, OS, model, type) becomes evidence for the classifier.

    The router's own type is weaker than a clear name or a scan, but it is free and it sees devices Netlens cannot scan.
    Returns how many devices received something.
    """
    from app.scanner import fingerprint, store

    by_mac, by_ip = device_lookup(conn)
    touched = 0
    for client in data.get("clients", []):
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if device_id is None:
            continue
        hints: list[str] = []
        os_text = client.get("os")
        vendor = (client.get("vendor") or "").strip()
        if vendor and not os_text:  # routers often put the DHCP vendor class ("MSFT 5.0", "android-dhcp-13") in the vendor field
            os_text = fingerprint.os_from_dhcp_class(vendor)
            if os_text:
                vendor = ""
        if os_text:
            hints.append(f"os:{os_text}")
        if client.get("model"):
            hints.append(f"model:{client['model']}")
        if client.get("device_type"):
            hints.append(f"ctl:{client['device_type']}")
        changed = store.add_hints(conn, device_id, hints, replace_prefix=("ctl:",))
        if vendor and vendor.lower() not in ("others", "unknown", "-"):
            known = conn.execute("SELECT vendor FROM devices WHERE id = ?", (device_id,)).fetchone()["vendor"]
            if not known:
                conn.execute("UPDATE devices SET vendor = ? WHERE id = ?", (vendor, device_id))
                changed = True
        if changed:
            store.reclassify_device(conn, device_id)
            touched += 1
    conn.commit()
    return touched


def record_client_links(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> int:
    """Remember which node (switch, access point) and port each client is connected to; clients this plugin no longer reports are forgotten.

    A link the owner set by hand is never changed: what the plugin reports instead is kept beside it (seen_node, seen_port), so the page can say they differ."""
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    node_name = {mac: n.get("name") for n in data.get("nodes", []) for mac in (n.get("macs") or [n["mac"]])}
    node_device: dict[str, int] = {}                  # node MAC -> the node as a device of its own
    for n in data.get("nodes", []):
        found = next((by_mac[m] for m in (n.get("macs") or [n["mac"]]) if m in by_mac), None) or by_ip.get(n.get("ip") or "")
        if found is not None:
            for m in (n.get("macs") or [n["mac"]]):
                node_device[m] = found
    manual = {r["device_id"] for r in conn.execute("SELECT device_id FROM client_links WHERE source = 'manual'")}
    seen: set[int] = set()
    for client in data.get("clients", []):
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if device_id is None or device_id in seen or not (client.get("node_mac") or client.get("port")):
            continue
        if device_id in manual:
            conn.execute("UPDATE client_links SET seen_node = ?, seen_port = ? WHERE device_id = ?",
                         (node_name.get(client.get("node_mac")) or client.get("node_mac"), client.get("port"), device_id))
            continue
        seen.add(device_id)
        conn.execute(
            """
            INSERT INTO client_links (device_id, plugin_id, node_mac, node_name, port, medium, updated, source, node_device_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'plugin', ?)
            ON CONFLICT(device_id) DO UPDATE SET plugin_id = excluded.plugin_id, node_mac = excluded.node_mac, node_name = excluded.node_name,
                port = excluded.port, medium = excluded.medium, updated = excluded.updated, node_device_id = excluded.node_device_id
            WHERE client_links.source != 'manual'
            """,
            (device_id, plugin_id, client.get("node_mac"), node_name.get(client.get("node_mac")), client.get("port"), client.get("medium"), now,
             node_device.get(client.get("node_mac"))),
        )
    if seen:
        marks = ",".join("?" for _ in seen)
        conn.execute(f"DELETE FROM client_links WHERE plugin_id = ? AND device_id NOT IN ({marks})", (plugin_id, *seen))
    else:
        conn.execute("DELETE FROM client_links WHERE plugin_id = ?", (plugin_id,))
    conn.commit()
    return len(seen)


def record_wifi(conn: sqlite3.Connection, data: dict, now: str | None = None) -> dict:
    """Store one signal sample per Wi-Fi client and log a `wifi_roamed` event when a client changed node.

    Call once per fresh fetch (not when links are re-applied), so every sample is a real measurement.
    """
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    node_name = {m: n.get("name") or n["mac"] for n in data.get("nodes", []) for m in n["macs"]}
    gateway = next((n for n in data.get("nodes", []) if n["role"] == "gateway"), None)
    samples = roams = 0
    from datetime import datetime, timedelta, timezone

    cutoff_roam = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(hours=ROAM_WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for client in data.get("clients", []):
        if client.get("medium") != "wifi":
            continue
        device_id = by_mac.get(client["mac"]) or by_ip.get(client.get("ip") or "")
        if device_id is None:
            continue
        node = node_name.get(client.get("node_mac") or (gateway or {}).get("mac"), None)
        previous = conn.execute("SELECT ts, node FROM wifi_samples WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
        if previous and previous["node"] and node and previous["node"] != node and previous["ts"] >= cutoff_roam:
            add_event(conn, "wifi_roamed", f"{previous['node']} -> {node}" + (f" ({client['band']})" if client.get("band") else ""), device_id=device_id, now=now)
            roams += 1
        conn.execute(
            "INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps, rx_mbps) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_id, now, node, client.get("band"), client.get("rssi"), client.get("tx_mbps"), client.get("rx_mbps")),
        )
        samples += 1
    old = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(days=WIFI_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM wifi_samples WHERE ts < ?", (old,))
    conn.commit()
    return {"samples": samples, "roams": roams}


PORT_RETENTION_DAYS = 14
COUNTER_WRAP = 2 ** 32


def _counter_delta(new, old):
    """Growth of a packet counter between two syncs. A counter that went back either wrapped around its 32 bits (it was near the top) or was reset (a restart): the latter gives None."""
    if new is None or old is None:
        return None
    if new >= old:
        return new - old
    return new + COUNTER_WRAP - old if old > COUNTER_WRAP - 2 ** 26 else None


def _record_port_series(conn, device_id, node_name, ports, before, now):
    """Packets per second, errors per second and link state of every port as time series (they show up as graphs under Ports on the switch's page)."""
    from datetime import datetime, timezone

    from app import tsdb

    store = tsdb.for_conn(conn)
    if store is None:
        return
    stamp = lambda text: int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    points = []
    for port in ports:
        label = f"Port {port['port']}" + (f" {port['name']}" if port.get("name") else "")
        if port["enabled"]:                                     # a port the administrator switched off is not reported as "down"
            points.append(("device", device_id, "if_up", 1.0 if port["up"] else 0.0, label, "state"))
        old = before.get(port["port"])
        if old is None or not port["up"]:
            continue
        seconds = stamp(now) - stamp(old["updated"])
        if seconds <= 0:
            continue
        for key, metric in (("tx_packets", "net_tx_pps"), ("rx_packets", "net_rx_pps")):
            grown = _counter_delta(port.get(key), old[key])
            if grown is not None:
                points.append(("device", device_id, metric, grown / seconds, label, "pps"))
        rates = []
        for key, metric in (("tx_bytes", "net_tx_bps"), ("rx_bytes", "net_rx_bps")):
            grown = _counter_delta(port.get(key), old[key])
            if grown is not None:
                rates.append(grown * 8 / seconds)
                points.append(("device", device_id, metric, grown * 8 / seconds, label, "bps"))
        if rates and port.get("speed_mbps"):                    # how full the link is: the busier direction against the negotiated speed
            points.append(("device", device_id, "if_util_pct", min(100.0, max(rates) / (port["speed_mbps"] * 1_000_000) * 100), label, "%"))
        errors = [_counter_delta(port.get(k), old[k]) for k in ("tx_errors", "rx_errors")]
        if None not in errors and (sum(errors) > 0 or store.latest("device", device_id, "if_err_ps", label) is not None):    # a port that never had an error gets no graph
            points.append(("device", device_id, "if_err_ps", sum(errors) / seconds, label, "/s"))
    if points:
        store.record(points, ts=stamp(now))


def record_switch_ports(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> int:
    """Store the ports a topology node reports (a switch without SNMP): the latest state, one counter sample per sync, and a
    `link_down` / `link_up` event when a port changed state since the previous sync. Returns the number of ports recorded."""
    from datetime import datetime, timedelta, timezone

    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    recorded = 0
    for node in data.get("nodes", []):
        ports = node.get("ports") or []
        device_id = next((by_mac[m] for m in node["macs"] if m in by_mac), None) or by_ip.get(node.get("ip") or "")
        if device_id is None or not ports:
            continue
        before = {r["port"]: r for r in conn.execute("SELECT port, up, tx_packets, rx_packets, tx_errors, rx_errors, tx_bytes, rx_bytes, updated FROM switch_ports WHERE device_id = ?", (device_id,))}
        _record_port_series(conn, device_id, node.get("name"), ports, before, now)
        for port in ports:
            number, up = port["port"], 1 if port["up"] else 0
            label = f"port {number}" + (f" ({port['name']})" if port.get("name") else "")
            if number in before and before[number]["up"] != up:
                add_event(conn, "link_up" if up else "link_down", f"{node.get('name') or node['mac']}: {label}" + (f" at {port['speed_mbps']:g} Mbit/s" if up and port.get("speed_mbps") else ""), device_id=device_id, now=now)
            counters = (port.get("tx_packets"), port.get("rx_packets"), port.get("tx_errors"), port.get("rx_errors"))
            conn.execute(
                """
                INSERT INTO switch_ports (device_id, port, plugin_id, name, enabled, up, speed_mbps, duplex, tx_packets, rx_packets, tx_errors, rx_errors, tx_bytes, rx_bytes, updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, port) DO UPDATE SET plugin_id = excluded.plugin_id, name = excluded.name, enabled = excluded.enabled, up = excluded.up,
                    speed_mbps = excluded.speed_mbps, duplex = excluded.duplex, tx_packets = excluded.tx_packets, rx_packets = excluded.rx_packets,
                    tx_errors = excluded.tx_errors, rx_errors = excluded.rx_errors, tx_bytes = excluded.tx_bytes, rx_bytes = excluded.rx_bytes,
                    updated = excluded.updated
                """,
                (device_id, number, plugin_id, port.get("name"), 1 if port["enabled"] else 0, up, port.get("speed_mbps"), port.get("duplex"), *counters, port.get("tx_bytes"), port.get("rx_bytes"), now),
            )
            conn.execute(
                "INSERT INTO switch_port_samples (device_id, port, ts, up, speed_mbps, tx_packets, rx_packets, tx_errors, rx_errors) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, number, now, up, port.get("speed_mbps"), *counters),
            )
            recorded += 1
        gone = [n for n in before if n not in {p["port"] for p in ports}]
        for number in gone:
            conn.execute("DELETE FROM switch_ports WHERE device_id = ? AND port = ?", (device_id, number))
    old = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(days=PORT_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM switch_port_samples WHERE ts < ?", (old,))
    conn.commit()
    return recorded


USAGE_RETENTION_DAYS = 400


def record_usage(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> int:
    """Store the traffic per application and per device a router reports for a day (the figure is the total so far, so the latest one replaces the
    earlier ones). Devices are found by MAC; traffic of a device Netlens does not know is left out. Returns the number of application rows written."""
    from datetime import datetime, timedelta

    now = now or utcnow()
    by_mac, _ = device_lookup(conn)
    written = 0
    for entry in data.get("usage") or []:
        for app in entry["applications"]:
            conn.execute(
                "INSERT INTO app_usage (day, source, name, rx_bytes, tx_bytes, updated) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(day, source, name) DO UPDATE SET rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes, updated = excluded.updated",
                (entry["day"], plugin_id, app["name"], app["rx_bytes"], app["tx_bytes"], now),
            )
            written += 1
        for client in entry["clients"]:
            device_id = by_mac.get(client["mac"])
            if device_id is not None:
                conn.execute(
                    "INSERT INTO client_usage (day, source, device_id, rx_bytes, tx_bytes, updated) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(day, source, device_id) DO UPDATE SET rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes, updated = excluded.updated",
                    (entry["day"], plugin_id, device_id, client["rx_bytes"], client["tx_bytes"], now),
                )
                if client.get("applications"):          # an empty list means "not read this time": what was stored stays
                    # the day's figures replace what was stored for this device and day (an application that no longer appears is dropped)
                    conn.execute("DELETE FROM client_app_usage WHERE day = ? AND source = ? AND device_id = ?", (entry["day"], plugin_id, device_id))
                    for app in client["applications"]:
                        conn.execute(
                            "INSERT INTO client_app_usage (day, source, device_id, name, rx_bytes, tx_bytes, updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (entry["day"], plugin_id, device_id, app["name"], app["rx_bytes"], app["tx_bytes"], now),
                        )
    cutoff = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=USAGE_RETENTION_DAYS)).strftime("%Y-%m-%d")
    conn.execute("DELETE FROM app_usage WHERE day < ?", (cutoff,))
    conn.execute("DELETE FROM client_usage WHERE day < ?", (cutoff,))
    conn.execute("DELETE FROM client_app_usage WHERE day < ?", (cutoff,))
    conn.commit()
    return written


LICENCE_WARN_DAYS = 30


def record_firewall(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> int:
    """Store what a firewall node reports (version, high availability, VPN tunnels, licences) and raise events when it changes between two syncs:
    `firewall_ha` (the state changed, for example a failover), `vpn_down` / `vpn_up` (a tunnel), `firewall_licence` (a licence ends within 30 days, once per end date)."""
    import json
    from datetime import date, datetime

    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    today = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").date()
    count = 0
    for node in data.get("nodes", []):
        fw = node.get("firewall")
        device_id = next((by_mac[m] for m in node["macs"] if m in by_mac), None) or by_ip.get(node.get("ip") or "")
        if not fw or device_id is None:
            continue
        name = node.get("name") or node["mac"]
        row = conn.execute("SELECT data FROM firewall_state WHERE device_id = ?", (device_id,)).fetchone()
        try:
            before = json.loads(row["data"]) if row else None
        except ValueError:
            before = None
        warned = dict((before or {}).get("warned") or {})
        if before is not None:
            old_ha, new_ha = (before.get("ha") or {}).get("state"), (fw.get("ha") or {}).get("state")
            if old_ha and new_ha and old_ha != new_ha:
                add_event(conn, "firewall_ha", f"{name}: high availability {old_ha} -> {new_ha}", device_id=device_id, now=now)
            was = {t["name"]: t["up"] for t in before.get("tunnels") or []}
            for t in fw["tunnels"]:
                if t["name"] in was and was[t["name"]] != t["up"]:
                    add_event(conn, "vpn_up" if t["up"] else "vpn_down", f"{name}: tunnel {t['name']}" + (f" to {t['remote']}" if t.get("remote") else ""), device_id=device_id, now=now)
        for lic in fw["licences"]:
            if not lic["expires"]:
                continue
            days = (date.fromisoformat(lic["expires"]) - today).days
            if days <= LICENCE_WARN_DAYS and warned.get(lic["name"]) != lic["expires"]:
                warned[lic["name"]] = lic["expires"]
                add_event(conn, "firewall_licence", f"{name}: {lic['name']} " + (f"ended {-days} day(s) ago" if days < 0 else f"ends in {days} day(s)"), device_id=device_id, now=now)
        stored = {**fw, "warned": warned}
        conn.execute(
            "INSERT INTO firewall_state (device_id, plugin_id, data, updated) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET plugin_id = excluded.plugin_id, data = excluded.data, updated = excluded.updated",
            (device_id, plugin_id, json.dumps(stored), now),
        )
        count += 1
    conn.commit()
    return count
