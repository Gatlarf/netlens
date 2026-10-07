import sqlite3
import ipaddress
from datetime import datetime, timedelta, timezone
from app.db import utcnow


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cutoff(now: str, days: int) -> str:
    dt = _parse_ts(now)
    dt = dt - timedelta(days=days)
    return _format_ts(dt)


def record_checks(
    conn: sqlite3.Connection,
    seen_ids: set[int],
    ranges: list[str],
    now: str | None = None,
    rtts: dict[int, float] | None = None,
    keep_days: int = 90,
) -> int:
    if now is None:
        now = utcnow()

    rtts = rtts or {}
    networks = []
    for r in ranges:
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            pass

    devices = conn.execute("SELECT id, primary_ip FROM devices").fetchall()

    inserted = 0
    for row in devices:
        device_id = row["id"]
        primary_ip = row["primary_ip"]

        in_seen = device_id in seen_ids
        in_range = False
        if primary_ip:
            try:
                ip = ipaddress.ip_address(primary_ip)
                if ip.version == 4:
                    for net in networks:
                        if ip in net:
                            in_range = True
                            break
            except ValueError:
                pass

        if not in_seen and not in_range:
            continue

        up = 1 if in_seen else 0
        rtt_ms = rtts.get(device_id) if up else None

        conn.execute(
            "INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)",
            (device_id, now, up, rtt_ms),
        )
        inserted += 1

    cutoff = _cutoff(now, keep_days)
    conn.execute("DELETE FROM checks WHERE ts < ?", (cutoff,))
    conn.commit()
    return inserted


def uptime_percent(
    conn: sqlite3.Connection,
    device_id: int,
    days: int,
    now: str | None = None,
) -> float | None:
    if now is None:
        now = utcnow()
    cutoff = _cutoff(now, days)
    row = conn.execute(
        "SELECT SUM(up) AS total_up, COUNT(*) AS total FROM checks WHERE device_id = ? AND ts >= ?",
        (device_id, cutoff),
    ).fetchone()
    if row is None or row["total"] == 0:
        return None
    return round(row["total_up"] / row["total"] * 100, 2)


def recent_checks(
    conn: sqlite3.Connection,
    device_id: int,
    limit: int = 60,
) -> list[dict]:
    rows = conn.execute(
        "SELECT ts, up, rtt_ms FROM checks WHERE device_id = ? ORDER BY ts DESC, id DESC LIMIT ?",
        (device_id, limit),
    ).fetchall()
    result = []
    for row in reversed(rows):
        result.append({
            "ts": row["ts"],
            "up": bool(row["up"]),
            "rtt_ms": row["rtt_ms"],
        })
    return result


def device_uptime(
    conn: sqlite3.Connection,
    device_id: int,
    now: str | None = None,
    limit: int = 60,
) -> dict:
    if now is None:
        now = utcnow()

    up_24h = uptime_percent(conn, device_id, 1, now)
    up_7d = uptime_percent(conn, device_id, 7, now)
    up_30d = uptime_percent(conn, device_id, 30, now)
    checks = recent_checks(conn, device_id, limit)

    # avg_rtt_ms over last 24h
    cutoff_24h = _cutoff(now, 1)
    row = conn.execute(
        "SELECT AVG(rtt_ms) AS avg_rtt FROM checks WHERE device_id = ? AND ts >= ? AND rtt_ms IS NOT NULL",
        (device_id, cutoff_24h),
    ).fetchone()
    avg_rtt_ms = round(row["avg_rtt"], 1) if row and row["avg_rtt"] is not None else None

    # since: oldest check
    oldest = conn.execute(
        "SELECT ts FROM checks WHERE device_id = ? ORDER BY ts ASC, id ASC LIMIT 1",
        (device_id,),
    ).fetchone()
    since = oldest["ts"] if oldest else None

    # status_for_seconds
    status_for_seconds = None
    all_checks = conn.execute(
        "SELECT ts, up FROM checks WHERE device_id = ? ORDER BY ts ASC, id ASC",
        (device_id,),
    ).fetchall()
    if all_checks:
        latest = all_checks[-1]
        latest_up = latest["up"]
        # find most recent check whose up differs from latest.up
        diff_idx = None
        for i in range(len(all_checks) - 1, -1, -1):
            if all_checks[i]["up"] != latest_up:
                diff_idx = i
                break
        if diff_idx is not None:
            # the check right after that one
            next_check = all_checks[diff_idx + 1]
            status_for_seconds = int((_parse_ts(now) - _parse_ts(next_check["ts"])).total_seconds())
        else:
            # no check differs, seconds between now and oldest
            status_for_seconds = int((_parse_ts(now) - _parse_ts(all_checks[0]["ts"])).total_seconds())

    return {
        "up_24h": up_24h,
        "up_7d": up_7d,
        "up_30d": up_30d,
        "checks": checks,
        "avg_rtt_ms": avg_rtt_ms,
        "since": since,
        "status_for_seconds": status_for_seconds,
    }


def uptime_overview(
    conn: sqlite3.Connection,
    bars: int = 60,
    now: str | None = None,
) -> list[dict]:
    if now is None:
        now = utcnow()

    cutoff_24h = _cutoff(now, 1)
    cutoff_7d = _cutoff(now, 7)

    # Aggregate queries for 24h and 7d percentages
    agg_24h = {}
    for row in conn.execute(
        "SELECT device_id, SUM(up) AS total_up, COUNT(*) AS total FROM checks WHERE ts >= ? GROUP BY device_id",
        (cutoff_24h,),
    ).fetchall():
        agg_24h[row["device_id"]] = round(row["total_up"] / row["total"] * 100, 2) if row["total"] else None

    agg_7d = {}
    for row in conn.execute(
        "SELECT device_id, SUM(up) AS total_up, COUNT(*) AS total FROM checks WHERE ts >= ? GROUP BY device_id",
        (cutoff_7d,),
    ).fetchall():
        agg_7d[row["device_id"]] = round(row["total_up"] / row["total"] * 100, 2) if row["total"] else None

    # Window function query for bars
    bars_map: dict[int, list[int]] = {}
    for row in conn.execute(
        "SELECT device_id, up FROM ("
        "SELECT device_id, up, ts, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY ts DESC, id DESC) AS rn "
        "FROM checks"
        ") WHERE rn <= ? ORDER BY device_id, rn DESC",
        (bars,),
    ).fetchall():
        bars_map.setdefault(row["device_id"], []).append(int(row["up"]))

    # last_ts
    last_ts_map = {}
    for row in conn.execute(
        "SELECT device_id, MAX(ts) AS last_ts FROM checks GROUP BY device_id",
    ).fetchall():
        last_ts_map[row["device_id"]] = row["last_ts"]

    # Fetch devices
    devices = conn.execute(
        "SELECT id, primary_ip, online, custom_name, hostname FROM devices"
    ).fetchall()

    def display_name(row) -> str:
        if row["custom_name"]:
            return row["custom_name"]
        if row["hostname"]:
            return row["hostname"]
        if row["primary_ip"]:
            return row["primary_ip"]
        return f"device {row['id']}"

    devices_sorted = sorted(devices, key=lambda r: (display_name(r).lower(), r["id"]))

    result = []
    for row in devices_sorted:
        device_id = row["id"]
        result.append({
            "id": device_id,
            "name": display_name(row),
            "ip": row["primary_ip"],
            "online": bool(row["online"]),
            "up_24h": agg_24h.get(device_id),
            "up_7d": agg_7d.get(device_id),
            "bars": bars_map.get(device_id, []),
            "last_ts": last_ts_map.get(device_id),
        })

    return result