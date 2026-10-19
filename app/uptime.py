import sqlite3
import ipaddress
from datetime import datetime, timedelta, timezone
from app import checkstats, tsdb
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
    samples: list[tuple] = []
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
        samples.append(("device", device_id, "up", up, "", "state"))
        if rtt_ms is not None:
            samples.append(("device", device_id, "rtt_ms", rtt_ms, "", "ms"))

    store = tsdb.for_conn(conn)
    if store is not None and samples:
        store.record(samples, ts=int(_parse_ts(now).timestamp()))

    cutoff = _cutoff(now, keep_days)
    conn.execute("DELETE FROM checks WHERE ts < ?", (cutoff,))
    checkstats.prune(conn, now)
    conn.commit()
    checkstats.fold(conn)                         # count the new checks into the hourly roll-up
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
    days: int | None = None,
) -> dict:
    """days=N: `checks` are `limit` slices of time over the last N days (with their response time) instead of the last `limit` checks."""
    if now is None:
        now = utcnow()

    up_24h = uptime_percent(conn, device_id, 1, now)
    up_7d = uptime_percent(conn, device_id, 7, now)
    up_30d = uptime_percent(conn, device_id, 30, now)
    checks = _bucket_rows(conn, now, days, limit, device_id).get(device_id, []) if days else recent_checks(conn, device_id, limit)

    # avg_rtt_ms over the chosen period (24 h by default)
    cutoff_24h = _cutoff(now, days or 1)
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
    days: int | None = None,
) -> list[dict]:
    """days=None: the last `bars` checks as 1/0 (the original form); days=N: `bars` slices of time with their time and response time."""
    if now is None:
        now = utcnow()

    cutoff_24h = _cutoff(now, 1)
    cutoff_7d = _cutoff(now, 7)

    # percentages over 24 hours, 7 and 30 days (from the hourly roll-up, see app/checkstats.py)
    def pct(u: int, n: int):
        return round(u / n * 100, 2) if n else None

    agg_24h = {d: pct(u, n) for d, (u, n, _a, _b) in checkstats.totals(conn, cutoff_24h).items()}
    agg_7d = {d: pct(u, n) for d, (u, n, _a, _b) in checkstats.totals(conn, cutoff_7d).items()}
    agg_30d = {d: pct(u, n) for d, (u, n, _a, _b) in checkstats.totals(conn, _cutoff(now, 30)).items()}

    # Window function query for bars
    bars_map: dict[int, list] = {}
    sliced = _bucket_rows(conn, now, days, bars) if days else None
    for row in [] if days else conn.execute(
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
        "SELECT id, primary_ip, online, custom_name, hostname, always_on FROM devices"
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
            "always_on": bool(row["always_on"]),
            "up_24h": agg_24h.get(device_id),
            "up_7d": agg_7d.get(device_id),
            "up_30d": agg_30d.get(device_id),
            "bars": sliced.get(device_id, []) if sliced is not None else bars_map.get(device_id, []),
            "last_ts": last_ts_map.get(device_id),
        })

    return result


# ---------- the bars and response-time line for a chosen period (24 h, 7 days, 30 days) ----------

RANGES = {"24h": 1, "7d": 7, "30d": 30}


def _bucket_rows(conn: sqlite3.Connection, now: str, days: int, bars: int, device_id: int | None = None) -> dict[int, list[dict]]:
    """Checks of the last `days` days grouped into `bars` equal slices of time, per device (oldest first). A slice that holds one check
    is exactly that measurement; a slice with several says how many there were and how many failed. A slice is down when any check in it failed."""
    end = _parse_ts(now)
    start = end - timedelta(days=days)
    size = days * 86400 / bars
    t0 = int(start.timestamp())
    sql = ("SELECT device_id, MIN(?, CAST((CAST(strftime('%s', ts) AS INTEGER) - ?) / ? AS INTEGER)) AS b, COUNT(*) AS n, SUM(up) AS ups, "
           "AVG(rtt_ms) AS rtt, MAX(rtt_ms) AS rtt_max, MIN(ts) AS first, MAX(ts) AS last FROM checks WHERE ts >= ? AND ts <= ?")
    args: list = [bars - 1, t0, size, _format_ts(start), now]
    if device_id is not None:
        sql += " AND device_id = ?"
        args.append(device_id)
    sql += " GROUP BY device_id, b ORDER BY device_id, b"
    out: dict[int, list[dict]] = {}
    for r in conn.execute(sql, args):
        down = r["n"] - (r["ups"] or 0)
        item = {"ts": r["first"], "up": down == 0, "rtt_ms": round(r["rtt"], 1) if r["rtt"] is not None else None}
        if r["n"] > 1:
            item.update(n=r["n"], down=down, end=r["last"], rtt_max=round(r["rtt_max"], 1) if r["rtt_max"] is not None else None)
        out.setdefault(r["device_id"], []).append(item)
    return out


def range_days(name: str | None) -> int | None:
    return RANGES.get(name) if name else None


# ---------- the always-on ("core") devices ----------

SUGGEST_TYPES = ("router", "switch", "ap", "server", "nas", "camera", "vm", "printer", "appliance")
SUGGEST_MIN_UPTIME = 99.0   # percent over 30 days
SUGGEST_MIN_CHECKS = 30


def core_choices(conn: sqlite3.Connection, now: str | None = None) -> list[dict]:
    """Every device with whether it is marked always-on, its 30-day uptime and whether Netlens suggests marking it: it has been up
    nearly all the time (so it is probably meant to be) and is the kind of device that runs all day."""
    now = now or utcnow()
    stats = {d: (u, n) for d, (u, n, _rs, _rn) in checkstats.totals(conn, _cutoff(now, 30)).items()}
    out = []
    for r in conn.execute("SELECT id, primary_ip, custom_name, hostname, always_on, COALESCE(type_override, device_type, 'unknown') AS type FROM devices"):
        u, n = stats.get(r["id"], (0, 0))
        pct = round(u / n * 100, 2) if n else None
        out.append({
            "id": r["id"], "name": r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}", "ip": r["primary_ip"], "type": r["type"],
            "always_on": bool(r["always_on"]), "up_30d": pct,
            "suggested": (not r["always_on"]) and r["type"] in SUGGEST_TYPES and n >= SUGGEST_MIN_CHECKS and pct is not None and pct >= SUGGEST_MIN_UPTIME,
        })
    out.sort(key=lambda d: d["name"].lower())
    return out


def set_core(conn: sqlite3.Connection, device_ids: list[int]) -> int:
    """Exactly these devices are always-on afterwards. Returns how many."""
    ids = sorted({int(i) for i in device_ids})
    conn.execute("UPDATE devices SET always_on = 0 WHERE always_on = 1")
    if ids:
        conn.execute(f"UPDATE devices SET always_on = 1 WHERE id IN ({','.join('?' * len(ids))})", ids)
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM devices WHERE always_on = 1").fetchone()[0]
