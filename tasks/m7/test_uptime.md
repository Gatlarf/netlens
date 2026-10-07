
TASK: write tests/test_uptime.py (pytest, full file, under 150 lines, each test written once, no duplicated tests).

Module under test: app/uptime.py with these functions (all take an open connection `conn`):
- record_checks(conn, seen_ids: set[int], ranges: list[str], now=None, rtts: dict[int, float] | None = None, keep_days: int = 90) -> int  (rows inserted)
    inserts one row per device that is in seen_ids OR whose primary_ip lies inside one of `ranges`; up=1 if in seen_ids else 0; rtt_ms only stored when up; then deletes checks older than keep_days.
- uptime_percent(conn, device_id, days, now=None) -> float | None   (percent up among checks in the window, 2 decimals, None if no checks)
- recent_checks(conn, device_id, limit=60) -> list[dict]   ({"ts","up": bool,"rtt_ms"}, oldest first)
- device_uptime(conn, device_id, now=None, limit=60) -> dict with keys up_24h, up_7d, up_30d, checks, avg_rtt_ms, since, status_for_seconds
- uptime_overview(conn, bars=60, now=None) -> list[dict] with keys id, name, ip, online, up_24h, up_7d, bars, last_ts

Test setup: a pytest fixture `conn` that does `from app.db import connect, init_db, get_or_create_device`, c = connect(":memory:"); init_db(c); yield c. Create devices with get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10") (returns the id; use different MACs/IPs for each device). All timestamps are strings like "2026-03-10T12:00:00Z". Pass `now=` explicitly in every call so tests are deterministic. Use NOW = "2026-03-10T12:00:00Z".

Cases to cover (exactly these):
1. record_checks: devices A (192.168.1.10) and B (192.168.1.11) inside range ["192.168.1.0/24"], device C (10.9.9.9) outside the range. seen_ids={A}. Returns 2; A has up=1, B has up=0, C has no row.
2. record_checks with ranges=[] and seen_ids={A}: returns 1 (only A).
3. rtt: seen_ids={A, B}, rtts={A: 1.5} -> A.rtt_ms == 1.5, B.rtt_ms is None; and a down device keeps rtt_ms None even if present in rtts.
4. retention: insert a check for A at "2025-01-01T00:00:00Z" directly with SQL (INSERT INTO checks (device_id, ts, up) VALUES (?, ?, 1)), then record_checks(..., now=NOW, keep_days=90) removes it (SELECT COUNT(*) FROM checks WHERE ts < '2026-01-01' is 0).
5. uptime_percent: insert via SQL for A: 3 checks up and 1 down within the last day (ts "2026-03-10T10:00:00Z", "...10:15:00Z", "...10:30:00Z" up=1; "...10:45:00Z" up=0) -> uptime_percent(conn, A, 1, now=NOW) == 75.0; one more down check at "2026-03-01T00:00:00Z" is outside the 1 day window but inside 30 days: uptime_percent(conn, A, 30, now=NOW) == 60.0; a device with no checks returns None.
6. recent_checks: with 5 inserted checks and limit=3 returns the newest 3 in oldest-first order and `up` values are real bools.
7. device_uptime: checks for A at 11:00 up, 11:10 up, 11:20 down, 11:30 down, 11:40 down (all 2026-03-10Z, rtt_ms 2.0 on the two up checks, NULL on the others), now=NOW (12:00:00). Expect up_24h == 40.0, status_for_seconds == 2400 (status changed to down at 11:20, now is 12:00 -> 40 minutes), avg_rtt_ms == 2.0, since == "2026-03-10T11:00:00Z", len(checks) == 5. Device with no checks: up_24h is None, status_for_seconds is None, checks == [].
8. uptime_overview: two devices with custom names set via SQL UPDATE devices SET custom_name = 'Zebra' / 'Alpha'; checks for each; bars limited by bars=2 (only the last 2 checks, oldest first as ints 0/1); result ordered Alpha then Zebra; a third device without checks has bars == [] and last_ts is None; `online` is a bool.
