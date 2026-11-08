"""Alerts are sent from the background, and one failing hourly step does not skip the others."""
import asyncio

import pytest

from app import services
from app.notify import channels


@pytest.mark.asyncio
async def test_notify_soon_returns_at_once_runs_one_round_at_a_time_and_goes_round_again(monkeypatch):
    started, release, rounds = asyncio.Event(), asyncio.Event(), []

    async def slow(db_path, **kw):
        rounds.append(db_path)
        started.set()
        await release.wait()                        # a webhook that hangs
        return {}

    monkeypatch.setattr(channels, "process_channels", slow)
    channels.notify_soon("db")
    await asyncio.wait_for(started.wait(), 2)       # the caller was not held up: we are here while the send still hangs
    channels.notify_soon("db"); channels.notify_soon("db")                      # while it runs: only remembered (once)
    assert rounds == ["db"]
    release.set()
    await asyncio.wait_for(channels.settle(), 2)
    assert rounds == ["db", "db"]                   # one more round for everything that came meanwhile


@pytest.mark.asyncio
async def test_a_failing_round_is_logged_and_the_next_one_still_works(monkeypatch):
    calls = []

    async def boom(db_path, **kw):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("smtp down")

    monkeypatch.setattr(channels, "process_channels", boom)
    channels.notify_soon("db"); await channels.settle()
    channels.notify_soon("db"); await channels.settle()
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_one_failing_hourly_step_does_not_skip_the_rest(tmp_path, monkeypatch):
    from app import backup_schedule, netchecks, speedtest
    from app.db import connect, init_db

    db = str(tmp_path / "h.db")
    c = connect(db); init_db(c); c.close()
    ran = []

    def boom(*a, **k):
        raise RuntimeError("backup target gone")

    monkeypatch.setattr(backup_schedule, "run_if_due", boom)
    monkeypatch.setattr(netchecks, "dhcp_due", lambda conn: ran.append("dhcp") or False)
    monkeypatch.setattr(speedtest, "due", lambda conn: ran.append("speed") or False)
    await services._hourly(db)
    assert ran == ["dhcp", "speed"]                 # both came after the backup step that failed


def test_the_overview_bars_only_look_at_recent_checks(tmp_path):
    from app import uptime
    from app.db import connect, init_db

    c = connect(tmp_path / "u.db"); init_db(c)
    c.execute("INSERT INTO devices (id, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, '10.0.0.1', 'old', 1, 'x', 'x'), (2, '10.0.0.2', 'new', 1, 'x', 'x')")
    for i in range(5):
        c.execute("INSERT INTO checks (device_id, ts, up) VALUES (1, ?, 1)", (f"2026-10-01T10:0{i}:00Z",))      # a month ago
        c.execute("INSERT INTO checks (device_id, ts, up) VALUES (2, ?, ?)", (f"2026-11-01T11:0{i}:00Z", 1 if i != 2 else 0))
    c.commit()
    rows = {r["id"]: r for r in uptime.uptime_overview(c, now="2026-11-01T12:00:00Z")}
    assert rows[1]["bars"] == [] and rows[2]["bars"] == [1, 1, 0, 1, 1]
