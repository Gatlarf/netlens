import asyncio

import pytest

from app.scanner.scheduler import scheduler_loop


class FakeManager:
    def __init__(self):
        self.started = []

    def is_running(self):
        return False

    async def start(self, kind):
        self.started.append(kind)


def _run(quick, deep, steps, step_seconds):
    """Run the loop on a fake clock; `steps` is a list of callables invoked before each tick."""
    manager = FakeManager()
    now = [0.0]
    tick = [0]

    async def fake_sleep(_):
        tick[0] += 1
        now[0] += step_seconds
        if tick[0] > len(steps):
            raise asyncio.CancelledError
        steps[tick[0] - 1]()

    async def go():
        try:
            await scheduler_loop(manager, quick, deep, poll=step_seconds, clock=lambda: now[0], sleep=fake_sleep)
        except asyncio.CancelledError:
            pass

    asyncio.run(go())
    return manager.started


def test_callable_intervals_are_re_read_every_cycle():
    box = {"quick": 10_000}
    # With a huge quick interval only the first scan runs; lowering it takes effect without restart.
    started = _run(lambda: box["quick"], lambda: 10**9, [lambda: None, lambda: box.update(quick=120), lambda: None, lambda: None], 100)
    assert started[0] == "quick"
    assert started.count("quick") >= 2


def test_plain_numbers_still_work():
    started = _run(150, 10**9, [lambda: None] * 6, 100)
    assert started.count("quick") >= 2
