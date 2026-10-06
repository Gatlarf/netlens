import asyncio
import pytest
from app.scanner.scheduler import scheduler_loop
from app.scanner.orchestrator import ScanBusy


class FakeManager:
    def __init__(self, busy=False, error=None):
        self.kinds = []
        self.busy = busy
        self.error = error

    def is_running(self):
        return self.busy

    async def start(self, kind):
        if self.error:
            raise self.error
        self.kinds.append(kind)
        return 1


def make_clock(max_sleeps):
    state = {"t": 0.0, "n": 0}

    def clock():
        return state["t"]

    async def sleep(d):
        state["n"] += 1
        state["t"] += d
        if state["n"] >= max_sleeps:
            raise asyncio.CancelledError
        return

    return clock, sleep, state


async def run(manager, max_sleeps, quick=60, deep=1000000, poll=15):
    clock, sleep, _ = make_clock(max_sleeps)
    with pytest.raises(asyncio.CancelledError):
        await scheduler_loop(manager, quick, deep, poll=poll, clock=clock, sleep=sleep)


async def test_first_quick_scan():
    manager = FakeManager()
    await run(manager, max_sleeps=1)
    assert manager.kinds == ["quick"]


async def test_no_second_quick_before_interval():
    manager = FakeManager()
    await run(manager, max_sleeps=3, quick=60, poll=15)
    assert manager.kinds == ["quick"]


async def test_second_quick_after_interval():
    manager = FakeManager()
    await run(manager, max_sleeps=6, quick=60, poll=15)
    assert manager.kinds == ["quick", "quick"]


async def test_busy_manager_skips_scan():
    manager = FakeManager(busy=True)
    await run(manager, max_sleeps=1)
    assert manager.kinds == []


async def test_scan_busy_error_survives():
    manager = FakeManager(error=ScanBusy("x"))
    await run(manager, max_sleeps=1)
    assert manager.kinds == []


async def test_runtime_error_survives():
    manager = FakeManager(error=RuntimeError("x"))
    await run(manager, max_sleeps=1)
    assert manager.kinds == []