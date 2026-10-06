INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/scanner/scheduler.py
15:def due_kind(
16:    now: float,
17:    started_at: float,
18:    last_quick: Optional[float],
19:    last_deep: Optional[float],
20:    quick_interval: float,
21:    deep_interval: float,
50:async def scheduler_loop(
51:    manager: ScanManager,
52:    quick_interval: float,
53:    deep_interval: float,
55:    poll: float = 15.0,
56:    clock: callable = time.monotonic,
57:    sleep: callable = asyncio.sleep,
73:    last_quick: Optional[float] = None
74:    last_deep: Optional[float] = None

TASK:
Create tests/test_scheduler_loop.py (under 100 lines, each test written once) with pytest (asyncio_mode=auto) for app.scanner.scheduler.scheduler_loop(manager, quick_interval, deep_interval, *, poll=15.0, clock=time.monotonic, sleep=asyncio.sleep). Harness to write exactly like this:
class FakeManager: __init__(self, busy=False, error=None): self.kinds=[]; self.busy=busy; self.error=error. def is_running(self): return self.busy. async def start(self, kind): if self.error: raise self.error; self.kinds.append(kind); return 1.
def make_clock(max_sleeps): state={"t":0.0,"n":0}; def clock(): return state["t"]; async def sleep(d): state["n"]+=1; state["t"]+=d; if state["n"]>=max_sleeps: raise asyncio.CancelledError; return clock, sleep, state.
async def run(manager, max_sleeps, quick=60, deep=1000000, poll=15): clock, sleep, _ = make_clock(max_sleeps); with pytest.raises(asyncio.CancelledError): await scheduler_loop(manager, quick, deep, poll=poll, clock=clock, sleep=sleep).
Tests: (1) FakeManager(), run with max_sleeps=1 -> kinds == ["quick"]; (2) max_sleeps=3 with quick=60, poll=15 -> kinds == ["quick"] (45s elapsed); (3) max_sleeps=6 (75s elapsed) -> kinds == ["quick","quick"]; (4) FakeManager(busy=True) -> kinds == []; (5) FakeManager(error=ScanBusy("x")) (import ScanBusy from app.scanner.orchestrator) -> loop still reaches CancelledError and kinds == []; (6) FakeManager(error=RuntimeError("x")) -> same, loop survives.
