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

## app/auth.py
10:COOKIE_NAME = "netlens_session"
13:def session_value(token: str) -> str:
17:def is_authorized(token: str, cookie: Optional[str], authorization: Optional[str]) -> bool:
37:class LoginLimiter:
38:    def __init__(self, max_failures: int = 5, window: float = 60.0, clock=time.monotonic):
44:    def allowed(self, key: str) -> bool:
52:    def record_failure(self, key: str) -> None:
63:    def reset(self, key: str) -> None:
67:def require_auth(request: Request) -> None:

TASK:
Create tests/test_auth.py with pytest for app.auth (COOKIE_NAME, session_value, is_authorized, LoginLimiter, require_auth). Tests: session_value is deterministic, 64 hex chars, differs per token; is_authorized true with the right cookie, true with "Bearer secret", false with wrong cookie, wrong bearer, "Basic secret", None/None, and does not raise for non-ascii input; LoginLimiter with a fake clock (a list/mutable value): 5 failures block, 4 do not, failures expire after the window, reset clears, keys are independent; require_auth via a tiny FastAPI app built inside the test (app.state.settings = types.SimpleNamespace(token="secret"); route GET /p with dependencies=[Depends(require_auth)] returning {"ok": True}) and fastapi.testclient.TestClient(app, headers={"Authorization": "Bearer wrong"}): 401 with detail "authentication required" for wrong bearer, 200 with header "Bearer secret", 200 with cookie set via client.cookies.set(COOKIE_NAME, session_value("secret")). At least 14 tests.
