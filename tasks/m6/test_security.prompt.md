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

## app/security.py
7:class SecurityHeadersMiddleware:
12:    def __init__(self, app: ASGIApp) -> None:
15:    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:

## app/main.py
24:VERSION = "0.1.0"
28:async def lifespan(app: FastAPI):
55:def create_app(
56:    settings: Any,
57:    db_path: str | os.PathLike | None = None,
59:    scheduler: bool = False,
60:    scan_manager: ScanManager | None = None,
86:    async def health() -> dict[str, str]:
96:def main() -> None:

TASK:
Create tests/test_security.py with pytest and fastapi.testclient.TestClient for app.security.SecurityHeadersMiddleware. Build a tiny FastAPI app inside the test file with two routes (GET /api/x returning {"ok": true}, GET /page returning PlainTextResponse("hi") with a custom Cache-Control "max-age=60" header on a third route GET /cached) and add the middleware with app.add_middleware(SecurityHeadersMiddleware). Tests: every response has X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy no-referrer, a Content-Security-Policy that contains "default-src 'self'" and "frame-ancestors 'none'", Permissions-Policy and Cross-Origin-Opener-Policy; /api/x gets Cache-Control no-store; /page gets none added; /cached keeps exactly its own "max-age=60" and no no-store; headers are not duplicated (a single value for X-Frame-Options); a websocket route (@app.websocket("/ws") that accepts, sends text "ok" and closes) still works through the middleware via client.websocket_connect. Also one integration test with the real app: app.main.create_app(app.config.load_settings({"NETLENS_TOKEN":"t"}), db_path=tmp_path/"t.db") started with `with TestClient(app) as c:` -> GET /api/health has the Content-Security-Policy header. At least 8 tests.
