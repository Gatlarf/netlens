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

## app/api/auth.py
11:class LoginBody(BaseModel):
12:    token: str
18:def _is_https(request: Request) -> bool:
27:async def login(request: Request, body: LoginBody) -> JSONResponse:
29:    limiter: LoginLimiter = request.app.state.login_limiter
58:async def logout(request: Request) -> JSONResponse:
65:async def session(request: Request) -> JSONResponse:

## app/main.py
25:VERSION = "0.1.0"
29:async def lifespan(app: FastAPI):
56:def create_app(
57:    settings: Any,
58:    db_path: str | os.PathLike | None = None,
60:    scheduler: bool = False,
61:    scan_manager: ScanManager | None = None,
89:    async def health() -> dict[str, str]:
99:def main() -> None:

TASK:
Create tests/test_auth_cookie_secure.py with pytest and fastapi.testclient.TestClient. Build the app like this: from app.config import load_settings; from app.main import create_app; app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path/"t.db"); use `with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:`. Tests: POST /api/login {"token":"secret"} over plain http gives a Set-Cookie header WITHOUT the "secure" attribute (compare lowercase; note "samesite=strict" and "httponly" must be present); with header X-Forwarded-Proto: https the Set-Cookie contains "secure"; with "X-Forwarded-Proto: https, http" (first value wins) it contains "secure"; with "X-Forwarded-Proto: http" it does not; a client created with base_url="https://testserver" gets a cookie with "secure"; POST /api/logout with X-Forwarded-Proto https returns a Set-Cookie that deletes netlens_session and contains "secure". At least 6 tests.
