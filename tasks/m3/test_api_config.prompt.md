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

## app/main.py
21:VERSION = "0.1.0"
25:async def lifespan(app: FastAPI):
52:def create_app(
53:    settings: Any,
54:    db_path: str | os.PathLike | None = None,
56:    scheduler: bool = False,
57:    scan_manager: ScanManager | None = None,
76:    async def health() -> dict[str, str]:
86:def main() -> None:

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

## app/api/auth.py
11:class LoginBody(BaseModel):
12:    token: str
19:async def login(request: Request, body: LoginBody) -> JSONResponse:
21:    limiter: LoginLimiter = request.app.state.login_limiter
49:async def logout(request: Request) -> JSONResponse:
56:async def session(request: Request) -> JSONResponse:

TASK:
Create tests/test_api_config.py (pytest + fastapi.testclient.TestClient) for the auth and config API. Build the app with: from app.config import load_settings; from app.main import create_app; settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"}); app = create_app(settings, db_path=tmp_path/"t.db"); use `with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:` (an explicit wrong default header; a conftest patches TestClient so that by default requests carry the correct header, which is why tests that need an unauthenticated client must pass their own Authorization header or remove it with client.headers.pop("Authorization", None)). Tests: GET /api/health is public (200 without credentials); GET /api/devices, /api/scans, /api/events, /api/config return 401 {"detail": "authentication required"} without credentials; with header "Bearer secret" they return 200; POST /api/login with the right token returns {"ok": true} and sets an HttpOnly cookie named netlens_session (inspect resp.headers["set-cookie"], contains "HttpOnly" and "SameSite=strict" case-insensitively), after which a cookie-only request (new client without Authorization header: client.headers.pop) to /api/devices returns 200; wrong token gives 401 {"detail":"invalid token"}; six wrong attempts give 429 on the sixth; a correct login after 5 failures is also 429 (blocked) ; GET /api/session reports authenticated false/true and never 401; POST /api/logout clears the cookie (set-cookie contains netlens_session= with Max-Age=0 or an expires in the past); GET /api/config (authenticated) returns ranges ["192.168.1.0/24"], quick_interval 900, deep_interval 86400, terminal_enabled true, snmp_enabled true, bind "0.0.0.0:8080", version, and the response text contains neither "secret" nor "public". At least 12 tests.
