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
Create app/api/auth.py (FastAPI). Uses app.auth: COOKIE_NAME, session_value, is_authorized, LoginLimiter (methods allowed(key), record_failure(key), reset(key)). State on the app: request.app.state.settings.token (str) and request.app.state.login_limiter (a LoginLimiter).
router = APIRouter(prefix="/api", tags=["auth"]).
- POST /login with pydantic body {"token": str}: key = request.client.host if request.client else "unknown"; if not limiter.allowed(key) -> HTTPException 429 detail "too many attempts"; if hmac.compare_digest(body.token.encode(), settings.token.encode()) is False -> limiter.record_failure(key) and HTTPException 401 detail "invalid token"; on success limiter.reset(key) and return JSONResponse({"ok": True}) with response.set_cookie(COOKIE_NAME, session_value(settings.token), httponly=True, samesite="strict", path="/", max_age=30*24*3600).
- POST /logout: JSONResponse({"ok": True}) with delete_cookie(COOKIE_NAME, path="/").
- GET /session: {"authenticated": bool} using is_authorized(settings.token, request.cookies.get(COOKIE_NAME), request.headers.get("authorization")). Never 401.
