Create app/auth.py (stdlib + FastAPI).
- COOKIE_NAME = "netlens_session".
- def session_value(token: str) -> str: hmac.new(token.encode(), b"netlens-session-v1", hashlib.sha256).hexdigest().
- def is_authorized(token: str, cookie: str | None, authorization: str | None) -> bool: True if cookie is not None and hmac.compare_digest(cookie, session_value(token)); or authorization starts with "Bearer " and hmac.compare_digest(the rest, token). Use compare_digest on equal-type str (encode to bytes first to avoid TypeError on non-ascii). Never raise.
- class LoginLimiter: __init__(self, max_failures: int = 5, window: float = 60.0, clock=time.monotonic); allowed(key: str) -> bool (False when there are >= max_failures failures recorded within the last `window` seconds); record_failure(key: str) -> None; reset(key: str) -> None. Old failures expire; memory per key bounded by max_failures entries.
- def require_auth(request: Request) -> None: FastAPI dependency. token = request.app.state.settings.token; if not is_authorized(token, request.cookies.get(COOKIE_NAME), request.headers.get("authorization")): raise HTTPException(status_code=401, detail="authentication required").
