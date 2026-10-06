import hmac
import hashlib
import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request


COOKIE_NAME = "netlens_session"


def session_value(token: str) -> str:
    return hmac.new(token.encode(), b"netlens-session-v1", hashlib.sha256).hexdigest()


def is_authorized(token: str, cookie: Optional[str], authorization: Optional[str]) -> bool:
    if cookie is not None:
        try:
            if hmac.compare_digest(cookie.encode(), session_value(token).encode()):
                return True
        except Exception:
            pass

    if authorization is not None:
        try:
            if authorization.startswith("Bearer "):
                rest = authorization[7:]
                if hmac.compare_digest(rest.encode(), token.encode()):
                    return True
        except Exception:
            pass

    return False


class LoginLimiter:
    def __init__(self, max_failures: int = 5, window: float = 60.0, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.clock = clock
        self._failures: dict[str, list[float]] = defaultdict(list)

    def allowed(self, key: str) -> bool:
        now = self.clock()
        cutoff = now - self.window
        failures = self._failures[key]
        # Remove expired entries
        self._failures[key] = [t for t in failures if t > cutoff]
        return len(self._failures[key]) < self.max_failures

    def record_failure(self, key: str) -> None:
        now = self.clock()
        cutoff = now - self.window
        failures = self._failures[key]
        # Remove expired entries
        self._failures[key] = [t for t in failures if t > cutoff]
        # Bound memory by max_failures entries
        if len(self._failures[key]) >= self.max_failures:
            self._failures[key] = self._failures[key][-self.max_failures:]
        self._failures[key].append(now)

    def reset(self, key: str) -> None:
        self._failures[key] = []


def require_auth(request: Request) -> None:
    token = request.app.state.settings.token
    if not is_authorized(token, request.cookies.get(COOKIE_NAME), request.headers.get("authorization")):
        raise HTTPException(status_code=401, detail="authentication required")