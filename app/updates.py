"""Is a newer Netlens available? Looks at the version tags of the published container image (once a day).

Nothing is installed automatically: Netlens only shows that an update exists and how to apply it. Turning the check off
in Settings -> About stops all requests.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from app.db import get_setting, set_setting, utcnow
from app.plugins.index import PluginIndexError, http_get, is_newer, version_tuple
from app.version import VERSION

IMAGE = "gatlarf/netlens"
TOKEN_URL = f"https://ghcr.io/token?scope=repository:{IMAGE}:pull&service=ghcr.io"
TAGS_URL = f"https://ghcr.io/v2/{IMAGE}/tags/list?n=1000"
CHANGELOG_URL = "https://github.com/Gatlarf/netlens/blob/main/CHANGELOG.md"
HOW_TO_URL = "https://github.com/Gatlarf/netlens#updating-to-a-new-version"
SETTINGS_KEY = "update_check.settings"
CACHE_KEY = "update_check.cache"
TTL_SECONDS = 24 * 3600
VERSION_TAG = re.compile(r"^\d+\.\d+\.\d+$")


def enabled(conn) -> bool:
    try:
        return bool(json.loads(get_setting(conn, SETTINGS_KEY) or "{}").get("enabled", True))
    except ValueError:
        return True


def set_enabled(conn, value: bool) -> None:
    set_setting(conn, SETTINGS_KEY, json.dumps({"enabled": bool(value)}))


def _cache(conn) -> dict | None:
    try:
        data = json.loads(get_setting(conn, CACHE_KEY) or "null")
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("latest") else None


def fetch_latest(getter=http_get) -> str:
    """The highest x.y.z tag of the published image. Raises PluginIndexError when the registry cannot be asked."""
    status, body, _ = getter(TOKEN_URL, max_bytes=20000, timeout=15.0)
    try:
        token = json.loads(body.decode("utf-8"))["token"]
        status, body, _ = getter(TAGS_URL, max_bytes=500000, headers={"Authorization": f"Bearer {token}"}, timeout=15.0)
        tags = json.loads(body.decode("utf-8"))["tags"]
    except (ValueError, KeyError, TypeError):
        raise PluginIndexError("the image registry answered something unexpected") from None
    versions = [t for t in tags if isinstance(t, str) and VERSION_TAG.match(t)]
    if not versions:
        raise PluginIndexError("no version tags found")
    return max(versions, key=version_tuple)


def status(conn, current: str = VERSION) -> dict:
    """What is known right now (never touches the network)."""
    cache = _cache(conn)
    latest = cache["latest"] if cache else None
    return {
        "enabled": enabled(conn), "current": current, "latest": latest, "checked": cache.get("checked") if cache else None,
        "available": bool(latest and enabled(conn) and is_newer(latest, current)),
        "changelog_url": CHANGELOG_URL, "how_to_url": HOW_TO_URL, "error": None,
    }


def check(conn, *, force: bool = False, getter=http_get, now: str | None = None, current: str = VERSION) -> dict:
    """Ask the registry when the cached answer is older than a day (or `force`); a failure keeps the last known answer."""
    result = status(conn, current)
    if not result["enabled"]:
        return result
    now = now or utcnow()
    cache = _cache(conn)
    if cache and not force and cache.get("checked"):
        age = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - datetime.strptime(cache["checked"], "%Y-%m-%dT%H:%M:%SZ")).total_seconds()
        if 0 <= age < TTL_SECONDS:
            return result
    try:
        latest = fetch_latest(getter)
    except PluginIndexError as exc:
        return {**result, "error": str(exc)}
    set_setting(conn, CACHE_KEY, json.dumps({"latest": latest, "checked": now}))
    return status(conn, current)
