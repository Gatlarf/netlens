"""The plugin index: a public list of plugins (with pinned release hashes and review levels) that Netlens can browse.

The index is a JSON file in the Netlens repository (plugin-index/index.json, generated from one small file per plugin).
It only *points at* plugins. Nothing is downloaded or run until the user presses Install, and every download is
checked against the SHA-256 the index pins, then goes through the same safety checks as a manual upload.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.db import get_setting, set_setting, utcnow
from app.plugins.contract import API_VERSION, ID_RE, VERSION_RE
from app.plugins.registry import MAX_ZIP_BYTES

OFFICIAL_URL = "https://raw.githubusercontent.com/Gatlarf/netlens/main/plugin-index/index.json"
SCHEMA = 1
MAX_INDEX_BYTES = 2 * 1024 * 1024
MAX_PLUGINS = 500
CACHE_TTL_SECONDS = 6 * 3600
LEVELS = ("verified", "reviewed", "community")  # best first
LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}
SETTINGS_KEY = "plugin_index.settings"
CACHE_KEY = "plugin_index.cache"
# the official index may only point at release assets on GitHub (a custom index may use any https host)
OFFICIAL_DOWNLOAD_HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class PluginIndexError(Exception):
    """The index could not be read or a download failed; the message is meant for the user."""


# ----------------------------------------------------------------------------- versions
def version_tuple(text: str | None) -> tuple[int, ...]:
    """'1.2.3' -> (1, 2, 3); '0.2.44' / '0.2.0-dev' / None are handled (unknown parts count as 0)."""
    if not text:
        return (0,)
    numbers = re.match(r"^\d+(\.\d+)*", str(text).strip())
    return tuple(int(p) for p in numbers.group(0).split(".")) if numbers else (0,)


def is_newer(candidate: str, current: str) -> bool:
    a, b = version_tuple(candidate), version_tuple(current)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


# ----------------------------------------------------------------------------- settings
def load_settings(conn) -> dict:
    default = {"enabled": True, "url": OFFICIAL_URL}
    try:
        data = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        return default
    if not isinstance(data, dict):
        return default
    url = data.get("url") if isinstance(data.get("url"), str) and data["url"].startswith("https://") else OFFICIAL_URL
    return {"enabled": bool(data.get("enabled", True)), "url": url}


def save_settings(conn, enabled: bool, url: str) -> dict:
    url = (url or OFFICIAL_URL).strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("the index address must start with https://")
    settings = {"enabled": bool(enabled), "url": url}
    set_setting(conn, SETTINGS_KEY, json.dumps(settings))
    return settings


# ----------------------------------------------------------------------------- parsing (never trust the file)
def _text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _release(raw: Any, official: bool) -> dict | None:
    if not isinstance(raw, dict):
        return None
    version, url, sha = raw.get("version"), raw.get("download_url"), raw.get("sha256")
    if not (isinstance(version, str) and VERSION_RE.match(version) and isinstance(sha, str) and SHA_RE.match(sha.lower()) and isinstance(url, str)):
        return None
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    if official and parsed.hostname not in OFFICIAL_DOWNLOAD_HOSTS:
        return None
    api = raw.get("api_version", API_VERSION)
    if isinstance(api, bool) or not isinstance(api, int):
        return None
    review = raw.get("review") if isinstance(raw.get("review"), dict) else {}
    level = review.get("level") if review.get("level") in LEVELS else "community"
    return {
        "version": version, "download_url": url, "sha256": sha.lower(), "api_version": api,
        "min_netlens": _text(raw.get("min_netlens"), 20), "released": _text(raw.get("released"), 20), "changelog": _text(raw.get("changelog"), 600),
        "review": {
            "level": level,
            "reviewer": _text(review.get("reviewer"), 60) if level != "community" else "",
            "date": _text(review.get("date"), 20),
            "tested_on": [_text(t, 100) for t in review.get("tested_on", []) if isinstance(t, str)][:10] if isinstance(review.get("tested_on"), list) else [],
            "notes": _text(review.get("notes"), 400),
        },
    }


def parse_index(data: Any, official: bool = False) -> tuple[list[dict], int]:
    """(valid plugin entries, number of entries that were skipped as invalid). Raises PluginIndexError if the file is not an index."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("plugins"), list):
        raise PluginIndexError("this is not a Netlens plugin index (wrong format or an index version this Netlens does not know)")
    entries, skipped, seen = [], 0, set()
    for raw in data["plugins"][:MAX_PLUGINS]:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not ID_RE.match(raw["id"]) or raw["id"] in seen:
            skipped += 1
            continue
        kind = raw.get("kind")
        if kind not in ("hypervisor", "topology") or not _text(raw.get("name"), 60):
            skipped += 1
            continue
        builtin = bool(raw.get("builtin"))
        releases = [r for r in (_release(x, official) for x in raw["releases"]) if r] if isinstance(raw.get("releases"), list) else []
        if not builtin and not releases:
            skipped += 1
            continue
        releases.sort(key=lambda r: version_tuple(r["version"]), reverse=True)
        seen.add(raw["id"])
        entries.append({
            "id": raw["id"], "name": _text(raw["name"], 60), "kind": kind, "description": _text(raw.get("description"), 500),
            "author": _text(raw.get("author"), 80), "license": _text(raw.get("license"), 40), "homepage": raw["homepage"] if isinstance(raw.get("homepage"), str) and raw["homepage"].startswith("https://") else "",
            "supports": [_text(s, 80) for s in raw.get("supports", []) if isinstance(s, str)][:30] if isinstance(raw.get("supports"), list) else [],
            "builtin": builtin, "releases": releases,
        })
    return entries, skipped


# ----------------------------------------------------------------------------- fetching
def http_get(url: str, *, max_bytes: int, headers: dict | None = None, timeout: float = 20.0) -> tuple[int, bytes, dict]:
    request = urllib.request.Request(url, headers={"User-Agent": "Netlens", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https only, checked by callers
            body = resp.read(max_bytes + 1)
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, b"", dict(exc.headers)
        raise PluginIndexError(f"the server answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PluginIndexError(f"cannot reach the server ({getattr(exc, 'reason', exc.__class__.__name__)})") from None


def load_cache(conn) -> dict | None:
    try:
        data = json.loads(get_setting(conn, CACHE_KEY) or "null")
    except ValueError:
        return None
    return data if isinstance(data, dict) and isinstance(data.get("index"), dict) else None


def get_index(conn, *, force: bool = False, getter=http_get, now: str | None = None, offline: bool = False) -> dict:
    """The index with its freshness: {"entries", "skipped", "url", "fetched", "stale", "error", "enabled"}.

    Uses the cache for six hours (or until `force`), asks the server only when needed, and falls back to the old copy
    (marked stale) when the server cannot be reached.
    """
    settings = load_settings(conn)
    result = {"enabled": settings["enabled"], "url": settings["url"], "entries": [], "skipped": 0, "fetched": None, "stale": False, "error": None}
    if not settings["enabled"]:
        return result
    official = settings["url"] == OFFICIAL_URL
    cache = load_cache(conn)
    if cache and cache.get("url") != settings["url"]:
        cache = None
    now = now or utcnow()
    if offline:  # only what is already known (the menu uses this so opening Settings never waits for the internet)
        if not cache:
            return result
        entries, skipped = parse_index(cache["index"], official)
        return {**result, "entries": entries, "skipped": skipped, "fetched": cache["fetched"]}
    if cache and not force:
        age = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - datetime.strptime(cache["fetched"], "%Y-%m-%dT%H:%M:%SZ")).total_seconds()
        if 0 <= age < CACHE_TTL_SECONDS:
            entries, skipped = parse_index(cache["index"], official)
            return {**result, "entries": entries, "skipped": skipped, "fetched": cache["fetched"]}
    headers = {"If-None-Match": cache["etag"]} if cache and cache.get("etag") else {}
    try:
        status, body, response_headers = getter(settings["url"], max_bytes=MAX_INDEX_BYTES, headers=headers)
        if status == 304 and cache:
            index_data, etag = cache["index"], cache.get("etag")
        else:
            if len(body) > MAX_INDEX_BYTES:
                raise PluginIndexError("the index file is too large")
            try:
                index_data = json.loads(body.decode("utf-8"))
            except ValueError:
                raise PluginIndexError("the index file is not valid JSON") from None
            etag = {k.lower(): v for k, v in response_headers.items()}.get("etag")
        entries, skipped = parse_index(index_data, official)
    except PluginIndexError as exc:
        if cache:  # keep working from the last copy
            try:
                entries, skipped = parse_index(cache["index"], official)
            except PluginIndexError:
                entries, skipped = [], 0
            return {**result, "entries": entries, "skipped": skipped, "fetched": cache["fetched"], "stale": True, "error": str(exc)}
        return {**result, "error": str(exc)}
    set_setting(conn, CACHE_KEY, json.dumps({"url": settings["url"], "fetched": now, "etag": etag, "index": index_data}))
    return {**result, "entries": entries, "skipped": skipped, "fetched": now}


# ----------------------------------------------------------------------------- compatibility, downloading
def incompatible_reason(release: dict, netlens_version: str) -> str | None:
    if release["api_version"] != API_VERSION:
        return f"needs plugin API version {release['api_version']} (this Netlens supports {API_VERSION})"
    if release["min_netlens"] and is_newer(release["min_netlens"], netlens_version) and version_tuple(netlens_version) != (0,):
        return f"needs Netlens {release['min_netlens']} or newer (you have {netlens_version})"
    return None


def pick_release(entry: dict, netlens_version: str, version: str | None = None) -> tuple[dict | None, str | None]:
    """(release, reason it cannot be used). Without `version`: the newest release this Netlens can run."""
    if version is not None:
        release = next((r for r in entry["releases"] if r["version"] == version), None)
        if release is None:
            return None, f"version {version} is not in the index"
        return (release, None) if not (reason := incompatible_reason(release, netlens_version)) else (None, reason)
    reasons = []
    for release in entry["releases"]:
        reason = incompatible_reason(release, netlens_version)
        if reason is None:
            return release, None
        reasons.append(reason)
    return None, reasons[0] if reasons else "no releases listed"


def download_release(release: dict, *, getter=http_get) -> bytes:
    """Download a release zip and verify it against the pinned SHA-256; raises PluginIndexError on any mismatch."""
    status, body, _ = getter(release["download_url"], max_bytes=MAX_ZIP_BYTES, timeout=60.0)
    if len(body) > MAX_ZIP_BYTES:
        raise PluginIndexError(f"the download is too large (max {MAX_ZIP_BYTES // 1024 // 1024} MB)")
    digest = hashlib.sha256(body).hexdigest()
    if digest != release["sha256"]:
        raise PluginIndexError("the downloaded file does not match the checksum in the index; nothing was installed")
    return body


# ----------------------------------------------------------------------------- what the UI shows
def view(entries: list[dict], installed: dict[str, dict], netlens_version: str) -> list[dict]:
    """Entries joined with what is installed. `installed[id]` = {"version", "builtin", "source", "level", "can_rollback"}."""
    out = []
    for e in entries:
        best, reason = pick_release(e, netlens_version)
        latest = e["releases"][0] if e["releases"] else None
        have = installed.get(e["id"])
        update = bool(have and not have["builtin"] and best and have.get("version") and is_newer(best["version"], have["version"]))
        out.append({
            **{k: e[k] for k in ("id", "name", "kind", "description", "author", "license", "homepage", "supports", "builtin")},
            "installed": have is not None,
            "installed_version": have["version"] if have else None,
            "installed_source": have["source"] if have else None,
            "installed_level": have.get("level") if have else None,
            "can_rollback": bool(have and have.get("can_rollback")),
            "update_available": update,
            "latest": best or latest,
            "incompatible": None if best else reason,
            "releases": [{"version": r["version"], "released": r["released"], "level": r["review"]["level"], "incompatible": incompatible_reason(r, netlens_version)} for r in e["releases"]],
        })
    out.sort(key=lambda x: (not x["update_available"], x["builtin"], x["name"].lower()))
    return out


def level_text(level: str) -> str:
    return {"verified": "Verified (code read and tested on real hardware)", "reviewed": "Reviewed (code read, not tested on hardware)", "community": "Community (automatic checks only)"}.get(level, level)
