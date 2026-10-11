"""Is a newer image available for a container? Compares the digest a container's image was pulled with against the digest the
registry serves for the same tag today (a HEAD request on the manifest, the same thing Diun and Watchtower do).

Off unless the plugin's setting `check_image_updates` is on: it sends image names (not hostnames or addresses) to the
registries the containers come from. Results are cached for CACHE_HOURS, failures for ERROR_HOURS, so a sync (one per scan)
almost never leaves the machine. A registry that cannot be asked (private, needs a login, down) simply gives no verdict.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable

from app.db import get_setting, set_setting

CACHE_KEY = "imageupdates.cache"
CACHE_HOURS = 6
ERROR_HOURS = 1
MAX_LOOKUPS = 60          # per sync; the rest waits for the next one
TIMEOUT = 8
ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
))
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HUB_ALIASES = ("docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com")


def parse_ref(ref: str) -> tuple[str, str, str] | None:
    """'grafana/grafana:11' -> ('registry-1.docker.io', 'grafana/grafana', '11'). None for what cannot be checked
    (an image id, a reference pinned to a digest)."""
    ref = (ref or "").strip()
    if not ref or "@" in ref or ref.startswith("sha256:") or re.fullmatch(r"[0-9a-f]{12,64}", ref):
        return None
    parts = ref.split("/")
    registry = "docker.io"
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, parts = parts[0].lower(), parts[1:]
    last = parts[-1]
    tag = "latest"
    if ":" in last:
        last, tag = last.rsplit(":", 1)
        parts[-1] = last
    repo = "/".join(parts)
    if not repo or not tag or not re.fullmatch(r"[a-z0-9._/-]+", repo) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
        return None
    if registry in HUB_ALIASES:
        registry = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return registry, repo, tag


def _private_host(host: str) -> bool:
    name = host.rsplit(":", 1)[0] if not host.startswith("[") else host
    try:
        ip = ipaddress.ip_address(name.strip("[]"))
        return ip.is_private or ip.is_loopback
    except ValueError:
        return name == "localhost" or name.endswith(".local") or name.endswith(".lan") or name.endswith(".home.arpa")


def _open(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=TIMEOUT)


def _bearer(challenge: str, registry: str, repo: str) -> str | None:
    fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = fields.get("realm")
    if not realm:
        return None
    parsed = urllib.parse.urlsplit(realm)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and _private_host(parsed.netloc)):
        return None
    query = urllib.parse.urlencode({"service": fields.get("service", ""), "scope": fields.get("scope") or f"repository:{repo}:pull"})
    with _open(urllib.request.Request(f"{realm}{'&' if '?' in realm else '?'}{query}", headers={"User-Agent": "netlens"})) as response:
        body = json.loads(response.read(100_000) or b"{}")
    return body.get("token") or body.get("access_token")


def fetch_digest(registry: str, repo: str, tag: str) -> str:
    """The digest the registry serves for repo:tag right now. Raises OSError / ValueError when it cannot be found out."""
    schemes = ("https", "http") if _private_host(registry) else ("https",)
    last: Exception = OSError("no answer")
    for scheme in schemes:
        url = f"{scheme}://{registry}/v2/{repo}/manifests/{urllib.parse.quote(tag)}"
        headers = {"Accept": ACCEPT, "User-Agent": "netlens"}
        try:
            for attempt in (0, 1):
                try:
                    with _open(urllib.request.Request(url, headers=headers, method="HEAD")) as response:
                        digest = response.headers.get("Docker-Content-Digest") or ""
                    if not DIGEST_RE.match(digest):
                        raise ValueError("the registry did not report a digest")
                    return digest
                except urllib.error.HTTPError as exc:
                    challenge = exc.headers.get("WWW-Authenticate", "") if exc.headers else ""
                    if exc.code == 401 and attempt == 0 and challenge.lower().startswith("bearer"):
                        token = _bearer(challenge, registry, repo)
                        if token:
                            headers["Authorization"] = "Bearer " + token
                            continue
                    raise
        except urllib.error.HTTPError as exc:
            raise OSError(f"{registry} answered {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = exc
    raise OSError(str(last)[:200])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(conn) -> dict:
    try:
        data = json.loads(get_setting(conn, CACHE_KEY) or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _fresh(entry: dict, now: datetime) -> bool:
    try:
        then = datetime.strptime(entry["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError, TypeError):
        return False
    return now - then < timedelta(hours=CACHE_HOURS if entry.get("digest") else ERROR_HOURS)


def key_of(ref: str) -> str | None:
    parsed = parse_ref(ref)
    return None if parsed is None else f"{parsed[0]}/{parsed[1]}:{parsed[2]}"


def refresh(conn, refs: set[str], fetch: Callable[[str, str, str], str] | None = None, now: datetime | None = None) -> int:
    """Ask the registries about every image reference whose answer is missing or old. Returns how many were asked."""
    fetch = fetch or fetch_digest
    now = now or _now()
    cache = _load(conn)
    wanted = {}
    for ref in refs:
        parsed = parse_ref(ref)
        if parsed:
            wanted[f"{parsed[0]}/{parsed[1]}:{parsed[2]}"] = parsed
    todo = [k for k in sorted(wanted) if not _fresh(cache.get(k) or {}, now)][:MAX_LOOKUPS]

    def ask(key: str) -> tuple[str, dict]:
        try:
            return key, {"digest": fetch(*wanted[key]), "ts": _stamp(now)}
        except (OSError, ValueError) as exc:
            return key, {"digest": None, "error": str(exc)[:200], "ts": _stamp(now)}

    if todo:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for key, entry in pool.map(ask, todo):
                cache[key] = entry
    kept = {k: v for k, v in cache.items() if k in wanted or _fresh(v, now)}      # what no container uses any more is forgotten after a while
    if todo or kept != cache:
        set_setting(conn, CACHE_KEY, json.dumps(kept))
    return len(todo)


def annotate(conn, guests: list[dict]) -> int:
    """Mark the containers whose image is no longer what the registry serves for its tag. Only touches `details`. Returns how many."""
    cache = _load(conn)
    updates = 0
    for g in guests:
        d = g.get("details")
        if g.get("kind") != "container" or not isinstance(d, dict):
            continue
        key = key_of(d.get("image", ""))
        digest = d.get("image_digest")
        entry = cache.get(key) if key else None
        if not entry or not entry.get("digest") or not digest:
            continue
        d["image_checked"] = True
        if entry["digest"] != digest:
            d["update_available"] = True
            updates += 1
    return updates


def images_of(guests: list[dict]) -> set[str]:
    return {g["details"]["image"] for g in guests if g.get("kind") == "container" and isinstance(g.get("details"), dict) and g["details"].get("image") and g["details"].get("image_digest")}
