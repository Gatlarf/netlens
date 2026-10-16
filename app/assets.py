"""Versioned, long-cached interface files.

`index.html` is rewritten when it is served: the scripts, style sheets and images point at `v/<version>/...` instead of `js/...`, so every
script the page imports (they import each other with relative paths) is also under that address. Those files are marked immutable and
cached for a year; a new Netlens version has a new address, so nothing stale is ever shown. The page itself is never cached for long (it
is revalidated with an ETag) and lists the scripts it needs up front (`modulepreload`), so the browser does not discover them one import at
a time. The version in the address is only a cache key: any version segment serves the current files, so a tab that was opened before an
update still finds its scripts. Relative addresses everywhere keep it working behind a reverse proxy under a sub-path.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from starlette.responses import Response
from starlette.staticfiles import StaticFiles

from app.version import VERSION

STATIC = Path(__file__).parent / "static"
IMPORT = re.compile(r"""(?:^|\n)\s*(?:import|export)\b[^;'"`]*?\bfrom\s*["'](\.{1,2}/[^"']+)["']|(?:^|\n)\s*import\s*["'](\.{1,2}/[^"']+)["']""")
REWRITE = re.compile(r'(\b(?:href|src)=")((?:css|js|img)/[^"]+)(")')
LANDING = ("js/app.js", "js/pages/dashboard.js")          # what the first screen needs: the shell and the dashboard page
IMMUTABLE = "public, max-age=31536000, immutable"


def cacheable() -> bool:
    """A version built from source (a `-dev` tag) changes without its number changing: never cache it for long."""
    return not VERSION.endswith("-dev")


def module_graph(roots=LANDING, base: Path = STATIC) -> list[str]:
    """The scripts that `roots` import (statically, through relative paths), as paths below the static folder, roots first."""
    seen: list[str] = []
    todo = list(roots)
    while todo:
        rel = todo.pop(0)
        if rel in seen or not (base / rel).is_file():
            continue
        seen.append(rel)
        text = (base / rel).read_text(encoding="utf-8", errors="replace")
        for m in IMPORT.finditer(text):
            target = (Path(rel).parent / (m.group(1) or m.group(2))).as_posix()
            parts: list[str] = []
            for part in target.split("/"):
                if part == "..":
                    if parts:
                        parts.pop()
                elif part not in ("", "."):
                    parts.append(part)
            todo.append("/".join(parts))
    return seen


_PAGES: dict[str, tuple[str, str]] = {}


def page(name: str = "index.html") -> tuple[str, str]:
    """(html, etag) of an interface page with versioned asset addresses and the module preload list."""
    if name in _PAGES and cacheable():
        return _PAGES[name]
    html = (STATIC / name).read_text(encoding="utf-8")
    if cacheable():
        prefix = f"v/{VERSION}/"
        html = REWRITE.sub(lambda m: f"{m.group(1)}{prefix}{m.group(2)}{m.group(3)}", html)
        preload = "".join(f'  <link rel="modulepreload" href="{prefix}{p}">\n' for p in module_graph())
        html = html.replace("</head>", preload + "</head>", 1)
    etag = '"' + hashlib.sha256(html.encode()).hexdigest()[:20] + '"'
    _PAGES[name] = (html, etag)
    return _PAGES[name]


def page_response(name: str, if_none_match: str | None) -> Response:
    html, etag = page(name)
    headers = {"ETag": etag, "Cache-Control": "no-cache"}
    if if_none_match and etag in [t.strip() for t in if_none_match.split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(html, media_type="text/html; charset=utf-8", headers=headers)


class VersionedStatic(StaticFiles):
    """Serves the static folder below `/v/<version>/`: the first path segment is only a cache key and is dropped."""

    def get_path(self, scope) -> str:
        path = super().get_path(scope)
        return path.split("/", 1)[1] if "/" in path else ""
