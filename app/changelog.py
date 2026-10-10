"""CHANGELOG.md as data, for the "What's new" popup and the changelog in Settings → About.

The file is the one source of truth. Format:

    ## 0.2.100 — 2026-10-10          a release: the build number (the version shown in the app) and, optionally, a date and a note
    ### Added                         sections (Added / Changed / Fixed / ...); the same name twice in one release is merged
    - ★ **Title**: what it does       one change; a leading ★ marks a notable one (those fill the popup)

A release covers every build from its number up to the next release heading.
"""

from __future__ import annotations

import re
from pathlib import Path

HEADING = re.compile(r"^##\s+(\d+(?:\.\d+){1,2})\b\s*(.*)$")
DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
ITEM = re.compile(r"^-\s+(★\s*)?(?:\*\*(.+?)\*\*[:.]?\s*)?(.*)$")
FILE = Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def version_key(text: str) -> tuple[int, int, int]:
    """'0.2.100' -> (0, 2, 100); anything unparsable (a dev build) -> (0, 0, 0)."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", str(text or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else (0, 0, 0)


def parse(text: str) -> list[dict]:
    releases: list[dict] = []
    release = section = item = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = HEADING.match(line)
        if m:
            rest = m.group(2).strip(" —-–")
            date = DATE.search(rest)
            note = re.sub(r"\s{2,}", " ", DATE.sub("", rest)).strip(" —-–()")
            release = {"version": m.group(1), "date": date.group(1) if date else None, "note": note or None, "sections": []}
            releases.append(release)
            section = item = None
        elif release is None:
            continue
        elif line.startswith("### "):
            title = line[4:].strip()
            section = next((s for s in release["sections"] if s["title"] == title), None)
            if section is None:
                section = {"title": title, "items": []}
                release["sections"].append(section)
            item = None
        elif line.startswith("- ") and section is not None:
            m = ITEM.match(line)
            item = {"title": (m.group(2) or "").strip(), "text": (m.group(3) or "").strip(), "notable": bool(m.group(1))}
            section["items"].append(item)
        elif line.strip() and item is not None and line.startswith("  "):
            item["text"] = (item["text"] + " " + line.strip()).strip()   # a wrapped continuation line
    for r in releases:
        r["sections"] = [s for s in r["sections"] if s["items"]]
    releases.sort(key=lambda r: version_key(r["version"]), reverse=True)
    return releases


def load(path: Path = FILE) -> list[dict]:
    try:
        return parse(path.read_text(encoding="utf-8"))
    except OSError:
        return []


def releases_between(releases: list[dict], since: str | None, current: str) -> list[dict]:
    """Releases newer than `since` and not newer than `current` (a dev build shows everything)."""
    low = version_key(since) if since else None
    dev = "dev" in str(current)
    high = version_key(current)
    return [r for r in releases
            if (low is None or version_key(r["version"]) > low) and (dev or version_key(r["version"]) <= high)]
