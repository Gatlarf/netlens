#!/usr/bin/env python3
"""Merge plugin-index/plugins/*.json with plugin-index/reviews/*.json into plugin-index/index.json.

A review only counts for the exact version AND checksum it names, so changing a release after review makes it
Community again. Run without arguments to (re)write index.json, or with --validate to only check the sources.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import INDEX_DIR, ROOT, entry_files, load_json, netlens_index, review_files  # noqa: E402


def merge(index_dir: Path = INDEX_DIR) -> tuple[dict, list[str]]:
    """(index document, list of problems). The document is only meaningful when there are no problems."""
    problems: list[str] = []
    reviews = review_files(index_dir)
    plugins = []
    seen = set()
    for path in entry_files(index_dir):
        try:
            raw = load_json(path)
        except ValueError as exc:
            problems.append(f"{path.name}: not valid JSON ({exc})")
            continue
        if raw.get("id") != path.stem:
            problems.append(f"{path.name}: the id {raw.get('id')!r} must equal the file name")
            continue
        if raw["id"] in seen:
            problems.append(f"{path.name}: duplicate id")
        seen.add(raw["id"])
        review_list = reviews.get(raw["id"], {}).get("reviews", [])
        for release in raw.get("releases", []):
            match = next((r for r in review_list if r.get("version") == release.get("version") and str(r.get("sha256", "")).lower() == str(release.get("sha256", "")).lower()), None)
            release.pop("review", None)  # authors cannot grant themselves a level
            release["review"] = (
                {k: match[k] for k in ("level", "reviewer", "date", "tested_on", "notes") if k in match}
                if match and match.get("level") in netlens_index.LEVELS else {"level": "community"}
            )
        entries, skipped = netlens_index.parse_index({"schema": netlens_index.SCHEMA, "plugins": [raw]}, official=True)
        if skipped or not entries:
            problems.append(f"{path.name}: the entry is not valid (id, name, kind, https GitHub release URL, 64-hex sha256, version, api_version)")
            continue
        plugins.append(raw)
    for review_id in reviews:
        if review_id not in seen:
            problems.append(f"reviews/{review_id}.json: there is no plugin with this id")
    plugins.sort(key=lambda p: p["id"])
    return {"schema": netlens_index.SCHEMA, "plugins": plugins}, problems


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true", help="only check the source files")
    parser.add_argument("--check", action="store_true", help="fail when index.json is not up to date")
    args = parser.parse_args()
    doc, problems = merge()
    for p in problems:
        print(f"ERROR {p}")
    if problems:
        return 1
    target = INDEX_DIR / "index.json"
    text = render(doc)
    if args.validate:
        print(f"{len(doc['plugins'])} plugin entries are valid")
        return 0
    if args.check:
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            print("ERROR plugin-index/index.json is out of date: run python plugin-index/tools/build_index.py")
            return 1
        print("index.json is up to date")
        return 0
    target.write_text(text, encoding="utf-8")
    print(f"wrote {target.relative_to(ROOT)} with {len(doc['plugins'])} plugins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
