#!/usr/bin/env python3
"""A released version must never change: its download URL and checksum are pinned once published.

Compares the entries in the working tree with those of a base git ref (the target branch of a pull request).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import INDEX_DIR, ROOT, entry_files, load_json  # noqa: E402


def releases_by_version(entry: dict) -> dict[str, dict]:
    return {r.get("version"): r for r in entry.get("releases", []) if isinstance(r, dict)}


def compare(old: dict, new: dict) -> list[str]:
    """Problems between the old and the new entry of one plugin."""
    problems = []
    before, after = releases_by_version(old), releases_by_version(new)
    for version, rel in before.items():
        if version not in after:
            problems.append(f"{old['id']} {version}: a published release was removed (add `yanked` in its changelog instead)")
            continue
        for key in ("download_url", "sha256"):
            if str(rel.get(key, "")).lower() != str(after[version].get(key, "")).lower():
                problems.append(f"{old['id']} {version}: {key} changed; a published version is immutable, publish a new version instead")
    if old.get("id") != new.get("id"):
        problems.append("the id of a plugin cannot change")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="git ref to compare with, e.g. origin/main")
    args = parser.parse_args()
    problems = []
    for path in entry_files():
        rel = path.relative_to(ROOT).as_posix()
        shown = subprocess.run(["git", "show", f"{args.base}:{rel}"], cwd=ROOT, capture_output=True, text=True)
        if shown.returncode != 0:
            continue  # a new plugin
        try:
            problems += compare(json.loads(shown.stdout), load_json(path))
        except ValueError:
            problems.append(f"{path.name}: not valid JSON")
    for p in problems:
        print(f"ERROR {p}")
    print("immutability check:", "FAILED" if problems else "ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
