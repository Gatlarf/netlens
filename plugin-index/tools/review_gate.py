#!/usr/bin/env python3
"""Only trusted reviewers (plugin-index/REVIEWERS) may change review records.

A pull request that touches plugin-index/reviews/ (or the REVIEWERS file) needs its author or an approving reviewer to
be listed in REVIEWERS. Used by the index workflow; CODEOWNERS adds the same rule on GitHub when branch protection is on.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import reviewers  # noqa: E402

PROTECTED_PREFIXES = ("plugin-index/reviews/", "plugin-index/REVIEWERS")


def check(changed: list[str], author: str, approvers: list[str], trusted: list[str]) -> list[str]:
    touched = [f for f in changed if f.startswith(PROTECTED_PREFIXES)]
    if not touched:
        return []
    trusted_set = {t.lower() for t in trusted}
    if author.lower() in trusted_set or any(a.lower() in trusted_set for a in approvers):
        return []
    return [f"{', '.join(touched)}: review records may only be changed by a trusted reviewer or with a trusted reviewer's approval (see plugin-index/REVIEWERS)"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--author", required=True)
    parser.add_argument("--approvers", default="", help="comma separated GitHub users who approved the pull request")
    parser.add_argument("--changed", required=True, help="file with one changed path per line")
    args = parser.parse_args()
    changed = [line.strip() for line in Path(args.changed).read_text().splitlines() if line.strip()]
    problems = check(changed, args.author, [a for a in args.approvers.split(",") if a], reviewers())
    for p in problems:
        print(f"ERROR {p}")
    print("review gate:", "FAILED" if problems else "ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
