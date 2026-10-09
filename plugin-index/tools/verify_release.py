#!/usr/bin/env python3
"""Download the releases listed in the index and check them: checksum, package rules, manifest and risky code.

For every release: the download matches its sha256; the zip passes Netlens' own upload checks; plugin.json says the
same id, version, kind and API version as the index; and the static scan finds no blocking code (unless a trusted
reviewer allowed that rule for exactly this version in plugins' reviews file).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import INDEX_DIR, entry_files, load_json, netlens_index, registry, review_files  # noqa: E402
from static_scan import blocking, scan_files  # noqa: E402


def verify_release(entry: dict, release: dict, allowed: list[str], getter=netlens_index.http_get) -> tuple[list[str], list[str]]:
    """(errors, report lines) for one release."""
    label = f"{entry['id']} {release['version']}"
    errors, report = [], []
    parsed = netlens_index.parse_index({"schema": 1, "plugins": [{**entry, "releases": [release]}]}, official=True)[0]
    if not parsed:
        return [f"{label}: the entry is not valid for the official index (GitHub https URL, sha256, version...)"], report
    try:
        data = netlens_index.download_release(parsed[0]["releases"][0], getter=getter)
    except netlens_index.PluginIndexError as exc:
        return [f"{label}: {exc}"], report
    try:
        files, manifest = registry.read_zip(data)
    except registry.InstallError as exc:
        return [f"{label}: the package is not installable: {exc}"], report
    for key, expected in (("id", entry["id"]), ("version", release["version"]), ("kind", entry["kind"]), ("api_version", release.get("api_version", 1))):
        if manifest[key] != expected:
            errors.append(f"{label}: plugin.json says {key} {manifest[key]!r} but the index says {expected!r}")
    flags = scan_files(files)
    for f in flags:
        report.append(f"{label}: {f}")
    for f in blocking(flags, allowed):
        errors.append(f"{label}: blocking code ({f.rule}) at {f.file}:{f.line}; a trusted reviewer must allow it in the review (allow_flags) after reading it")
    return errors, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", help="plugin ids to verify (default: all)")
    args = parser.parse_args()
    reviews = review_files()
    errors, report, count = [], [], 0
    for path in entry_files():
        entry = load_json(path)
        if args.only and entry["id"] not in args.only:
            continue
        for release in entry.get("releases", []):
            review = next((r for r in reviews.get(entry["id"], {}).get("reviews", []) if r.get("version") == release.get("version") and str(r.get("sha256", "")).lower() == str(release.get("sha256", "")).lower()), {})
            e, r = verify_release(entry, release, review.get("allow_flags", []))
            errors += e
            report += r
            count += 1
    print("\n".join(report))
    for e in errors:
        print(f"ERROR {e}")
    print(f"verified {count} release(s): {'FAILED' if errors else 'ok'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
