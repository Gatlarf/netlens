#!/usr/bin/env python3
"""Build the release zip of a plugin in this folder: python plugins/build_zip.py <id>  (prints the SHA-256 for the index entry)."""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ("plugin.json", "plugin.py")


def main() -> int:
    if len(sys.argv) != 2 or not (HERE / sys.argv[1] / "plugin.json").exists():
        print(__doc__)
        return 2
    folder = HERE / sys.argv[1]
    version = json.loads((folder / "plugin.json").read_text())["version"]
    out = HERE / "dist" / f"{sys.argv[1]}-{version}.zip"
    out.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in FILES:
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 9, 0, 0, 0))  # fixed timestamp: the same input gives the same zip
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, (folder / name).read_bytes())
    print(out)
    print("sha256", hashlib.sha256(out.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
