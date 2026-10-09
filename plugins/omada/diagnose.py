#!/usr/bin/env python3
"""The same diagnostic as the "Run diagnostic" button in Netlens, for use from a terminal.

    python diagnose.py --url https://192.168.0.10:8043 --username viewer [--site Default]

It asks for the password (nothing is stored), logs in once like the plugin does and writes `omada-diagnostic.json`:
the controller version, which steps worked, and for the first few items the NAMES and TYPES of every field. Names, MAC
addresses, IP addresses and other text are replaced by placeholders. Read the file before you send it.
"""

import argparse
import getpass
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("omada_plugin", HERE / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--site", default="")
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--out", default="omada-diagnostic.json")
    args = parser.parse_args()
    config = {"url": args.url, "username": args.username, "password": getpass.getpass("Password: "), "site": args.site, "verify_tls": args.verify_tls}
    report = {"plugin_version": json.loads((HERE / "plugin.json").read_text())["version"]}
    try:
        report.update(plugin.diagnose(config))
    except Exception as exc:  # noqa: BLE001
        report["error"] = plugin._problem(exc)
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(f"Written {args.out}. Open it, check that it contains nothing private, and send it to whoever maintains the plugin.")


if __name__ == "__main__":
    main()
