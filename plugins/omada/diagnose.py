#!/usr/bin/env python3
"""Collect an anonymised description of what YOUR Omada controller answers, to help fix the plugin.

    python diagnose.py --url https://192.168.0.10:8043 --username viewer [--site Default]

It asks for the password (nothing is stored), logs in once like the plugin does, reads the same pages and writes
`omada-diagnostic.json`: the controller version, how many items each page returned, and for the first few items the
NAMES and TYPES of every field. Names, MAC addresses, IP addresses and all other text are replaced by placeholders
(only a few harmless words such as device type and radio band are kept). Read the file before you send it.
"""

import argparse
import getpass
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("omada_plugin", HERE / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

KEEP_WORDS = {"type", "status", "statusCategory", "connectDevType", "connectType", "radioId", "wireless", "active", "wifiMode", "controllerVer"}
SAMPLES = 3


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac " + ("dashes" if "-" in value else "colons") + (", UPPER" if value.upper() == value and re.search("[A-F]", value) else "") + ">"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--site", default="")
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--out", default="omada-diagnostic.json")
    args = parser.parse_args()
    config = {"url": args.url, "username": args.username, "password": getpass.getpass("Password: "), "site": args.site, "verify_tls": args.verify_tls}
    report = {"plugin_version": json.loads((HERE / "plugin.json").read_text())["version"], "steps": {}}
    controller = plugin.Controller(config)

    def step(name, call):
        try:
            report["steps"][name] = {"ok": True, "shape": call()}
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]}

    try:
        controller.login()
        report["controller_version"] = controller.version
        sites = controller.sites()
        report["site_count"] = len(sites)
        site = sites[0]
        step("devices", lambda: (lambda rows: {"count": len(rows), "first": [describe(r) for r in rows[:SAMPLES]]})(controller._api(f"sites/{site['key']}/devices")))
        devices = controller._api(f"sites/{site['key']}/devices") or []
        for kind, path in (("switch", "switches"), ("ap", "eaps")):
            first = next((d for d in devices if d.get("type") == kind), None)
            if first:
                step(f"{kind}_detail", lambda first=first, path=path: describe(controller._api(f"sites/{site['key']}/{path}/{first['mac']}")))
        step("clients", lambda: (lambda rows: {"count": len(rows), "first": [describe(r) for r in rows[:SAMPLES]]})(list(controller.paged(f"sites/{site['key']}/clients"))))
        nodes, clients = controller.snapshot()
        out = plugin.to_topology(nodes, clients)
        report["result"] = {
            "nodes": len(out["nodes"]), "nodes_with_parent": sum(1 for n in out["nodes"] if n["parent_mac"]),
            "roles": sorted({n["role"] for n in out["nodes"]}),
            "clients": len(out["clients"]), "clients_with_node": sum(1 for c in out["clients"] if c["node_mac"]),
            "wifi_clients": sum(1 for c in out["clients"] if c["medium"] == "wifi"), "with_rssi": sum(1 for c in out["clients"] if c["rssi"] is not None),
            "with_rates": sum(1 for c in out["clients"] if c["tx_mbps"] is not None),
        }
    except Exception as exc:  # noqa: BLE001
        report["error"] = type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]
    finally:
        if controller.csrf:
            controller.logout()
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(f"Written {args.out}. Open it, check that it contains nothing private, and send it to whoever maintains the plugin.")


if __name__ == "__main__":
    main()
