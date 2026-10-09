#!/usr/bin/env python3
"""Check a plugin before you publish it (run from a checkout of the Netlens repository; needs only Python 3.12).

    python plugin-index/tools/check_plugin.py path/to/my-plugin            # a folder or a .zip
    python plugin-index/tools/check_plugin.py my-plugin --output out.json  # also validate recorded output
    python plugin-index/tools/check_plugin.py my-plugin --config cfg.json  # also call test() and fetch() for real

It runs the same package, manifest and output checks Netlens runs when someone installs your plugin, and the same
static scan the plugin index uses. `--config` talks to your real device with the settings in the JSON file.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import registry  # noqa: E402
from app.plugins.contract import ContractError, clean_config, validate_output  # noqa: E402
from app.plugins.runner import PluginRunError, run_subprocess  # noqa: E402
from static_scan import blocking, scan_files  # noqa: E402


def zip_folder(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(folder.rglob("*")):
            rel = path.relative_to(folder)
            if path.is_file() and not any(part.startswith(".") or part in ("__pycache__", "tests") for part in rel.parts):
                z.write(path, rel.as_posix())
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("plugin", help="plugin folder or .zip file")
    parser.add_argument("--output", help="JSON file with an example of what fetch() returns; validated against the contract")
    parser.add_argument("--config", help="JSON file with settings; calls test() and fetch() against your real device")
    args = parser.parse_args()
    path = Path(args.plugin)
    data = path.read_bytes() if path.is_file() else zip_folder(path)
    failed = False

    def ok(text: str) -> None:
        print(f"  ok     {text}")

    def bad(text: str) -> None:
        nonlocal failed
        failed = True
        print(f"  FAIL   {text}")

    try:
        files, manifest = registry.read_zip(data)
    except registry.InstallError as exc:
        bad(f"package: {exc}")
        return 1
    ok(f"package: {manifest['name']} {manifest['version']} ({manifest['kind']}, plugin API {manifest['api_version']}, {len(files)} file(s))")
    flags = scan_files(files)
    for f in flags:
        print(f"  {f}")
    if blocking(flags):
        bad("static scan: blocking code found; the index CI will refuse this unless a reviewer allows it after reading it")
    else:
        ok(f"static scan: no blocking code ({len(flags)} note(s))")

    kind = manifest["kind"]
    if args.output:
        try:
            validate_output(kind, json.loads(Path(args.output).read_text()))
            ok(f"output file follows the {kind} contract")
        except (ContractError, ValueError) as exc:
            bad(f"output file: {exc}")
    if args.config:
        import tempfile

        config = clean_config(manifest, json.loads(Path(args.config).read_text()))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "plugins" / manifest["id"]
            for rel, content in files.items():
                (folder / rel).parent.mkdir(parents=True, exist_ok=True)
                (folder / rel).write_bytes(content)
            plugin = registry.discover(tmp)[manifest["id"]]
            for action in ("test", "fetch"):
                try:
                    result = run_subprocess(plugin, action, config)
                    if action == "fetch":
                        out = validate_output(kind, result)
                        ok(f"fetch() ran and follows the contract ({', '.join(f'{len(v)} {k}' for k, v in out.items())})")
                    else:
                        ok(f"test() ran: {(result or {}).get('message', 'ok')}")
                except PluginRunError as exc:
                    bad(f"{action}(): {exc}")
                except ContractError as exc:
                    bad(f"fetch() output does not follow the contract: {exc}")
    print("RESULT:", "problems found" if failed else "all checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
