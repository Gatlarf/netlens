"""Every interface script must parse as an ES module. A duplicate `const` or a stray brace only shows up in the browser, as a blank page, so
check them all with Node when it is installed."""

import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "app" / "static" / "js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_every_script_parses_as_a_module(tmp_path):
    bad = []
    for script in sorted(STATIC.rglob("*.js")):
        copy = tmp_path / (script.name + ".mjs")
        copy.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
        result = subprocess.run(["node", "--check", str(copy)], capture_output=True, text=True)
        if result.returncode:
            bad.append(f"{script.relative_to(STATIC)}: {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'error'}")
    assert not bad, bad
