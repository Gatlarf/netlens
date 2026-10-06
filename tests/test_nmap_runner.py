import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from app.scanner.nmap_runner import build_args, run_nmap, ScanError


def _create_fake_script(
    tmp_path: Path,
    name: str,
    content: str,
) -> Path:
    """Create a fake executable script in tmp_path."""
    script_path = tmp_path / name
    script_path.write_text(content)
    script_path.chmod(0o755)
    return script_path


def _make_script_content(body: str) -> str:
    """Build script content with shebang using sys.executable."""
    return f"#!/usr/bin/env {sys.executable}\n{body}"


# ---------------------------------------------------------------------------
# build_args tests
# ---------------------------------------------------------------------------

def test_build_args_quick() -> None:
    targets = ["192.168.1.1", "192.168.1.2"]
    args = build_args(kind="quick", targets=targets, timing=3)
    expected = ["-T3", "--top-ports", "100", "-oX", "-", *targets]
    assert args == expected


def test_build_args_deep() -> None:
    targets = ["192.168.1.1"]
    args = build_args(kind="deep", targets=targets, timing=3)
    expected = [
        "-T3",
        "-sV",
        "-O",
        "--osscan-guess",
        "--top-ports",
        "1000",
        "-oX",
        "-",
        *targets,
    ]
    assert args == expected


def test_build_args_timing_changes_t_value() -> None:
    targets = ["192.168.1.1"]
    args = build_args(kind="quick", targets=targets, timing=5)
    assert args[0] == "-T5"
    assert args == ["-T5", "--top-ports", "100", "-oX", "-", *targets]


def test_build_args_invalid_kind_raises_value_error() -> None:
    with pytest.raises(ValueError):
        build_args(kind="invalid", targets=["192.168.1.1"], timing=3)


def test_build_args_timing_6_raises_value_error() -> None:
    with pytest.raises(ValueError):
        build_args(kind="quick", targets=["192.168.1.1"], timing=6)


def test_build_args_public_target_raises_value_error() -> None:
    with pytest.raises(ValueError):
        build_args(kind="quick", targets=["8.8.8.8"], timing=3)


def test_build_args_public_cidr_raises_value_error() -> None:
    with pytest.raises(ValueError):
        build_args(kind="quick", targets=["8.8.8.0/24"], timing=3)


def test_build_args_injection_attempt_raises_value_error() -> None:
    with pytest.raises(ValueError):
        build_args(kind="quick", targets=["192.168.1.0/24; rm -rf /"], timing=3)


def test_build_args_single_private_ip_accepted() -> None:
    targets = ["192.168.1.7"]
    args = build_args(kind="quick", targets=targets, timing=3)
    assert args == ["-T3", "--top-ports", "100", "-oX", "-", *targets]


def test_build_args_private_cidr_accepted() -> None:
    targets = ["10.0.0.0/20"]
    args = build_args(kind="quick", targets=targets, timing=3)
    assert args == ["-T3", "--top-ports", "100", "-oX", "-", *targets]


def test_build_args_private_cidr_8_rejected() -> None:
    with pytest.raises(ValueError):
        build_args(kind="quick", targets=["10.0.0.0/8"], timing=3)


# ---------------------------------------------------------------------------
# run_nmap tests
# ---------------------------------------------------------------------------

async def test_run_nmap_success(tmp_path: Path) -> None:
    """Fake script prints XML and exits 0."""
    script = _create_fake_script(
        tmp_path,
        "fake_nmap",
        _make_script_content("print('<nmaprun></nmaprun>')"),
    )
    result = await run_nmap("quick", ["192.168.1.1"], nmap_path=str(script))
    assert result.strip() == "<nmaprun></nmaprun>"


async def test_run_nmap_nonzero_exit_raises_scan_error(tmp_path: Path) -> None:
    """Fake script writes to stderr and exits 3."""
    script = _create_fake_script(
        tmp_path,
        "fake_nmap",
        _make_script_content("import sys\nsys.stderr.write('boom')\nsys.exit(3)"),
    )
    with pytest.raises(ScanError) as exc_info:
        await run_nmap("quick", ["192.168.1.1"], nmap_path=str(script))
    assert "boom" in str(exc_info.value)


async def test_run_nmap_timeout_raises_scan_error(tmp_path: Path) -> None:
    """Fake script sleeps 10 seconds; timeout=0.5 must raise ScanError mentioning timed out."""
    script = _create_fake_script(
        tmp_path,
        "fake_nmap",
        _make_script_content("import time\ntime.sleep(10)"),
    )
    with pytest.raises(ScanError) as exc_info:
        await run_nmap("quick", ["192.168.1.1"], nmap_path=str(script), timeout=0.5)
    assert "timed out" in str(exc_info.value).lower()


async def test_run_nmap_missing_path_raises_scan_error(tmp_path: Path) -> None:
    """Non-existent executable path raises ScanError mentioning not found."""
    missing_path = tmp_path / "does_not_exist"
    with pytest.raises(ScanError) as exc_info:
        await run_nmap("quick", ["192.168.1.1"], nmap_path=str(missing_path))
    assert "not found" in str(exc_info.value).lower()


async def test_run_nmap_checks_exact_args_passed(tmp_path: Path) -> None:
    """Fake script writes its own sys.argv[1:] as JSON to stdout."""
    script = _create_fake_script(
        tmp_path,
        "fake_nmap",
        _make_script_content(
            "import sys, json\nprint(json.dumps(sys.argv[1:]))"
        ),
    )
    targets = ["192.168.1.1"]
    expected_args = build_args(kind="quick", targets=targets, timing=3)
    result = await run_nmap("quick", targets, nmap_path=str(script))
    parsed = json.loads(result)
    assert parsed == expected_args