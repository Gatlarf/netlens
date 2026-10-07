import asyncio

import pytest

from app.scanner.errors import explain_scan_error
from app.scanner.nmap_runner import ScanError, run_nmap


@pytest.mark.parametrize(
    "raw, expect",
    [
        ("[Errno 1] Operation not permitted", "NET_RAW"),
        (PermissionError(13, "Permission denied"), "NET_RAW"),
        ("nmap exited with code 1: You requested a scan type which requires root privileges.", "NET_RAW"),
        ("nmap not found", "not installed"),
        ("nmap timed out", "smaller range"),
        ("no scan ranges found", "Settings"),
        ("interrupted by restart", "restarted"),
    ],
)
def test_known_errors_are_explained(raw, expect):
    assert expect in explain_scan_error(raw)


def test_original_text_kept_as_detail():
    msg = explain_scan_error("[Errno 1] Operation not permitted")
    assert "detail: [Errno 1] Operation not permitted" in msg


def test_unknown_error_passes_through():
    assert explain_scan_error(RuntimeError("weird failure 42")) == "weird failure 42"
    assert explain_scan_error("") == "The scan failed for an unknown reason."


def test_run_nmap_non_executable_becomes_scanerror(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\n")  # not executable -> PermissionError
    with pytest.raises(ScanError) as ei:
        asyncio.run(run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake)))
    assert "cannot execute nmap" in str(ei.value)
    assert "NET_RAW" in explain_scan_error(ei.value)
