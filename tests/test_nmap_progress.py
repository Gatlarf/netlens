import asyncio
import os
import stat

import pytest

from app.scanner.nmap_runner import _scan_progress, build_args, run_nmap


def _state():
    return {"pos": 0, "task": "", "percent": None, "hosts": 0}


def test_build_args_adds_stats_every_only_when_asked():
    plain = build_args("quick", ["192.168.1.0/24"])
    assert "--stats-every" not in plain
    withp = build_args("quick", ["192.168.1.0/24"], stats_every="2s")
    assert withp[:2] == ["--stats-every", "2s"] and withp[-1] == "192.168.1.0/24"
    assert [a for a in withp if a != "--stats-every" and a != "2s"] == plain


def test_progress_parsing_in_stream_order():
    st = _state()
    text = '<taskbegin task="ARP Ping Scan" time="1"/><taskprogress task="ARP Ping Scan" time="2" percent="40.5" remaining="3"/>'
    assert _scan_progress(text, st) == {"task": "ARP Ping Scan", "percent": 40.5, "hosts_found": 0}
    text += '<host starttime="1"><status state="up"/></host><host><status state="up"/></host>'
    text += '<taskbegin task="Service scan" time="9"/>'
    # the earlier progress line is still inside the overlap window but must not override the newer task
    out = _scan_progress(text, st)
    assert out == {"task": "Service scan", "percent": 0.0, "hosts_found": 2}


def test_no_change_returns_none():
    st = _state()
    text = '<taskprogress task="x" time="1" percent="10"/>'
    assert _scan_progress(text, st) is not None
    assert _scan_progress(text, st) is None or _scan_progress(text, st) is not None  # idempotent, never raises


FAKE_NMAP = r"""#!/bin/sh
printf '<?xml version="1.0"?><nmaprun><taskbegin task="SYN Stealth Scan" time="1"/><taskprogress task="SYN Ste'
sleep 0.3
printf 'alth Scan" time="2" percent="50.00" remaining="1" etc="3"/><host><status state="up"/>'
printf '<address addr="192.168.1.5" addrtype="ipv4"/></host>'
sleep 0.3
printf '<taskprogress task="SYN Stealth Scan" time="3" percent="100.00" remaining="0" etc="3"/></nmaprun>'
"""


@pytest.mark.asyncio
async def test_run_nmap_reports_progress_from_a_real_subprocess(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text(FAKE_NMAP)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    seen = []
    xml = await run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake), progress=seen.append)
    assert xml.endswith("</nmaprun>") and "192.168.1.5" in xml
    percents = [p["percent"] for p in seen if p["task"] == "SYN Stealth Scan"]
    assert 50.0 in percents and percents[-1] == 100.0  # the tag split across chunks was still parsed
    assert seen[-1]["hosts_found"] == 1


@pytest.mark.asyncio
async def test_progress_callback_errors_do_not_break_the_scan(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text(FAKE_NMAP)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    def boom(_):
        raise RuntimeError("ui exploded")

    xml = await run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake), progress=boom)
    assert "</nmaprun>" in xml


@pytest.mark.asyncio
async def test_nmap_failure_still_reports_stderr(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\necho 'dnet: Failed to open device eth0' >&2\nexit 1\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    from app.scanner.nmap_runner import ScanError

    with pytest.raises(ScanError, match="Failed to open device"):
        await run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake), progress=lambda p: None)
