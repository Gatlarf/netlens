import json
import stat

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_runner import build_args, run_nmap
from app.scanner.options import ScanOptions, options_from_dict

AUTH = {"Authorization": "Bearer secret"}


def _client(db):
    return TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers=AUTH)


def test_defaults_presets_and_preview(tmp_path):
    with _client(tmp_path / "t.db") as c:
        body = c.get("/api/scan-options").json()
        assert body["is_default"] is True and body["options"] == body["defaults"]
        assert body["preview"]["quick"] == "nmap -T3 --top-ports 100 --host-timeout 120s -oX - <ranges>"
        assert body["preview"]["deep"] == "nmap -T3 -sV -O --osscan-guess --traceroute --top-ports 1000 --host-timeout 900s -oX - <ranges>"
        assert set(body["presets"]) == {"default", "fast", "fastest"}
        assert body["presets"]["fast"]["timing"] == 4 and body["presets"]["fast"]["deep_version"] == "light"


def test_partial_update_applies_to_the_scan_manager_and_survives_restart(tmp_path):
    db = tmp_path / "t.db"
    with _client(db) as c:
        r = c.put("/api/scan-options", json={"timing": 4, "deep_version": "light", "deep_ports": "22,80,443"})
        assert r.status_code == 200
        body = r.json()
        assert body["is_default"] is False and body["options"]["timing"] == 4 and body["options"]["deep_top_ports"] == 1000
        assert body["preview"]["deep"] == "nmap -T4 -sV --version-light -O --osscan-guess --traceroute -p 22,80,443 --host-timeout 900s -oX - <ranges>"
        assert c.app.state.scan_manager.options.deep_ports == "22,80,443"
        # a second partial update keeps the earlier changes
        c.put("/api/scan-options", json={"skip_dns": True})
        assert c.get("/api/scan-options").json()["options"]["timing"] == 4
    with _client(db) as c:  # restart
        opts = c.get("/api/scan-options").json()["options"]
        assert opts["timing"] == 4 and opts["skip_dns"] is True and opts["deep_version"] == "light"
        assert c.app.state.scan_manager.options.timing == 4
        r = c.delete("/api/scan-options")
        assert r.json()["is_default"] is True and c.app.state.scan_manager.options == ScanOptions()
    with _client(db) as c:
        assert c.get("/api/scan-options").json()["is_default"] is True


@pytest.mark.parametrize("payload, text", [
    ({"timing": 9}, "timing"),
    ({"quick_ports": "22;ls"}, "quick_ports"),
    ({"deep_version": "turbo"}, "deep_version"),
    ({"turbo": True}, "unknown setting"),
    ({"deep_host_timeout": 3}, "deep_host_timeout"),
])
def test_invalid_updates_are_rejected_and_change_nothing(tmp_path, payload, text):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/scan-options", json=payload)
        assert r.status_code == 422 and text in r.json()["detail"]
        assert c.get("/api/scan-options").json()["is_default"] is True


def test_requires_auth(tmp_path):
    with _client(tmp_path / "t.db") as c:
        bad = {"Authorization": "Bearer no"}
        assert c.get("/api/scan-options", headers=bad).status_code == 401
        assert c.put("/api/scan-options", json={}, headers=bad).status_code == 401
        assert c.delete("/api/scan-options", headers=bad).status_code == 401


def test_corrupt_saved_options_fall_back_to_defaults(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    conn.execute("INSERT INTO settings (key, value) VALUES ('scan_options', '{\"timing\": 99}')")
    conn.commit()
    conn.close()
    with _client(db) as c:
        assert c.get("/api/scan-options").json()["is_default"] is True


def test_build_args_default_is_unchanged_and_options_take_over():
    assert build_args("quick", ["192.168.1.0/24"]) == ["-T3", "--top-ports", "100", "--host-timeout", "120s", "-oX", "-", "192.168.1.0/24"]
    assert build_args("quick", ["192.168.1.0/24"], timing=5)[0] == "-T5"
    fast = options_from_dict({"timing": 4, "deep_version": "off", "deep_os": False, "deep_traceroute": False, "deep_top_ports": 100, "deep_host_timeout": 0})
    assert build_args("deep", ["192.168.1.0/24"], options=fast) == ["-T4", "--top-ports", "100", "-oX", "-", "192.168.1.0/24"]
    with_progress = build_args("quick", ["192.168.1.0/24"], stats_every="2s", options=fast)
    assert with_progress[:3] == ["-v", "--stats-every", "2s"]
    with pytest.raises(ValueError):
        build_args("weird", ["192.168.1.0/24"])
    with pytest.raises(ValueError):
        build_args("quick", ["8.8.8.0/24"])  # public ranges are still refused


@pytest.mark.asyncio
async def test_run_nmap_passes_the_chosen_options_to_the_process(tmp_path):
    argv_file = tmp_path / "argv.txt"
    fake = tmp_path / "nmap"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {argv_file}\nprintf "<nmaprun></nmaprun>"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    opts = options_from_dict({"timing": 4, "quick_mode": "discovery", "skip_dns": True, "quick_host_timeout": 60})
    await run_nmap("quick", ["192.168.1.0/24"], nmap_path=str(fake), options=opts)
    assert argv_file.read_text().split() == ["-T4", "-sn", "-n", "--host-timeout", "60s", "-oX", "-", "192.168.1.0/24"]


@pytest.mark.asyncio
async def test_scan_manager_hands_current_options_to_the_runner(tmp_path):
    from app.scanner.orchestrator import ScanManager

    db = tmp_path / "t.db"
    init_db(connect(db))
    seen = {}

    async def runner(kind, targets, *, nmap_path="nmap", options=None, progress=None):
        seen["options"] = options
        return '<?xml version="1.0"?><nmaprun></nmaprun>'

    async def names():
        return {}

    async def ranges():
        return ["192.168.1.0/24"]

    manager = ScanManager(db, load_settings({"NETLENS_TOKEN": "t"}), runner=runner, names_provider=names, ranges_provider=ranges, after_scan=[])
    manager.options = options_from_dict({"timing": 5})
    await manager.start("quick")
    await manager.wait()
    assert seen["options"].timing == 5
