import json

from app.db import get_setting
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import ConfigError, load_settings
from app.db import connect, init_db
from app.demo import live, network, seed as seed_module
from app.main import create_app

NOW = datetime(2026, 10, 12, 20, 0, tzinfo=timezone.utc)      # a Monday evening


class QuietRandom(random.Random):
    """A generator that never rolls a new random outage (random() is always high), so a test controls who is down."""

    def random(self):
        return 0.99


@pytest.fixture
def seeded(tmp_path):
    path = tmp_path / "netlens.db"
    conn = connect(path)
    init_db(conn)
    seed_module.seed(conn, tmp_path, NOW)
    yield conn, path, tmp_path
    conn.close()


@pytest.fixture
def client(tmp_path):
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_DEMO": "on"})
    with TestClient(create_app(settings)) as c:
        yield c


def test_settings_demo_defaults_and_validation():
    assert load_settings({}).demo is False
    s = load_settings({"NETLENS_DEMO": "on", "NETLENS_TERMINAL": "on"})
    assert s.demo and s.demo_reset == "daily" and s.terminal_enabled is False        # a public demo never gets a shell
    assert load_settings({"NETLENS_DEMO": "on", "NETLENS_DEMO_RESET": "hourly"}).demo_reset == "hourly"
    with pytest.raises(ConfigError):
        load_settings({"NETLENS_DEMO": "yes"})
    with pytest.raises(ConfigError):
        load_settings({"NETLENS_DEMO_RESET": "weekly"})


def test_seed_builds_a_complete_network(seeded):
    conn, _path, _dir = seeded
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == len(network.DEVICES)
    assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] > 50000                 # a month of history
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_offline'").fetchone()[0] > 20
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_online'").fetchone()[0] > 20
    # every device has an address from the made-up range and a name in the made-up domain
    for r in conn.execute("SELECT primary_ip, hostname FROM devices"):
        assert r["primary_ip"].startswith(network.SUBNET + ".") and r["hostname"]
    # DNS: the plan is mostly "registered", and no real server was involved
    assert conn.execute("SELECT COUNT(*) FROM dns_state WHERE state = 'ok'").fetchone()[0] >= 30
    # the plugins are switched on with a configuration, and nothing in them is real
    for plugin in ("proxmox", "asus", "docker", "truenas", "hyperv", "npm", "snmp", "technitium"):
        assert json.loads(get_setting(conn, f"plugin.{plugin}"))["enabled"] is True
    assert not any(s.lower().startswith(("http://192.168.0.", "https://192.168.0.")) for (s,) in conn.execute("SELECT value FROM settings"))


def test_seed_twice_starts_over_and_keeps_the_account(seeded):
    conn, _path, tmp = seeded
    user_id = conn.execute("SELECT id FROM users WHERE username = 'demo'").fetchone()[0]
    seed_module.seed(conn, tmp, NOW + timedelta(hours=1))
    assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == len(network.DEVICES)
    assert conn.execute("SELECT id FROM users WHERE username = 'demo'").fetchone()[0] == user_id


def test_outage_of_a_switch_takes_its_cameras_with_it(seeded):
    conn, _path, _dir = seeded
    ids = {r["hostname"]: r["id"] for r in conn.execute("SELECT id, hostname FROM devices")}
    sim = live.Sim(1)
    sim.rng = QuietRandom(1)
    sim.down["sw_garden"] = NOW + timedelta(hours=1)
    live.tick(conn, sim, NOW + timedelta(minutes=5))
    for name in ("sw-garden", "cam-back", "cam-garden"):
        assert conn.execute("SELECT online FROM devices WHERE id = ?", (ids[name],)).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_offline' AND device_id = ? AND ts >= '2026-10-12T20:05:00Z'", (ids["cam-back"],)).fetchone()[0] == 1
    sim.down.clear()
    live.tick(conn, sim, NOW + timedelta(minutes=10))
    assert conn.execute("SELECT online FROM devices WHERE id = ?", (ids["cam-back"],)).fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'device_online' AND device_id = ? AND ts >= '2026-10-12T20:10:00Z'", (ids["cam-back"],)).fetchone()[0] == 1


def test_live_rounds_keep_going_without_errors(seeded):
    conn, _path, _dir = seeded
    sim = live.Sim(7)
    for i in range(1, 40):
        live.tick(conn, sim, NOW + timedelta(minutes=5 * i))
    assert conn.execute("SELECT MAX(ts) FROM checks").fetchone()[0] == "2026-10-12T23:15:00Z"
    assert conn.execute("SELECT COUNT(*) FROM stats_daily WHERE day = '2026-10-12'").fetchone()[0] == 1


@pytest.mark.parametrize("mode,later,due", [("off", timedelta(days=3), False), ("hourly", timedelta(minutes=30), False), ("hourly", timedelta(hours=1), True),
                                           ("daily", timedelta(hours=3), False), ("daily", timedelta(hours=5), True)])
def test_reset_schedule(seeded, mode, later, due):
    conn, _path, _dir = seeded
    assert live.reset_due(conn, mode, NOW + later) is due           # NOW is 20:00: five hours later is the next day


def test_demo_api_shows_everything_but_changes_nothing(client):
    session = client.get("/api/session").json()
    assert session["demo"]["username"] == "demo" and session["token_login"] is False
    assert client.post("/api/login", json={"username": "demo", "password": session["demo"]["password"]}).status_code == 200
    for path in ("/api/devices", "/api/map", "/api/hierarchy", "/api/uptime", "/api/stats/summary", "/api/service-checks", "/api/plugins", "/api/dns", "/api/sites", "/api/events?limit=5"):
        assert client.get(path).status_code == 200, path
    assert client.get("/api/devices").json()
    for method, path in (("post", "/api/scans"), ("put", "/api/map-settings"), ("delete", "/api/devices/1"), ("post", "/api/plugins/docker/sync")):
        response = client.request(method.upper(), path, json={})
        assert response.status_code == 403 and "demo" in response.json()["detail"], (method, path)
    assert client.post("/api/logout").status_code == 200


def test_demo_plugin_stand_ins_match_the_real_manifests():
    real = Path(__file__).resolve().parent.parent / "plugins"
    if not real.is_dir():
        pytest.skip("plugin sources are not part of this checkout")
    for folder in sorted((Path(seed_module.__file__).parent / "plugins").iterdir()):
        assert json.loads((folder / "plugin.json").read_text()) == json.loads((real / folder.name / "plugin.json").read_text()), folder.name


def test_demo_has_always_on_devices_and_suggestions(tmp_path):
    import tempfile
    from pathlib import Path

    from app.db import connect, init_db, utcnow
    from app.demo import seed as demo_seed
    from app.stats import core_numbers
    from app.uptime import core_choices

    data = Path(tempfile.mkdtemp())
    conn = connect(data / "t.db")
    init_db(conn)
    demo_seed.seed(conn, data)
    core = core_numbers(conn, utcnow())
    assert 10 <= core["devices"] < 30 and core["uptime"]["30d"] > 97              # the always-on view looks healthy next to ~80% for everything
    assert any(c["suggested"] for c in core_choices(conn))                           # and the chooser has something to suggest
