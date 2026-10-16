"""Automatic plugin updates (per plugin) and the warning after a Netlens upgrade."""

import pytest

from app.db import get_setting
from app.plugins import autoupdate as au
from app.plugins import index as idx
from app.plugins import index_install as inst
from app.plugins.index import OFFICIAL_URL, get_index, parse_index
from app.plugins.registry import discover
from app.plugins.service import set_status
from tests.test_plugin_index import Server, client, conn, entry, index_doc, publish, world  # noqa: F401 - fixtures


def setup(world, installed="1.0.0", offered=(("1.1.0", "reviewed"),), auto=True, extra=None):
    conn, tmp, server = world
    r0 = publish(server, installed, level="reviewed")
    e0 = parse_index(index_doc(entry("omada", releases=[r0])))[0][0]
    inst.install_release(conn, tmp, e0, e0["releases"][0], getter=server, index_url=OFFICIAL_URL)
    rels = [publish(server, v, level=lvl, **(extra or {})) for v, lvl in offered] + [r0]
    server.put_index(index_doc(entry("omada", releases=rels)), etag='"setup"')
    get_index(conn, force=True, getter=server)
    if auto:
        au.set_enabled(conn, "omada", True)
    return conn, tmp, server


def version(tmp):
    return discover(tmp)["omada"].manifest["version"]


def test_off_by_default_nothing_is_installed(world):
    conn, tmp, server = setup(world, auto=False)
    assert au.run(conn, tmp, getter=server) == []
    assert version(tmp) == "1.0.0" and au.settings(conn, "omada") == {"enabled": False, "skip": None, "last": None}


def test_a_reviewed_update_is_installed_and_logged(world):
    conn, tmp, server = setup(world)
    assert au.run(conn, tmp, getter=server) == [{"id": "omada", "from": "1.0.0", "to": "1.1.0"}]
    assert version(tmp) == "1.1.0"
    event = conn.execute("SELECT kind, detail FROM events WHERE kind = 'plugin_updated'").fetchone()
    assert event and "1.0.0 to 1.1.0" in event["detail"]
    assert au.run(conn, tmp, getter=server) == []                       # nothing newer: nothing to do


def test_settings_and_enabled_state_survive_an_automatic_update(world):
    from app.plugins.service import get_state, save_state

    conn, tmp, server = setup(world)
    save_state(conn, "omada", True, {"host": "10.0.0.1"})
    au.run(conn, tmp, getter=server)
    assert get_state(conn, discover(tmp)["omada"]) == {"enabled": True, "config": {"host": "10.0.0.1"}}


def test_a_community_release_is_never_installed_automatically(world):
    conn, tmp, server = setup(world, offered=(("1.1.0", "community"),))
    assert au.run(conn, tmp, getter=server) == []
    assert version(tmp) == "1.0.0"
    skipped = conn.execute("SELECT detail FROM events WHERE kind = 'plugin_update_skipped'").fetchall()
    assert len(skipped) == 1 and "not been reviewed" in skipped[0]["detail"]
    au.run(conn, tmp, getter=server)                                    # the same reason is not logged every hour
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'plugin_update_skipped'").fetchone()[0] == 1


def test_a_rollback_is_respected(world):
    conn, tmp, server = setup(world)
    au.run(conn, tmp, getter=server)
    result = inst.rollback(conn, tmp, "omada")
    au.skip_version(conn, "omada", result["from"])
    assert au.run(conn, tmp, getter=server) == [] and version(tmp) == "1.0.0"
    r3 = publish(server, "1.2.0", level="verified")                      # a newer version than the one rolled back from is fine again
    rels = [r3] + [publish(server, v, level="reviewed") for v in ("1.1.0",)] + [publish(server, "1.0.0", level="reviewed")]
    server.put_index(index_doc(entry("omada", releases=rels)), etag='"later"')
    get_index(conn, force=True, getter=server)
    assert au.run(conn, tmp, getter=server)[0]["to"] == "1.2.0"


def test_an_uploaded_plugin_is_never_replaced(client):
    z = client.server
    publish(z, "1.0.0", level="reviewed")
    from tests.test_plugin_index import make_zip

    assert client.post("/api/plugins", content=make_zip("omada", "1.0.0"), headers={"Content-Type": "application/zip"}).status_code == 200
    r = client.put("/api/plugin-index/omada/auto-update", json={"enabled": True})
    assert r.status_code == 422 and "uploaded" in r.json()["detail"]


def test_a_bad_download_is_reported_once_and_changes_nothing(world):
    conn, tmp, server = setup(world)
    url = "https://github.com/x/omada/releases/download/v1.1.0/omada.zip"
    server.files[url] = (b"not the file", None)
    out = au.run(conn, tmp, getter=server)
    assert out[0]["id"] == "omada" and "checksum" in out[0]["error"] and version(tmp) == "1.0.0"
    au.run(conn, tmp, getter=server)
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'plugin_update_failed'").fetchone()[0] == 1


def test_api_toggle_listing_and_rollback_skip(client):
    s = client.server
    r1 = publish(s, "1.0.0", level="reviewed")
    s.put_index(index_doc(entry("omada", releases=[r1])))
    assert client.post("/api/plugin-index/omada/install", json={}).status_code == 200
    row = lambda: next(p for p in client.get("/api/plugin-index").json()["plugins"] if p["id"] == "omada")
    assert row()["auto_update"] is False and row()["auto_update_possible"] is True
    assert client.put("/api/plugin-index/omada/auto-update", json={"enabled": True}).json()["enabled"] is True
    assert row()["auto_update"] is True
    assert next(p for p in client.get("/api/plugins").json()["plugins"] if p["id"] == "omada")["auto_update"] is True
    assert client.put("/api/plugin-index/nope/auto-update", json={"enabled": True}).status_code == 404
    r2 = publish(s, "1.1.0", level="reviewed")
    s.put_index(index_doc(entry("omada", releases=[r2, r1])), etag='"two"')
    client.get("/api/plugin-index?refresh=true")
    assert client.post("/api/plugin-index/omada/install", json={}).status_code == 200
    assert client.post("/api/plugin-index/omada/rollback").json()["version"] == "1.0.0"
    assert au.settings(__import__("app.db", fromlist=["connect"]).connect(client.tmp / "t.db"), "omada")["skip"] == "1.1.0"


# ------------------------------------------------------------------ Netlens upgraded
def test_upgrade_is_noticed_once_and_dismissed_until_the_next(conn, monkeypatch):
    monkeypatch.setattr(au, "VERSION", "0.4.30")
    assert au.note_version(conn) is None                                # first look: nothing to compare with
    monkeypatch.setattr(au, "VERSION", "0.4.31")
    up = au.note_version(conn)
    assert up["from"] == "0.4.30" and up["to"] == "0.4.31"
    assert au.note_version(conn)["from"] == "0.4.30"                    # still the same upgrade on the next look
    au.dismiss(conn)
    assert get_setting(conn, au.DISMISSED_KEY) == "0.4.31"


def test_check_lists_plugins_the_index_says_do_not_support_this_netlens(world, monkeypatch):
    conn, tmp, server = setup(world, auto=False)
    r0 = publish(server, "1.0.0", level="reviewed")
    r0["max_netlens"] = "0.4.30"
    r2 = publish(server, "1.1.0", level="reviewed")
    r2["max_netlens"] = "0.9.0"
    server.put_index(index_doc(entry("omada", releases=[r2, r0])), etag='"max"')
    get_index(conn, force=True, getter=server)
    monkeypatch.setattr(au, "VERSION", "0.4.31")
    found = au.check(conn, tmp, netlens_version="0.4.31")
    assert [p["id"] for p in found["problems"]] == ["omada"]
    problem = found["problems"][0]
    assert "up to Netlens 0.4.30" in problem["reason"] and problem["fix"] == {"version": "1.1.0", "level": "reviewed"}
    assert au.check(conn, tmp, netlens_version="0.4.20")["problems"] == []          # fine on the older Netlens


def test_check_lists_plugins_that_started_failing_after_the_upgrade(world, monkeypatch):
    conn, tmp, server = setup(world, auto=False)
    monkeypatch.setattr(au, "VERSION", "0.4.30")
    au.note_version(conn)
    monkeypatch.setattr(au, "VERSION", "0.4.31")
    up = au.note_version(conn)
    set_status(conn, "omada", ok=False, error="boom")
    found = au.check(conn, tmp, netlens_version="0.4.31")
    assert found["upgrade"]["from"] == "0.4.30" and "started failing after the Netlens upgrade: boom" in found["problems"][0]["reason"]


def test_check_is_quiet_without_an_upgrade(world):
    conn, tmp, server = setup(world, auto=False)
    set_status(conn, "omada", ok=False, error="boom")                 # a failing plugin alone is the plugin manager's business
    assert au.check(conn, tmp)["problems"] == []


def test_a_release_may_name_the_last_netlens_it_works_with():
    rel = {"api_version": 1, "min_netlens": "0.3.0", "max_netlens": "0.4.30"}
    assert idx.incompatible_reason(rel, "0.4.30") is None
    assert "up to Netlens 0.4.30" in idx.incompatible_reason(rel, "0.4.31")
    assert idx.incompatible_reason({**rel, "max_netlens": ""}, "9.9.9") is None


def test_api_compat_and_dismiss(client):
    body = client.get("/api/plugin-compat").json()
    assert body["problems"] == [] and body["upgrade"] is None
    assert client.post("/api/plugin-compat/dismiss").json() == {"dismissed": True}
    assert client.get("/api/plugin-compat").json()["dismissed"] is True
