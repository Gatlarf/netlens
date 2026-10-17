"""Proxmox and the ASUS router are ordinary plugins now: an installation that used them gets them back from the Plugin store, with its settings."""

import json

import pytest

from app.db import get_setting, set_setting
from app.plugins import moved
from app.plugins.index import OFFICIAL_URL, get_index
from app.plugins.registry import discover
from app.plugins.service import get_state
from tests.test_plugin_index import Server, conn, entry, index_doc, make_zip, publish, release, world  # noqa: F401 - fixtures

pytestmark = pytest.mark.no_shipped_plugins


def offer(server, conn, level="verified"):
    rel = publish(server, "1.4.0", level=level, plugin_id="proxmox", kind="hypervisor")
    server.put_index(index_doc(entry("proxmox", kind="hypervisor", releases=[rel])), etag='"m1"')
    get_index(conn, force=True, getter=server)


def test_nothing_happens_without_old_settings(world):
    conn, tmp, server = world
    offer(server, conn)
    assert moved.pending(conn, tmp) == [] and moved.run(conn, tmp, getter=server) == []
    assert "proxmox" not in discover(tmp)


def test_a_user_of_the_old_builtin_gets_it_back_enabled_with_its_settings(world):
    conn, tmp, server = world
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": True, "config": {"host": "https://pve:8006"}}))
    offer(server, conn)
    assert moved.pending(conn, tmp) == ["proxmox"]
    assert moved.run(conn, tmp, getter=server) == [{"id": "proxmox", "version": "1.4.0"}]
    state = get_state(conn, discover(tmp)["proxmox"])
    assert state["enabled"] is True and state["config"]["host"] == "https://pve:8006"
    event = conn.execute("SELECT detail FROM events WHERE kind = 'plugin_updated'").fetchone()
    assert "no longer built into Netlens" in event["detail"]
    assert moved.run(conn, tmp, getter=server) == []                    # installed now: nothing left to do


def test_a_plugin_that_was_off_stays_off(world):
    conn, tmp, server = world
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": False, "config": {"host": "x"}}))
    offer(server, conn)
    moved.run(conn, tmp, getter=server)
    assert get_state(conn, discover(tmp)["proxmox"])["enabled"] is False


def test_when_the_store_cannot_help_it_says_so_once_and_keeps_the_settings(world):
    conn, tmp, server = world
    set_setting(conn, "plugin.asus", json.dumps({"enabled": True, "config": {"url": "https://r"}}))
    server.put_index(index_doc(entry("omada", releases=[publish(server)])), etag='"m2"')
    get_index(conn, force=True, getter=server)
    assert moved.run(conn, tmp, getter=server)[0]["id"] == "asus"
    moved.run(conn, tmp, getter=server)
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'plugin_update_failed'").fetchone()[0] == 1
    assert json.loads(get_setting(conn, "plugin.asus"))["config"]["url"] == "https://r"


def test_an_old_cached_index_is_refreshed_once(world):
    conn, tmp, server = world
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": True, "config": {"host": "x"}}))
    server.put_index(index_doc(entry("proxmox", kind="hypervisor", builtin=True)), etag='"old"')      # how the index looked before the move
    get_index(conn, force=True, getter=server)
    rel = publish(server, "1.4.0", level="verified", plugin_id="proxmox", kind="hypervisor")
    server.put_index(index_doc(entry("proxmox", kind="hypervisor", releases=[rel])), etag='"new"')
    assert moved.run(conn, tmp, getter=server) == [{"id": "proxmox", "version": "1.4.0"}]


def test_the_old_single_server_settings_are_kept_so_the_server_list_can_be_built_from_them(world):
    conn, tmp, server = world
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": True, "config": {"url": "https://pve:8006", "username": "root@pam", "password": "pw"}}))
    offer(server, conn)
    moved.run(conn, tmp, getter=server)
    saved = json.loads(get_setting(conn, "plugin.proxmox"))["config"]
    assert saved["url"] == "https://pve:8006" and saved["password"] == "pw"
