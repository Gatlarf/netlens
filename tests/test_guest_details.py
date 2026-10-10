"""Guest details and guest events for the Proxmox, TrueNAS and Docker plugins (the same contract, the same screens)."""

import importlib.util
import json
import sqlite3
from pathlib import Path

from app import containers
from app.plugins.builtin.proxmox import plugin as proxmox_plugin
from app.plugins.contract import validate_output

spec = importlib.util.spec_from_file_location("truenas_plugin", Path(__file__).resolve().parents[1] / "plugins" / "truenas" / "plugin.py")
truenas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(truenas)


def test_proxmox_details_follow_the_contract():
    guest = {"cpus": 4, "memory_mb": 8192, "disk_gb": 64, "uptime": 3600, "tags": "prod, db", "os": "l26", "autostart": True}
    details = proxmox_plugin._details(guest)
    assert details["cpus"] == 4 and details["memory_mb"] == 8192 and details["disk_gb"] == 64 and details["tags"] == "prod, db" and details["os"] == "l26"
    assert details["autostart"] is True and details["started"].endswith("Z")
    out = validate_output("hypervisor", {"hosts": [{"id": "pve"}], "guests": [{"id": "100", "name": "web", "kind": "qemu", "host_id": "pve", "status": "running", "details": details}]})
    assert out["guests"][0]["details"]["memory_mb"] == 8192
    assert proxmox_plugin._details({"cpus": None, "uptime": 0}) == {}


def test_truenas_app_details_include_ports_version_and_update():
    app = {"name": "plex", "id": "plex", "state": "RUNNING", "human_version": "1.41.2", "upgrade_available": True,
           "active_workloads": {"container_details": [{"image": "plexinc/pms-docker:latest"}],
                                "used_ports": [{"container_port": 32400, "protocol": "tcp", "host_ports": [{"host_port": 32400, "host_ip": "0.0.0.0"}]}]}}
    snapshot = {"hostname": "nas", "version": "x", "interfaces": [], "notes": [], "instances": [], "apps": [app],
                "vms": [{"id": 1, "name": "vm", "status": {"state": "RUNNING"}, "vcpus": 2, "cores": 2, "threads": 1, "memory": 4096, "devices": []}]}
    out = validate_output("hypervisor", truenas.to_hypervisor(snapshot, "192.168.0.200"))
    guests = {g["name"]: g for g in out["guests"]}
    d = guests["plex"]["details"]
    assert d["image"] == "plexinc/pms-docker:latest" and d["version"] == "1.41.2" and d["update_available"] is True
    assert d["ports"][0]["host_port"] == 32400 and d["exposed"] is True
    assert guests["vm"]["details"]["cpus"] == 4 and guests["vm"]["details"]["memory_mb"] == 4096


def _guest(gid, kind, status, **details):
    return {"id": gid, "name": gid, "kind": kind, "host_id": "h", "status": status, "details": details, "device_id": None, "host_device_id": 1}


def test_vm_and_app_events():
    previous = {"a": {"status": "running", "health": None, "restarts": None, "update": False}, "b": {"status": "stopped", "health": None, "restarts": None, "update": False},
                "c": {"status": "running", "health": None, "restarts": None, "update": False}}
    guests = [_guest("a", "qemu", "stopped"), _guest("b", "lxc", "running"), _guest("c", "app", "running", update_available=True, version="2.0")]
    kinds = [k for k, _, _ in containers.changes(previous, guests, {"h": "pve"})]
    assert sorted(kinds) == ["guest_started", "guest_stopped", "guest_update_available"]
    # nothing changed, nothing reported
    same = [_guest("a", "qemu", "running"), _guest("c", "app", "running")]
    assert containers.changes({"a": previous["a"], "c": previous["c"]}, same, {}) == []


def test_guest_summary_counts_kinds_updates_and_old_images(tmp_path):
    from app.db import connect, init_db
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    rows = [("proxmox", "100", "web", "qemu", "pve", "running", {}), ("proxmox", "101", "db", "lxc", "pve", "stopped", {}),
            ("truenas", "app:plex", "plex", "app", "nas", "running", {"update_available": True, "version": "2.0"}),
            ("docker", "h/old", "old", "container", "dock", "running", {"image_created": "2020-01-01T00:00:00Z"}),
            ("docker", "h/new", "new", "container", "dock", "running", {"image_created": "2999-01-01T00:00:00Z"})]
    for plugin_id, gid, name, kind, host, status, details in rows:
        conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated, details) VALUES (?, ?, ?, ?, ?, ?, 'now', ?)",
                     (plugin_id, gid, name, kind, host, status, json.dumps(details)))
    g = containers.guest_summary(conn)
    assert g["total"] == 5 and g["running"] == 4 and g["stopped"] == 1 and g["hosts"] == 3
    assert g["by_kind"]["vm"] == {"total": 1, "running": 1} and g["by_kind"]["container"]["total"] == 2
    assert g["update_available"] == 1 and g["old_images"] == 1
    assert {a["name"] for a in g["attention"]} == {"plex", "old"}
