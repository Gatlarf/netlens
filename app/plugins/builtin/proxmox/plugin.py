"""Proxmox VE plugin: lists the VMs and containers and the host each one runs on (read-only)."""

from __future__ import annotations

import re

from .client import ProxmoxClient
from .config import ProxmoxConfig, has_credentials

CLIENT_FACTORY = ProxmoxClient  # replaced by tests


def _client(config: dict):
    cfg = ProxmoxConfig(
        url=config.get("url", ""),
        verify_tls=bool(config.get("verify_tls", True)),
        username=config.get("username", ""),
        password=config.get("password", ""),
        token_id=config.get("token_id", ""),
        token_secret=config.get("token_secret", ""),
    )
    if not has_credentials(cfg):
        raise ValueError("enter either an API token (ID and secret) or a username and password")
    return CLIENT_FACTORY(cfg)


def test(config: dict) -> dict:
    client = _client(config)
    version = client.version()
    inventory = client.inventory()
    return {"message": f"Connected: Proxmox VE {version}, {len(inventory['nodes'])} node(s), {len(inventory['guests'])} guest(s)"}


def fetch(config: dict) -> dict:
    inventory = _client(config).inventory()
    return {
        "hosts": [
            {"id": n["name"], "name": n["name"], "ip": n.get("ip"), "online": bool(n.get("online", True))}
            for n in inventory["nodes"]
        ],
        "guests": [
            {
                "id": str(g["vmid"]),
                "name": g["name"],
                "kind": g["kind"],
                "host_id": g["node"],
                "status": g["status"],
                "macs": g["macs"],
                "ips": g["ips"],
            }
            for g in inventory["guests"]
        ],
    }


def diagnose(config: dict) -> dict:
    """What this Proxmox answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""
    from app.plugins.builtin.diag import SAMPLES, describe, make_step, mask, problem

    client = _client(config)
    report: dict = {"steps": {}}
    step = make_step(report)
    step("version", lambda: client.get("/version"))
    step("cluster_status", lambda: client.get("/cluster/status"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    step("nodes", lambda: client.get("/nodes"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    resources = step("resources", lambda: client.get("/cluster/resources?type=vm"), lambda v: {"count": len(v), "first": [describe(x) for x in v[:SAMPLES]]})
    for kind in ("qemu", "lxc"):
        guest = next((g for g in resources or [] if isinstance(g, dict) and g.get("type") == kind and not g.get("template") and g.get("vmid") is not None), None)
        if guest:
            # the network lines of a guest keep their structure (`virtio=<mac>,bridge=vmbr0`); every other value is only described
            def read_config(guest=guest, kind=kind):
                cfg = client.get(f"/nodes/{guest['node']}/{kind}/{guest['vmid']}/config")
                return {k: (mask(v) if isinstance(v, str) and re.fullmatch(r"(net|ipconfig)\d+", k) else describe(v, k)) for k, v in cfg.items()}

            step(f"{kind}_config", read_config, lambda v: v)
    try:
        inventory = client.inventory()
        report["result"] = {
            "nodes": len(inventory["nodes"]), "nodes_with_ip": sum(1 for n in inventory["nodes"] if n.get("ip")),
            "guests": len(inventory["guests"]), "by_kind": {k: sum(1 for g in inventory["guests"] if g["kind"] == k) for k in ("qemu", "lxc")},
            "guests_with_mac": sum(1 for g in inventory["guests"] if g["macs"]), "guests_with_ip": sum(1 for g in inventory["guests"] if g["ips"]),
        }
    except Exception as exc:  # noqa: BLE001
        report["error"] = problem(exc)
    return report
