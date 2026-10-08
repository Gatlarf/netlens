"""Proxmox VE plugin: lists the VMs and containers and the host each one runs on (read-only)."""

from __future__ import annotations

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
