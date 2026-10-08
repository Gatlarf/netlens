"""ASUS router / AiMesh plugin: which client is connected to which mesh node (stock ASUSWRT, read-only)."""

from __future__ import annotations

from .client import AsusClient

CLIENT_FACTORY = AsusClient  # replaced by tests


def _client(config: dict):
    from .config import AsusConfig

    cfg = AsusConfig(
        url=config.get("url", ""),
        verify_tls=bool(config.get("verify_tls", False)),
        username=config.get("username", ""),
        password=config.get("password", ""),
    )
    if not (cfg.url and cfg.username and cfg.password):
        raise ValueError("enter the router address, username and password")
    return CLIENT_FACTORY(cfg)


def to_topology(snapshot: dict) -> dict:
    """Turn the router's raw view into the plugin contract (kind 'topology')."""
    nodes = snapshot["nodes"]
    main = next((n for n in nodes if n["main"]), None)
    out_nodes = []
    for n in nodes:
        parent = None
        if main is not None and n is not main:
            holder = next((p for p in nodes if p is not n and n["mac"] in p["wired_macs"]), None)  # the node it is wired to
            parent = (holder or main)["mac"]
        out_nodes.append({
            "mac": n["mac"], "macs": n["macs"], "ip": n["ip"], "name": n["name"], "model": n["model"],
            "role": "gateway" if n is main else "node", "parent_mac": parent,
        })
    known = {m for n in nodes for m in n["macs"]}
    clients = []
    for c in snapshot["clients"]:
        node = c["node_mac"] if c["node_mac"] in known else (main["mac"] if main else None)
        clients.append({
            "mac": c["mac"], "ip": c["ip"], "name": c["name"], "node_mac": node,
            "medium": "wired" if c["wired"] else "wifi", "band": c["band"],
        })
    return {"nodes": out_nodes, "clients": clients}


def test(config: dict) -> dict:
    snapshot = _client(config).snapshot()
    return {"message": f"Connected: {len(snapshot['nodes'])} mesh node(s), {len(snapshot['clients'])} online client(s)"}


def fetch(config: dict) -> dict:
    return to_topology(_client(config).snapshot())
