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
            "rssi": c.get("rssi"), "tx_mbps": c.get("tx_mbps"), "rx_mbps": c.get("rx_mbps"),
            "vendor": c.get("vendor"), "device_type": "printer" if c.get("printer") else None,
        })
    return {"nodes": out_nodes, "clients": clients}


def test(config: dict) -> dict:
    snapshot = _client(config).snapshot()
    return {"message": f"Connected: {len(snapshot['nodes'])} mesh node(s), {len(snapshot['clients'])} online client(s)"}


def fetch(config: dict) -> dict:
    return to_topology(_client(config).snapshot())


def diagnose(config: dict) -> dict:
    """What this router answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""
    import json

    from app.plugins.builtin.diag import SAMPLES, describe, make_step, problem

    from .client import AsusAuthError, AsusError, build_snapshot, parse_onboarding

    client = _client(config)
    report: dict = {"steps": {}}
    step = make_step(report)
    client.login()  # a refused login is reported as such (and stops automatic syncing), like test()
    clientlist = onboarding = None
    try:
        def read_clientlist():
            status, text = client._send("/appGet.cgi?hook=get_clientlist()")
            if status != 200:
                raise AsusError(f"HTTP {status}")
            return json.loads(text)

        def read_onboarding():
            status, text = client._send("/ajax_onboarding.asp")
            if status != 200:
                raise AsusError(f"HTTP {status}")
            return text

        clientlist = step("clientlist", read_clientlist)
        raw = step("onboarding", read_onboarding, lambda t: {"length": len(t), "lines": t.count("\n") + 1})
        if raw is not None:
            nodes = parse_onboarding(raw)
            onboarding = nodes
            report["steps"]["onboarding"]["nodes_parsed"] = len(nodes)
            report["steps"]["onboarding"]["first_node"] = [describe(n) for n in nodes[:SAMPLES]]
        if clientlist is not None and onboarding is not None:
            snapshot = build_snapshot(clientlist, onboarding)
            report["result"] = {
                "nodes": len(snapshot["nodes"]), "main_nodes": sum(1 for n in snapshot["nodes"] if n["main"]),
                "clients": len(snapshot["clients"]), "wired": sum(1 for c in snapshot["clients"] if c["wired"]),
                "with_rssi": sum(1 for c in snapshot["clients"] if c.get("rssi") is not None), "with_rates": sum(1 for c in snapshot["clients"] if c.get("tx_mbps") is not None),
                "with_node": sum(1 for c in snapshot["clients"] if c["node_mac"]),
            }
    except AsusAuthError:
        raise
    except Exception as exc:  # noqa: BLE001
        report["error"] = problem(exc)
    finally:
        client.logout()
    return report
