"""Proxmox VE plugin: lists the VMs and containers and the host each one runs on (read-only)."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from .client import ProxmoxClient
from .config import ProxmoxConfig, has_credentials

CLIENT_FACTORY = ProxmoxClient  # replaced by tests


def _servers(config: dict) -> list[dict]:
    """One flat config per Proxmox: the rows of the server list, or the single url and credentials of an older Netlens."""
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    keep = ("token_id", "token_secret", "username", "password")
    out = [{"url": r.get("host"), "verify_tls": config.get("verify_tls", True), **{k: r.get(k) or "" for k in keep}}
           for r in rows if isinstance(r, dict) and any(r.get(k) for k in ("host", *keep))]
    if not out:
        raise ValueError("enter the address and credentials of at least one Proxmox server")
    return out


def _each(config: dict, work):
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - keeps its type; only the message gets the server's name
            if len(servers) > 1 and exc.args:
                exc.args = (f"{one.get('url')}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


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


def _details(g: dict) -> dict:
    """Resources, uptime, tags and so on, as the guest details of the plugin contract (empty values left out)."""
    started = None
    if isinstance(g.get("uptime"), (int, float)) and g["uptime"] > 0:
        started = datetime.fromtimestamp(time.time() - g["uptime"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    details = {"cpus": g.get("cpus"), "memory_mb": g.get("memory_mb"), "disk_gb": g.get("disk_gb"), "started": started,
               "tags": g.get("tags"), "os": g.get("os"), "autostart": g.get("autostart")}
    return {k: v for k, v in details.items() if v not in (None, "")}


def _test_one(config: dict) -> str:
    client = _client(config)
    version = client.version()
    inventory = client.inventory()
    return f"Connected: Proxmox VE {version}, {len(inventory['nodes'])} node(s), {len(inventory['guests'])} guest(s)"


def test(config: dict) -> dict:
    messages = _each(config, _test_one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} Proxmox servers answered. " + " | ".join(messages)}


def fetch(config: dict) -> dict:
    results = _each(config, _fetch_one)
    if len(results) == 1:
        return results[0]
    hosts, guests, taken = [], [], set()
    for out in results:
        hosts += out["hosts"]
        for g in out["guests"]:
            if g["id"] in taken:                      # the same VM number on two clusters: keep both apart
                g = {**g, "id": f"{g['host_id']}/{g['id']}"}
            taken.add(g["id"])
            guests.append(g)
    return {"hosts": hosts, "guests": guests}


def _fetch_one(config: dict) -> dict:
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
                "details": _details(g),
            }
            for g in inventory["guests"]
        ],
    }


def diagnose(config: dict) -> dict:
    """What this Proxmox answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""
    from app.plugins.builtin.diag import SAMPLES, describe, make_step, mask, problem

    client = _client(_servers(config)[0])      # the first server is described
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
