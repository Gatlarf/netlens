import pytest
from app.scanner.relations import Edge, infer_relations


def mk(id, ip, type="pc", hostname=None, vendor=None, ports=(), online=1):
    return {
        "id": id,
        "primary_ip": ip,
        "type": type,
        "hostname": hostname,
        "vendor": vendor,
        "ports": list(ports),
        "online": online,
    }


def test_gateway_edges_basic():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2"),
        mk(3, "192.168.1.3"),
    ]
    edges = infer_relations(devices, gateway_ip="192.168.1.1")
    expected = [
        Edge(2, 1, "gateway", "default-route", 1.0),
        Edge(3, 1, "gateway", "default-route", 1.0),
    ]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected
    # No edge from router
    assert not any(e.src_id == 1 for e in edges)


def test_gateway_heuristic_single_router():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2"),
    ]
    edges = infer_relations(devices, gateway_ip=None)
    expected = [Edge(2, 1, "gateway", "heuristic", 0.5)]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected


def test_gateway_no_edges_with_two_routers():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2", type="router"),
        mk(3, "192.168.1.3"),
    ]
    edges = infer_relations(devices, gateway_ip=None)
    assert edges == []


def test_gateway_no_edges_with_no_routers():
    devices = [
        mk(1, "192.168.1.1"),
        mk(2, "192.168.1.2"),
    ]
    edges = infer_relations(devices, gateway_ip=None)
    assert edges == []


def test_gateway_ip_not_among_devices():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2"),
    ]
    edges = infer_relations(devices, gateway_ip="192.168.1.254")
    assert edges == []


def test_route_edges_with_hops():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "10.0.0.2", type="router"),
        mk(3, "10.0.5.20"),
    ]
    hops = {"10.0.5.20": ["192.168.1.1", "10.0.0.2"]}
    edges = infer_relations(devices, hops=hops, gateway_ip="192.168.1.1")
    # srv (3) has route edge to core (2)
    route_edge_srv_to_core = Edge(3, 2, "route", "traceroute", 0.9)
    # core (2) has route edge to gateway (1)
    route_edge_core_to_gw = Edge(2, 1, "route", "traceroute", 0.9)
    # srv should NOT have a gateway edge
    assert route_edge_srv_to_core in edges
    assert route_edge_core_to_gw in edges
    assert not any(e.kind == "gateway" and e.src_id == 3 for e in edges)
    # Check sorted order
    sorted_edges = sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id))
    assert sorted_edges == [route_edge_core_to_gw, route_edge_srv_to_core]


def test_unknown_hops_ignored():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "10.0.5.20"),
    ]
    hops = {"10.0.5.20": ["192.168.1.1", "10.0.0.99"]}
    edges = infer_relations(devices, hops=hops, gateway_ip="192.168.1.1")
    # Only known hop 192.168.1.1 is used; 10.0.0.99 is ignored
    # Device 2 gets the ROUTE edge to device 1, and NO gateway edge
    expected = [Edge(2, 1, "route", "traceroute", 0.9)]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected


def test_all_hops_unknown_falls_back_to_gateway():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "10.0.5.20"),
    ]
    hops = {"10.0.5.20": ["10.0.0.99", "10.0.0.100"]}
    edges = infer_relations(devices, hops=hops, gateway_ip="192.168.1.1")
    # All hops unknown, so device 2 gets a gateway edge
    expected = [Edge(2, 1, "gateway", "default-route", 1.0)]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected


def test_host_of_single_candidate():
    devices = [
        mk(4, "10.0.0.1", type="vm"),
        mk(5, "10.0.0.2", ports=[8006]),
    ]
    edges = infer_relations(devices)
    expected = [Edge(4, 5, "host-of", "heuristic", 0.5)]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected


def test_host_of_two_candidates_no_edge():
    devices = [
        mk(4, "10.0.0.1", type="vm"),
        mk(5, "10.0.0.2", ports=[8006]),
        mk(6, "10.0.0.3", ports=[8006]),
    ]
    edges = infer_relations(devices)
    assert edges == []


def test_host_of_hostname_candidate():
    devices = [
        mk(4, "10.0.0.1", type="vm"),
        mk(5, "10.0.0.2", hostname="proxmox1"),
    ]
    edges = infer_relations(devices)
    expected = [Edge(4, 5, "host-of", "heuristic", 0.5)]
    assert sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id)) == expected


def test_host_of_zero_candidates():
    devices = [
        mk(4, "10.0.0.1", type="vm"),
        mk(5, "10.0.0.2"),
    ]
    edges = infer_relations(devices)
    assert edges == []


def test_no_self_edges():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2"),
    ]
    edges = infer_relations(devices, gateway_ip="192.168.1.1")
    assert not any(e.src_id == e.dst_id for e in edges)


def test_no_duplicates():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "192.168.1.2"),
    ]
    edges = infer_relations(devices, gateway_ip="192.168.1.1")
    seen = set()
    for e in edges:
        key = (e.src_id, e.dst_id, e.kind)
        assert key not in seen
        seen.add(key)


def test_empty_device_list():
    edges = infer_relations([])
    assert edges == []


def test_sorted_by_kind_src_dst():
    devices = [
        mk(1, "192.168.1.1", type="router"),
        mk(2, "10.0.0.1", type="vm"),
        mk(3, "10.0.0.2", ports=[8006]),
    ]
    edges = infer_relations(devices, gateway_ip="192.168.1.1")
    # Device 3 is a normal device and gets a gateway edge
    # Sorted by (kind, src_id, dst_id): gateway edges first, then host-of
    sorted_edges = sorted(edges, key=lambda e: (e.kind, e.src_id, e.dst_id))
    assert sorted_edges == [
        Edge(2, 1, "gateway", "default-route", 1.0),
        Edge(3, 1, "gateway", "default-route", 1.0),
        Edge(2, 3, "host-of", "heuristic", 0.5),
    ]