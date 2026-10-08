import pytest

from app.db import connect, init_db
from app.hierarchy import (
    SOURCE_RANK,
    ancestors,
    build_hierarchy,
    children_map,
    descendants,
    hierarchy_payload,
    would_loop,
)


def dev(i, mode="auto", parent=None):
    return {"id": i, "parent_mode": mode, "parent_device_id": parent}


def rel(src, dst, kind, source="x", confidence=1.0):
    return {"src_id": src, "dst_id": dst, "kind": kind, "source": source, "confidence": confidence}


def parents(result):
    return {i: p.parent_id for i, p in result.items()}


def test_gateway_is_the_default_parent():
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(2, 1, "gateway", "default-route"), rel(3, 1, "gateway", "default-route")])
    assert parents(h) == {1: None, 2: 1, 3: 1}
    assert h[2].source == "gateway" and h[1].source == "none"


def test_proxmox_host_beats_the_gateway_for_guests():
    devices = [dev(1), dev(2), dev(3), dev(4)]  # 1 gateway, 2 Proxmox host, 3 and 4 guests
    relations = [
        rel(2, 1, "gateway"), rel(3, 1, "gateway"), rel(4, 1, "gateway"),
        rel(3, 2, "host-of", "plugin:proxmox"), rel(4, 2, "host-of", "plugin:proxmox"),
    ]
    h = build_hierarchy(devices, relations)
    assert parents(h) == {1: None, 2: 1, 3: 2, 4: 2}
    assert h[3].source == "hypervisor" and "proxmox" in h[3].reason
    assert descendants(h, 1) == {2, 3, 4} and ancestors(h, 4) == [2, 1]


def test_route_beats_gateway_and_chains_through_routers():
    devices = [dev(i) for i in range(1, 5)]  # 1 gateway, 2 and 3 routers, 4 a host behind them
    relations = [rel(4, 1, "gateway"), rel(4, 3, "route", "traceroute", 0.9), rel(3, 2, "route", "traceroute", 0.9), rel(2, 1, "gateway")]
    h = build_hierarchy(devices, relations)
    assert parents(h) == {1: None, 2: 1, 3: 2, 4: 3}
    assert h[4].source == "route"


def test_heuristic_hypervisor_guess_beats_route_and_gateway_but_not_proxmox():
    devices = [dev(1), dev(2), dev(3)]
    relations = [rel(3, 1, "gateway"), rel(3, 2, "host-of", "heuristic", 0.5)]
    assert parents(build_hierarchy(devices, relations))[3] == 2
    relations.append(rel(3, 1, "host-of", "plugin:proxmox"))
    h = build_hierarchy(devices, relations)
    assert h[3].parent_id == 1 and h[3].source == "hypervisor"


def test_uplink_sits_between_proxmox_and_the_heuristics():
    assert SOURCE_RANK["hypervisor"] < SOURCE_RANK["uplink"] < SOURCE_RANK["guess"] < SOURCE_RANK["route"] < SOURCE_RANK["gateway"]
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(3, 1, "gateway"), rel(3, 2, "uplink", "asus-mesh")])
    assert h[3].parent_id == 2 and h[3].source == "uplink" and "asus-mesh" in h[3].reason


def test_same_rank_prefers_higher_confidence_then_lower_id():
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(3, 1, "route", confidence=0.5), rel(3, 2, "route", confidence=0.9)])
    assert h[3].parent_id == 2
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(3, 2, "route"), rel(3, 1, "route")])
    assert h[3].parent_id == 1


def test_manual_and_service_links_do_not_define_a_parent():
    h = build_hierarchy([dev(1), dev(2)], [rel(2, 1, "manual", "manual"), rel(1, 2, "service")])
    assert parents(h) == {1: None, 2: None}


def test_user_choice_overrides_everything():
    devices = [dev(1), dev(2), dev(3, "device", 1)]
    relations = [rel(3, 2, "host-of", "plugin:proxmox"), rel(2, 1, "gateway")]
    h = build_hierarchy(devices, relations)
    assert h[3].parent_id == 1 and h[3].source == "manual" and h[3].locked is True


def test_user_can_make_a_device_top_level():
    h = build_hierarchy([dev(1), dev(2, "none")], [rel(2, 1, "gateway")])
    assert h[2].parent_id is None and h[2].source == "manual" and h[2].locked is True


def test_chosen_parent_that_no_longer_exists_falls_back_to_automatic():
    h = build_hierarchy([dev(1), dev(2, "device", 99)], [rel(2, 1, "gateway")])
    assert h[2].parent_id == 1 and h[2].source == "gateway"
    h = build_hierarchy([dev(1), dev(2, "device", None)], [rel(2, 1, "gateway")])
    assert h[2].parent_id == 1


def test_ignores_self_links_and_unknown_devices():
    h = build_hierarchy([dev(1), dev(2)], [rel(1, 1, "gateway"), rel(2, 99, "gateway"), rel(99, 1, "gateway")])
    assert parents(h) == {1: None, 2: None}


def _assert_forest(h):
    for dev_id in h:
        chain = ancestors(h, dev_id)
        assert dev_id not in chain and len(chain) == len(set(chain))


def test_loops_in_the_relations_never_form_cycles():
    # a and b claim each other as route parent; c sits behind a
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(1, 2, "route"), rel(2, 1, "route"), rel(3, 1, "route")])
    _assert_forest(h)
    assert sum(1 for p in h.values() if p.parent_id is not None) == 2  # one of the two links was dropped
    assert h[3].parent_id == 1


def test_a_stronger_link_wins_the_loop_and_the_weaker_falls_back():
    # 1 runs on 2 (Proxmox, strong); 2's only other idea is that it is behind 1 via a route (weaker)
    h = build_hierarchy([dev(1), dev(2), dev(3)], [rel(1, 2, "host-of", "plugin:proxmox"), rel(2, 1, "route"), rel(2, 3, "gateway")])
    _assert_forest(h)
    assert h[1].parent_id == 2 and h[1].source == "hypervisor"
    assert h[2].parent_id == 3 and h[2].source == "gateway"  # the next-best candidate was used


def test_two_manual_choices_cannot_form_a_loop():
    h = build_hierarchy([dev(1, "device", 2), dev(2, "device", 1)], [])
    _assert_forest(h)
    assert sum(1 for p in h.values() if p.parent_id is not None) == 1


def test_helpers():
    h = build_hierarchy([dev(1), dev(2), dev(3), dev(4)], [rel(2, 1, "gateway"), rel(3, 2, "route"), rel(4, 2, "route")])
    assert children_map(h) == {1: [2], 2: [3, 4]}
    assert ancestors(h, 3) == [2, 1] and ancestors(h, 1) == []
    assert descendants(h, 1) == {2, 3, 4} and descendants(h, 3) == set()
    assert would_loop(h, 1, 3) is True      # 3 is below 1: making it 1's parent loops
    assert would_loop(h, 3, 3) is True
    assert would_loop(h, 3, 4) is False     # siblings are fine
    assert would_loop(h, 4, 1) is False


def test_payload_from_the_database():
    conn = connect(":memory:")
    init_db(conn)
    now = "2026-03-10T10:00:00Z"
    for i, (mac, ip, name) in enumerate([("aa:00:00:00:00:01", "10.0.0.1", "router"), ("aa:00:00:00:00:02", "10.0.0.5", "pve"), ("aa:00:00:00:00:03", "10.0.0.6", None)], 1):
        conn.execute(
            "INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (i, mac, ip, name, now, now),
        )
    conn.executemany(
        "INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, ?, ?, 1.0, ?)",
        [(2, 1, "gateway", "default-route", 0), (3, 2, "host-of", "plugin:proxmox", 0), (3, 1, "gateway", "default-route", 0), (2, 3, "route", "hidden", -1)],
    )
    conn.commit()
    payload = hierarchy_payload(conn)
    by_id = {n["id"]: n for n in payload["nodes"]}
    assert payload["roots"] == [1] and payload["stats"] == {"devices": 3, "with_parent": 2, "manual": 0, "max_depth": 2}
    assert (by_id[3]["parent_id"], by_id[3]["source"], by_id[3]["depth"], by_id[3]["name"]) == (2, "hypervisor", 2, "10.0.0.6")
    assert (by_id[1]["children"], by_id[1]["descendants"]) == (1, 2)  # the hidden relation (manual = -1) was ignored
    assert "hypervisor" in payload["sources"]
