"""The DNS plan: what Netlens would add or change, and above all what it must never touch."""

import pytest

from app.dns import names
from app.dns.plan import DnsDevice, DnsSettings, build_plan, parse_networks

NOW = "2026-10-10T12:00:00Z"
ZONE, REV = "home.example.com", "0.168.192.in-addr.arpa"


def snap(records=(), writable=True, reverse=True, rev_writable=True):
    zones = [{"name": ZONE, "kind": "forward", "writable": writable}]
    if reverse:
        zones.append({"name": REV, "kind": "reverse", "writable": rev_writable})
    full = [{"zone": r[0], "name": r[1], "type": r[2], "value": r[3], "ttl": None, "managed": r[4] if len(r) > 4 else False, "comment": ""} for r in records]
    return {"zones": zones, "records": full, "server": "dns1"}


def settings(**kw):
    return DnsSettings(networks=parse_networks(f"192.168.0.0/24 = {ZONE}"), grace_hours=0, **kw)


def dev(id=1, ip="192.168.0.10", **kw):
    kw.setdefault("hostname", f"host{id}.{ZONE}")
    return DnsDevice(id=id, ip=ip, **kw)


def plan(devices, snapshot=None, st=None, **kw):
    return build_plan(devices, snapshot or snap(), st or settings(), NOW, **kw)


def only(result, device_id):
    return next(i for i in result["items"] if i["device_id"] == device_id)


def A(name, ip, managed=False):
    return (ZONE, f"{name}.{ZONE}", "A", ip, managed)


def PTR(ip, name, managed=False):
    return (REV, names.reverse_name(ip), "PTR", f"{name}.{ZONE}", managed)


# ---------------------------------------------------------------- the basics
def test_networks_and_zones():
    nets = parse_networks("192.168.0.0/24 = home.example.com\n10.0.0.0/8 = lab.example.org.\n# comment")
    assert [(str(n), z) for n, z in nets] == [("192.168.0.0/24", "home.example.com"), ("10.0.0.0/8", "lab.example.org")]
    assert parse_networks("home.example.com")[0][1] == "home.example.com"          # one zone for everything
    with pytest.raises(ValueError, match="not a network"):
        parse_networks("lan = home.example.com")


def test_a_missing_device_gets_an_a_record_and_a_reverse_record():
    r = plan([dev(1, hostname="Printer.home.example.com")])
    item = only(r, 1)
    assert item["state"] == "add" and item["name"] == f"printer.{ZONE}"
    kinds = [(c["action"], c["type"], c["name"], c["value"]) for c in item["changes"]]
    assert kinds == [("add", "A", f"printer.{ZONE}", "192.168.0.10"), ("add", "PTR", "10.0.168.192.in-addr.arpa", f"printer.{ZONE}")]
    assert all(c["comment"] == "managed by Netlens" for c in item["changes"])


def test_devices_in_networks_without_a_zone_are_not_listed():
    assert plan([dev(1, ip="10.9.9.9")])["items"] == []


def test_names_come_from_the_override_then_hostname_then_name_then_a_generated_one():
    d = [dev(1, dns_name="My NAS", hostname="x1"), dev(2, hostname=f"pc2.{ZONE}", custom_name="Bert PC", ip="192.168.0.12"),
         dev(3, hostname=None, custom_name="Living room TV", ip="192.168.0.13"),
         dev(4, hostname=None, type="tv", vendor="Samsung Electronics Co., Ltd.", mac="aa:bb:cc:00:a1:b2", ip="192.168.0.14")]
    r = plan(d)
    assert [only(r, i)["name"].split(".")[0] for i in (1, 2, 3, 4)] == ["my-nas", "pc2", "living-room-tv", "tv-samsung-a1b2"]
    assert r["auto_names"] == {4: "tv-samsung-a1b2"}


def test_a_stored_generated_name_stays_even_when_type_or_vendor_change():
    d = dev(4, hostname=None, type="speaker", vendor="Sonos", mac="aa:bb:cc:00:a1:b2", auto_name="tv-samsung-a1b2")
    assert only(plan([d]), 4)["name"] == f"tv-samsung-a1b2.{ZONE}"


def test_two_devices_wanting_the_same_name_get_a_suffix_and_the_owner_keeps_it():
    snapshot = snap([A("tv", "192.168.0.11", True), PTR("192.168.0.11", "tv", True)])
    r = plan([dev(1, hostname="tv", ip="192.168.0.10"), dev(2, hostname="tv", ip="192.168.0.11")], snapshot)
    assert only(r, 2)["state"] == "ok" and only(r, 2)["name"] == f"tv.{ZONE}"       # it already owns the record
    assert only(r, 1)["name"] == f"tv-2.{ZONE}" and only(r, 1)["state"] == "add"


def test_an_invalid_user_name_is_refused_not_silently_replaced():
    assert only(plan([dev(1, dns_name="!!!")]), 1)["state"] == "skip"


# ---------------------------------------------------------------- Netlens' own records
def test_everything_in_place_means_nothing_to_do():
    r = plan([dev(1, hostname="nas")], snap([A("nas", "192.168.0.10", True), PTR("192.168.0.10", "nas", True)]))
    assert only(r, 1)["state"] == "ok" and r["counts"] == {"ok": 1}


def test_a_changed_address_updates_the_record_it_made_and_its_reverse_record():
    snapshot = snap([A("laptop", "192.168.0.99", True), PTR("192.168.0.99", "laptop", True)])
    item = only(plan([dev(1, hostname="laptop", ip="192.168.0.10")], snapshot), 1)
    assert item["state"] == "update"
    assert [(c["action"], c["type"], c["old_value"], c["value"]) for c in item["changes"]] == [("update", "A", "192.168.0.99", "192.168.0.10"), ("add", "PTR", None, f"laptop.{ZONE}")]


def test_a_missing_reverse_record_alone_is_an_update():
    item = only(plan([dev(1, hostname="nas")], snap([A("nas", "192.168.0.10", True)])), 1)
    assert item["state"] == "update" and [c["type"] for c in item["changes"]] == ["PTR"]


def test_records_remembered_as_written_by_netlens_count_even_without_a_marker():
    snapshot = snap([A("nas", "192.168.0.10")])
    r = plan([dev(1, hostname="nas")], snapshot, tracked=frozenset({(ZONE, f"nas.{ZONE}", "A", "192.168.0.10")}))
    assert only(r, 1)["state"] == "update"      # ours, correct; only the reverse record is missing


def test_leftover_records_are_listed_and_only_removed_when_removal_is_on():
    snapshot = snap([A("gone", "192.168.0.50", True), PTR("192.168.0.50", "gone", True)])
    listed = plan([], snapshot)
    assert {i["state"] for i in listed["items"]} == {"orphan"} and all(not i["changes"] for i in listed["items"])
    removed = plan([], snapshot, settings(remove=True))
    assert {i["state"] for i in removed["items"]} == {"delete"} and all(i["changes"][0]["action"] == "delete" for i in removed["items"])


# ---------------------------------------------------------------- other people's records are never touched
def test_a_record_someone_else_made_with_the_same_address_is_left_alone():
    r = plan([dev(1, hostname="desktop-abc")], snap([A("desktop-abc", "192.168.0.10")]))
    item = only(r, 1)
    assert item["state"] == "self" and item["changes"] == []


def test_a_record_with_a_different_address_is_a_conflict_and_never_overwritten():
    item = only(plan([dev(1, hostname="desktop-abc")], snap([A("desktop-abc", "192.168.0.77")])), 1)
    assert item["state"] == "conflict" and item["changes"] == [] and "192.168.0.77" in item["reason"]
    forced = only(plan([dev(1, hostname="desktop-abc", dns_mode="always")], snap([A("desktop-abc", "192.168.0.77")])), 1)
    assert forced["state"] == "conflict" and forced["changes"] == []              # "always" does not mean "overwrite"


def test_an_address_that_already_has_a_name_is_registered_even_under_another_name():
    # the Windows machine registered itself as desktop-abc; in Netlens it is called "Bert PC"
    d = dev(1, hostname=None, custom_name="Bert PC")
    for records in (snap([A("desktop-abc", "192.168.0.10")]), snap([PTR("192.168.0.10", "desktop-abc")])):
        item = only(plan([d], records), 1)
        assert item["state"] == "self" and "desktop-abc" in item["reason"] and item["changes"] == []


def test_a_foreign_reverse_record_is_never_replaced_but_the_forward_record_is_still_added():
    r = plan([dev(1, hostname="nas")], snap([PTR("192.168.0.10", "other", False)]))
    assert only(r, 1)["state"] == "self"      # the address belongs to "other" already: nothing to register


def test_a_cname_on_the_name_is_a_conflict():
    snapshot = snap([(ZONE, f"nas.{ZONE}", "CNAME", "server.home.example.com", False)])
    assert only(plan([dev(1, hostname="nas")], snapshot), 1)["state"] == "conflict"


def test_when_a_client_overwrites_our_record_with_its_own_we_step_back():
    # our record is gone (the client replaced it): a foreign record with the right address -> "registers itself"
    assert only(plan([dev(1, hostname="pc")], snap([A("pc", "192.168.0.10", False)])), 1)["state"] == "self"


# ---------------------------------------------------------------- windows, grace, known devices
def test_windows_machines_are_skipped_unless_set_to_always():
    skipped = only(plan([dev(1, windows=True)]), 1)
    assert skipped["state"] == "skip" and "Windows registers itself" in skipped["reason"]
    assert only(plan([dev(1, windows=True, dns_mode="always")]), 1)["state"] == "add"
    assert only(plan([dev(1, windows=True)], st=settings(skip_windows=False)), 1)["state"] == "add"


def test_grace_period_gives_clients_time_to_register_themselves():
    st = DnsSettings(networks=parse_networks(ZONE), grace_hours=2)
    first = build_plan([dev(1)], snap(), st, NOW)
    assert only(first, 1)["state"] == "wait" and first["first_missing"] == {1: NOW}
    later = build_plan([dev(1, first_missing="2026-10-10T10:30:00Z")], snap(), st, NOW)     # 1.5 h
    assert only(later, 1)["state"] == "wait" and "0.5 h" in only(later, 1)["reason"]
    ready = build_plan([dev(1, first_missing="2026-10-10T09:00:00Z")], snap(), st, NOW)     # 3 h
    assert only(ready, 1)["state"] == "add"
    registered = build_plan([dev(1, first_missing="2026-10-10T09:00:00Z")], snap([A("host1", "192.168.0.10")]), st, NOW)
    assert only(registered, 1)["state"] == "self" and registered["first_missing"] == {1: None}   # it did register itself: the clock is reset
    assert only(build_plan([dev(1, dns_mode="always")], snap(), st, NOW), 1)["state"] == "add"     # always: no waiting


def test_only_known_devices_are_registered():
    assert only(plan([dev(1, trusted=False)]), 1)["state"] == "skip"
    assert only(plan([dev(1, trusted=False)], st=settings(only_known=False)), 1)["state"] == "add"
    assert only(plan([dev(1, trusted=False, dns_mode="always")]), 1)["state"] == "add"


def test_never_and_long_gone_devices():
    assert only(plan([dev(1, dns_mode="never")]), 1)["state"] == "skip"
    old = only(plan([dev(1, last_seen="2026-09-01T00:00:00Z")]), 1)
    assert old["state"] == "skip" and "not seen" in old["reason"]
    assert only(plan([dev(1, last_seen="2026-10-09T00:00:00Z")]), 1)["state"] == "add"


# ---------------------------------------------------------------- the server's side
def test_missing_or_read_only_zones_and_missing_reverse_zones():
    assert only(plan([dev(1)], snap(writable=False)), 1)["state"] == "skip"
    no_reverse = only(plan([dev(1)], snap(reverse=False)), 1)
    assert no_reverse["state"] == "add" and [c["type"] for c in no_reverse["changes"]] == ["A"]
    read_only_reverse = only(plan([dev(1)], snap(rev_writable=False)), 1)
    assert [c["type"] for c in read_only_reverse["changes"]] == ["A"]
    missing_zone = build_plan([dev(1)], {"zones": [], "records": []}, settings(), NOW)
    assert only(missing_zone, 1)["state"] == "skip" and "does not exist" in only(missing_zone, 1)["reason"]


def test_several_zones_and_the_most_specific_network_wins():
    st = DnsSettings(networks=parse_networks("192.168.0.0/16 = a.example.com\n192.168.0.0/24 = home.example.com"), grace_hours=0)
    assert [z for _, z in st.networks][0] == "home.example.com"
    snapshot = {"zones": [{"name": "home.example.com", "kind": "forward", "writable": True}, {"name": "a.example.com", "kind": "forward", "writable": True}], "records": []}
    r = build_plan([dev(1, ip="192.168.0.5"), dev(2, ip="192.168.7.5")], snapshot, st, NOW)
    assert only(r, 1)["zone"] == "home.example.com" and only(r, 2)["zone"] == "a.example.com"


def test_change_ids_are_unique_and_stable():
    r1 = plan([dev(1), dev(2, ip="192.168.0.11")])
    r2 = plan([dev(2, ip="192.168.0.11"), dev(1)])
    ids = [c["id"] for i in r1["items"] for c in i["changes"]]
    assert len(ids) == len(set(ids)) == 4 and ids == [c["id"] for i in r2["items"] for c in i["changes"]]


# ----------------------------------------------------------------------------- containers that share their host's address
from app.dns.plan import DnsAlias


def alias_plan(records=(), aliases=None, st=None, devices=None):
    aliases = aliases if aliases is not None else [DnsAlias(key="1-web", label="web", host_id=1, host_ip="192.168.0.10")]
    return build_plan(devices or [dev(1, hostname="dockerhost")], snap(records), st or settings(register_containers=True), NOW, aliases=aliases)


def alias_item(result, label="web"):
    return next(i for i in result["items"] if i["id"].startswith("c:") and i["name"] == f"{label}.{ZONE}")


def test_a_container_alias_is_a_cname_to_its_registered_host():
    item = alias_item(alias_plan())
    assert item["state"] == "add" and item["device_id"] is None
    assert [(c["type"], c["name"], c["value"]) for c in item["changes"]] == [("CNAME", f"web.{ZONE}", f"dockerhost.{ZONE}")]


def test_aliases_are_off_by_default():
    result = build_plan([dev(1, hostname="dockerhost")], snap(), settings(), NOW, aliases=[DnsAlias(key="1-web", label="web", host_id=1, host_ip="192.168.0.10")])
    assert not any(i["id"].startswith("c:") for i in result["items"])


def test_an_alias_waits_for_its_host_to_be_registered():
    result = alias_plan(devices=[dev(1, hostname="dockerhost", trusted=False)])
    assert alias_item(result)["state"] == "skip" and "host is not registered" in alias_item(result)["reason"]


def test_an_existing_foreign_name_is_a_conflict_and_never_touched():
    for existing in ((ZONE, f"web.{ZONE}", "A", "192.168.0.99"), (ZONE, f"web.{ZONE}", "CNAME", "other.example.com")):
        item = alias_item(alias_plan([existing]))
        assert item["state"] == "conflict" and item["changes"] == []


def test_a_name_used_by_a_device_is_a_conflict():
    result = alias_plan(aliases=[DnsAlias(key="1-dockerhost", label="dockerhost", host_id=1, host_ip="192.168.0.10")])
    assert alias_item(result, "dockerhost")["state"] == "conflict"


def test_our_alias_is_ok_updated_when_the_host_is_renamed_and_orphaned_when_gone():
    ours = (ZONE, f"web.{ZONE}", "CNAME", f"dockerhost.{ZONE}", True)
    assert alias_item(alias_plan([ours]))["state"] == "ok"
    moved = alias_plan([(ZONE, f"web.{ZONE}", "CNAME", f"oldname.{ZONE}", True)])
    item = alias_item(moved)
    assert item["state"] == "update" and item["changes"][0]["old_value"] == f"oldname.{ZONE}" and item["changes"][0]["value"] == f"dockerhost.{ZONE}"
    gone = alias_plan([ours], aliases=[])
    assert any(i["state"] == "orphan" and i["name"] == f"web.{ZONE}" for i in gone["items"])
