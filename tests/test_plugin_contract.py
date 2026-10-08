import pytest

from app.plugins.contract import ContractError, clean_config, default_config, missing_required, validate_manifest, validate_output

BASE = {"id": "my-router", "name": "My router", "version": "1.2.0", "api_version": 1, "kind": "topology"}


def manifest(**extra):
    return validate_manifest({**BASE, **extra})


def test_minimal_manifest_gets_defaults():
    m = manifest()
    assert m["timeout"] == 60 and m["config"] == [] and m["description"] == "" and m["kind"] == "topology"


@pytest.mark.parametrize("change,message", [
    ({"id": "Bad Id"}, "id"),
    ({"id": "x"}, "id"),
    ({"api_version": 2}, "api_version"),
    ({"kind": "toaster"}, "kind"),
    ({"version": "latest"}, "version"),
    ({"name": ""}, "name"),
    ({"timeout": 2}, "timeout"),
    ({"timeout": True}, "timeout"),
    ({"config": "no"}, "config"),
    ({"config": [{"key": "a", "type": "color"}]}, "type"),
    ({"config": [{"key": "A!"}]}, "key"),
    ({"config": [{"key": "a"}, {"key": "a"}]}, "used twice"),
    ({"config": [{"key": "s", "type": "select"}]}, "option"),
    ({"config": [{"key": "s", "type": "select", "options": ["a"], "default": "z"}]}, "default"),
    ({"config": [{"key": "n", "type": "number", "default": "x"}]}, "default"),
])
def test_invalid_manifests_say_what_is_wrong(change, message):
    with pytest.raises(ContractError) as exc:
        manifest(**change)
    assert message in str(exc.value)


def test_manifest_must_be_an_object():
    with pytest.raises(ContractError):
        validate_manifest([])


FIELDS = [
    {"key": "host", "type": "text", "label": "Host", "required": True},
    {"key": "pw", "type": "password"},
    {"key": "tls", "type": "bool", "default": True},
    {"key": "port", "type": "number", "default": 80, "min": 1, "max": 65535},
    {"key": "mode", "type": "select", "options": ["a", {"value": "b", "label": "Bee"}]},
]


def test_config_defaults_and_cleaning():
    m = manifest(config=FIELDS)
    assert default_config(m) == {"host": "", "pw": "", "tls": True, "port": 80, "mode": "a"}
    assert next(f for f in m["config"] if f["key"] == "pw")["secret"] is True
    cleaned = clean_config(m, {"host": " r.lan ", "tls": 0, "port": 8080, "mode": "b", "junk": 1})
    assert cleaned == {"host": "r.lan", "pw": "", "tls": False, "port": 8080, "mode": "b"}
    assert missing_required(m, {"host": ""}) == ["Host"] and missing_required(m, {"host": "x"}) == []
    for bad in ({"port": 0}, {"port": "80"}, {"mode": "z"}, {"host": 5}):
        with pytest.raises(ContractError):
            clean_config(m, bad)


# ---------------------------------------------------------------- hypervisor output
HV = {
    "hosts": [{"id": "pve1", "name": "pve1", "ip": "10.0.0.5"}],
    "guests": [{"id": 100, "name": "web", "kind": "lxc", "host_id": "pve1", "status": "running", "macs": ["AA-BB-CC-DD-EE-FF"], "ips": ["10.0.0.64"]}],
}


def test_hypervisor_output_is_normalised():
    out = validate_output("hypervisor", HV)
    assert out["hosts"][0] == {"id": "pve1", "name": "pve1", "ip": "10.0.0.5", "mac": None, "online": True}
    assert out["guests"][0]["id"] == "100" and out["guests"][0]["macs"] == ["aa:bb:cc:dd:ee:ff"]
    assert validate_output("hypervisor", {}) == {"hosts": [], "guests": []}


@pytest.mark.parametrize("mutate,message", [
    (lambda d: d["guests"][0].update(host_id="nope"), "guests[0].host_id"),
    (lambda d: d["guests"][0].update(macs=["12:34"]), "macs[0]"),
    (lambda d: d["guests"][0].update(ips=["not-an-ip"]), "ips[0]"),
    (lambda d: d["guests"][0].update(ips=["::1"]), "IPv4"),
    (lambda d: d["guests"].append(dict(d["guests"][0])), "used twice"),
    (lambda d: d["hosts"][0].pop("id"), "hosts[0].id"),
    (lambda d: d.update(hosts="x"), "hosts"),
    (lambda d: d["guests"][0].update(name=5), "guests[0].name"),
])
def test_hypervisor_errors_point_at_the_field(mutate, message):
    import copy

    data = copy.deepcopy(HV)
    mutate(data)
    with pytest.raises(ContractError) as exc:
        validate_output("hypervisor", data)
    assert message in str(exc.value)


# ---------------------------------------------------------------- topology output
TOPO = {
    "nodes": [
        {"mac": "AA:00:00:00:00:01", "ip": "10.0.0.1", "name": "Router", "role": "gateway"},
        {"mac": "aa:00:00:00:00:02", "name": "AP", "role": "ap", "parent_mac": "aa:00:00:00:00:01", "macs": ["aa:00:00:00:00:12"]},
    ],
    "clients": [{"mac": "11:00:00:00:00:01", "ip": "10.0.0.50", "node_mac": "aa:00:00:00:00:12", "medium": "wifi", "band": "5 GHz"}],
}


def test_topology_output_is_normalised():
    out = validate_output("topology", TOPO)
    assert out["nodes"][0]["mac"] == "aa:00:00:00:00:01" and out["nodes"][1]["macs"] == ["aa:00:00:00:00:02", "aa:00:00:00:00:12"]
    assert out["clients"][0]["name"] is None and out["clients"][0]["node_mac"] == "aa:00:00:00:00:12"


@pytest.mark.parametrize("mutate,message", [
    (lambda d: d["nodes"][1].update(role="toaster"), "role"),
    (lambda d: d["nodes"][1].update(parent_mac="aa:00:00:00:00:99"), "parent_mac"),
    (lambda d: d["clients"][0].update(node_mac="aa:00:00:00:00:99"), "node_mac"),
    (lambda d: d["clients"][0].update(medium="smoke"), "medium"),
    (lambda d: d["clients"][0].pop("mac"), "clients[0].mac"),
    (lambda d: d["nodes"][1].update(role="gateway"), "at most one"),
    (lambda d: d["nodes"].append(dict(d["nodes"][0])), "used twice"),
])
def test_topology_errors_point_at_the_field(mutate, message):
    import copy

    data = copy.deepcopy(TOPO)
    mutate(data)
    with pytest.raises(ContractError) as exc:
        validate_output("topology", data)
    assert message in str(exc.value)


def test_too_many_entries_and_unknown_kind():
    with pytest.raises(ContractError):
        validate_output("topology", {"clients": [{}] * 5001})
    with pytest.raises(ContractError):
        validate_output("printer", {})
