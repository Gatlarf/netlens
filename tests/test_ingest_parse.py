"""The payload parsers of the agent ingest: allow-list, plausibility, safe alphabet, and no crash on hostile input."""

from __future__ import annotations

import copy
import json
import random
import time

import pytest

from app.ingest import parse
from tests.ingest_helpers import otlp_doc

T = 1_800_000_000.0


def points_of(doc, state=None, now=T):
    resources, dropped = parse.otlp(doc)
    out = []
    for host, samples in resources:
        out += parse.otlp_points(samples, state if state is not None else {}, now)[0]
    return out


def test_cpu_needs_two_rounds_and_a_counter_reset_gives_nothing():
    state = {}
    assert [p for p in points_of(otlp_doc(T - 60, 1000, 2000), state) if p[0] == "cpu_pct"] == []
    cpu = [p for p in points_of(otlp_doc(T, 1090, 2100), state) if p[0] == "cpu_pct"]
    assert cpu and abs(cpu[0][2] - 10.0) < 1e-9                                      # 10 of 100 ticks busy
    assert [p for p in points_of(otlp_doc(T + 60, 5, 20), state, T + 60) if p[0] == "cpu_pct"] == []        # the machine restarted


def test_the_allow_list_and_the_alphabet():
    doc = otlp_doc(T, 1, 2)
    metrics = doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    names = {p[0] for p in points_of(doc)}
    assert "process.cpu.time" not in json.dumps(sorted(names))
    fs = [m for m in metrics if m["name"] == "system.filesystem.usage"][0]
    fs["sum"]["dataPoints"].append({"attributes": [{"key": "mountpoint", "value": {"stringValue": "/<script>alert(1)</script>"}}, {"key": "state", "value": {"stringValue": "used"}}, {"key": "type", "value": {"stringValue": "ext4"}}], "asInt": "9", "timeUnixNano": str(int(T * 1e9))})
    labels = {p[1] for p in points_of(doc) if p[0] == "disk_pct"}
    assert labels == {"/"}
    assert parse._label("C:\\") == "C:\\" and parse._label("/var/lib/data-1") and parse._label("a\nb") is None and parse._label("x" * 41) is None


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "1e999", True, None, [], {}])
def test_implausible_numbers_are_dropped(value):
    doc = otlp_doc(T, 1, 2)
    for m in doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]:
        for dp in m.get("gauge", m.get("sum"))["dataPoints"]:
            dp.pop("asInt", None)
            dp["asDouble"] = value
    out = points_of(doc)
    assert all(isinstance(p[2], float) and p[2] == p[2] and p[2] >= 0 for p in out)


def test_percentages_stay_between_0_and_100():
    doc = otlp_doc(T, 1, 2, used=10_000, free=1, fs_used=10**12, fs_free=1)
    for p in points_of(doc):
        if p[3] == "%":
            assert 0 <= p[2] <= 100


def test_too_much_is_refused():
    with pytest.raises(parse.ParseError):
        parse.otlp({"resourceMetrics": [{}] * (parse.MAX_RESOURCES + 1)})
    with pytest.raises(parse.ParseError):
        parse.otlp({"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "system.uptime", "gauge": {"dataPoints": [{"asDouble": 1}] * (parse.MAX_POINTS + 1)}}]}]}]})
    for bad in (None, 5, "x", [], {"resourceMetrics": "x"}):
        with pytest.raises(parse.ParseError):
            parse.otlp(bad)
    with pytest.raises(parse.ParseError):
        parse.telegraf([{}] * (parse.MAX_POINTS + 1))
    with pytest.raises(parse.ParseError):
        parse.telegraf("x")


def test_the_host_name_is_normalised_or_empty():
    assert parse._host("WEB01.Example.COM") == "web01.example.com"
    assert parse._host("evil name; drop table") == "" and parse._host("") == "" and parse._host(None) == ""


def test_telegraf_batches_and_single_objects():
    one = {"name": "mem", "tags": {"host": "A"}, "fields": {"used_percent": 33.0}, "timestamp": T}
    assert parse.telegraf(one) == [one] and parse.telegraf([one]) == [one] and parse.telegraf({"metrics": [one]}) == [one]
    assert parse.telegraf_points([one], {}, T)[0][0][:3] == ("mem_pct", "", 33.0)
    assert list(parse.telegraf_hosts([one, {"name": "x", "tags": {}, "fields": {}}]).keys()) == ["a", ""]
    ms = dict(one, timestamp=T * 1000)                                              # milliseconds are understood
    assert parse.telegraf_points([ms], {}, T)[0]


def test_garbage_does_not_crash_the_parsers():
    rnd = random.Random(int(__import__("os").environ.get("FUZZ_SEED", "7")))
    base = otlp_doc(T, 1000, 2000)
    atoms = [None, True, False, 0, -1, 2**70, 1e308, "x", "", "\x00", "💥", [], {}, [None], {"a": None}, "NaN", "9" * 400]

    def mutate(node, depth=0):
        if isinstance(node, dict) and node and rnd.random() < 0.7:
            k = rnd.choice(list(node))
            if rnd.random() < 0.3:
                del node[k]
            else:
                node[k] = mutate(node[k], depth + 1) if rnd.random() < 0.6 else rnd.choice(atoms)
        elif isinstance(node, list) and node and rnd.random() < 0.7:
            i = rnd.randrange(len(node))
            node[i] = mutate(node[i], depth + 1) if rnd.random() < 0.6 else rnd.choice(atoms)
        return node

    for _ in range(3000):
        doc = copy.deepcopy(base)
        for _ in range(rnd.randint(1, 6)):
            doc = mutate(doc)
        try:
            resources, _d = parse.otlp(doc)
            for _h, samples in resources:
                parse.otlp_points(samples, {}, T)
        except parse.ParseError:
            pass
    tele = [{"name": "cpu", "tags": {"cpu": "cpu-total", "host": "a"}, "fields": {"usage_idle": 1.0}, "timestamp": T},
            {"name": "disk", "tags": {"path": "/", "fstype": "xfs"}, "fields": {"used_percent": 5, "free": 9}, "timestamp": T}]
    for _ in range(3000):
        doc = copy.deepcopy(tele)
        for _ in range(rnd.randint(1, 5)):
            doc = mutate(doc)
        try:
            items = parse.telegraf(doc)
            parse.telegraf_points(items, {}, T)
            parse.telegraf_hosts(items)
        except parse.ParseError:
            pass
