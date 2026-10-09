"""Run with: pytest   (copy this folder, then replace the fake data in plugin.py with real calls)."""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import plugin  # noqa: E402


def test_test_returns_a_message():
    assert "message" in plugin.test({"host": "192.168.0.1"})


def test_a_missing_host_is_a_clear_error():
    try:
        plugin.fetch({"host": ""})
    except ValueError as exc:
        assert "address" in str(exc)
    else:
        raise AssertionError("expected an error")


def test_fetch_has_nodes_and_clients():
    out = plugin.fetch({"host": "192.168.0.1"})
    assert out["nodes"] and out["clients"]
    # tests/sample_output.json shows the shape Netlens expects. Validate real output with
    #   python <netlens checkout>/plugin-index/tools/check_plugin.py . --output tests/sample_output.json
