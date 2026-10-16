"""No plugin puts a server address into its diagnostic report (the report is meant to be pasted into public issues)."""

import importlib.util
from pathlib import Path

import pytest

PLUGINS = Path(__file__).resolve().parents[1] / "plugins"
IDS = sorted(p.parent.name for p in PLUGINS.glob("*/plugin.py") if "def _problem" in p.read_text())
TEXTS = ["cannot reach 192.168.0.5:8080: [Errno 111] Connection refused", "nas.home.lan:8006 did not answer properly: timed out", "cannot reach http://pve.example.com:8006/api: x",
         "10.0.0.7 answered HTTP 500 for /x", "router.lan refused the login"]


@pytest.mark.parametrize("pid", IDS)
def test_problem_text_has_no_address(pid):
    spec = importlib.util.spec_from_file_location(f"p_{pid.replace('-', '_')}", PLUGINS / pid / "plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module._problem.__code__.co_argcount == 2:           # the newer plugins take the server whose address is to be hidden
        out = module._problem(Exception(TEXTS[0]), type("S", (), {"id": "192.168.0.5:8080"})())
        assert "192.168" not in out and ":8080" not in out
        return
    for text in TEXTS:
        out = module._problem(Exception(text))
        for leak in ("192.168", "home.lan", "example.com", "10.0.0.7", "router.lan", ":8080", ":8006"):
            assert leak not in out, (pid, out)


def test_all_plugins_with_a_diagnostic_are_covered():
    assert len(IDS) >= 35
