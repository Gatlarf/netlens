import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def default_auth_header(monkeypatch):
    original_init = TestClient.__init__

    def patched_init(self, *args, headers=None, **kwargs):
        merged = {"Authorization": "Bearer t"}
        merged.update(headers or {})
        original_init(self, *args, headers=merged, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", patched_init)

@pytest.fixture(autouse=True)
def unlimited_sites(request, monkeypatch):
    """The tests of remote sites add several of them; the licence limit has its own tests (marker `real_licence`)."""
    if request.node.get_closest_marker("real_licence"):
        return
    from app import licence

    monkeypatch.setattr(licence, "site_limit", lambda conn: None)


@pytest.fixture(autouse=True)
def shipped_plugins(request, tmp_path_factory, monkeypatch):
    """Netlens ships no plugin inside the application any more. Many tests need a hypervisor and a topology plugin that are always there, so
    Proxmox and the ASUS router from plugins/ are presented as the shipped ("built-in") ones, unless the test is about the real, empty set."""
    if request.node.get_closest_marker("no_shipped_plugins"):
        return
    from pathlib import Path

    from app.plugins import registry

    folder = tmp_path_factory.mktemp("shipped")
    for pid in ("proxmox", "asus"):
        (folder / pid).symlink_to(Path(__file__).resolve().parents[1] / "plugins" / pid, target_is_directory=True)
    monkeypatch.setattr(registry, "BUILTIN_DIR", folder)
