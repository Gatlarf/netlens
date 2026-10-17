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
