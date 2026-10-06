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