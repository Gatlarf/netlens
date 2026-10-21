import importlib

import app.version as version


def _reload(monkeypatch, tmp_path, baked, env):
    monkeypatch.setattr("pathlib.Path.read_text", lambda self, *a, **k: baked if self.name == "BUILD_VERSION" else (_ for _ in ()).throw(OSError()))
    if env is None:
        monkeypatch.delenv("NETLENS_VERSION", raising=False)
    else:
        monkeypatch.setenv("NETLENS_VERSION", env)
    return importlib.reload(version)


def test_the_file_in_the_image_wins_over_a_pinned_variable(monkeypatch, tmp_path):
    v = _reload(monkeypatch, tmp_path, "0.4.137", "0.4.100")
    assert v.VERSION == "0.4.137" and v.STALE_ENV is True


def test_variable_is_used_without_a_file_or_for_dev_builds(monkeypatch, tmp_path):
    assert _reload(monkeypatch, tmp_path, "", "1.2.3").VERSION == "1.2.3"
    v = _reload(monkeypatch, tmp_path, "dev", "1.2.3")
    assert v.VERSION == "1.2.3" and v.STALE_ENV is False
    assert _reload(monkeypatch, tmp_path, "", None).VERSION == "0.2.0-dev"


def teardown_module(module):
    importlib.reload(version)
