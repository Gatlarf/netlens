import io
import json
import zipfile

import pytest

from app.plugins import registry
from app.plugins.example import build_example_zip
from app.plugins.registry import InstallError, discover, install, read_zip, uninstall
from tests.plugin_helpers import write_plugin

MANIFEST = {"id": "demo", "name": "Demo", "version": "1.0.0", "api_version": 1, "kind": "topology"}
GOOD_PY = "def test(config):\n    return {}\n\ndef fetch(config):\n    return {}\n"


def make_zip(files, prefix=""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(prefix + name, content)
    return buf.getvalue()


def good_files(**manifest):
    return {"plugin.json": json.dumps({**MANIFEST, **manifest}), "plugin.py": GOOD_PY}


def test_builtins_are_found_and_valid():
    found = discover(None)
    assert {"proxmox", "asus"} <= set(found)
    assert all(p.builtin and p.problem is None and p.manifest for p in found.values())
    assert found["proxmox"].manifest["kind"] == "hypervisor" and found["asus"].manifest["kind"] == "topology"


def test_user_plugins_are_discovered_and_broken_ones_are_reported(tmp_path):
    write_plugin(tmp_path, "good")
    broken = tmp_path / "plugins" / "broken"
    broken.mkdir()
    (broken / "plugin.json").write_text("{nope")
    wrong = write_plugin(tmp_path, "renamed")
    (wrong / "plugin.json").write_text(json.dumps({**MANIFEST, "id": "other"}))
    nopy = write_plugin(tmp_path, "nopy")
    (nopy / "plugin.py").unlink()
    found = discover(tmp_path)
    assert found["good"].problem is None and found["good"].builtin is False
    assert "plugin.json" in found["broken"].problem
    assert "folder is called" in found["renamed"].problem
    assert "plugin.py is missing" in found["nopy"].problem
    assert discover(tmp_path / "missing")  # no data dir yet: only the built-ins


def test_user_folder_cannot_shadow_a_builtin(tmp_path):
    write_plugin(tmp_path, "proxmox", manifest={"name": "Evil"})
    assert discover(tmp_path)["proxmox"].builtin is True


def test_install_from_zip_and_replace(tmp_path):
    result = install(tmp_path, make_zip(good_files()))
    assert result["manifest"]["id"] == "demo" and result["replaced"] is False and len(result["sha256"]) == 64
    assert (tmp_path / "plugins" / "demo" / "plugin.py").read_text() == GOOD_PY
    assert discover(tmp_path)["demo"].problem is None
    with pytest.raises(InstallError, match="already installed"):
        install(tmp_path, make_zip(good_files()))
    again = install(tmp_path, make_zip(good_files(version="2.0.0")), replace=True)
    assert again["replaced"] is True and discover(tmp_path)["demo"].manifest["version"] == "2.0.0"
    assert not any(p.name.startswith(".") for p in (tmp_path / "plugins").iterdir())  # no staging leftovers


def test_zip_with_a_single_top_folder_and_macos_junk(tmp_path):
    files = good_files()
    wrapped = make_zip({"demo/plugin.json": files["plugin.json"], "demo/plugin.py": files["plugin.py"], "__MACOSX/demo/._plugin.py": "x"})
    with pytest.raises(InstallError):
        read_zip(wrapped)  # two top-level entries: ambiguous
    wrapped = make_zip({"demo/plugin.json": files["plugin.json"], "demo/plugin.py": files["plugin.py"], "demo/helper.py": "X = 1"})
    got, manifest = read_zip(wrapped)
    assert set(got) == {"plugin.json", "plugin.py", "helper.py"} and manifest["id"] == "demo"


@pytest.mark.parametrize("files,message", [
    ({}, "empty"),
    ({"plugin.py": GOOD_PY}, "plugin.json not found"),
    ({"plugin.json": json.dumps(MANIFEST)}, "plugin.py not found"),
    ({"plugin.json": "{", "plugin.py": GOOD_PY}, "plugin.json"),
    ({"plugin.json": json.dumps({**MANIFEST, "kind": "x"}), "plugin.py": GOOD_PY}, "kind"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": "def fetch(config:"}, "syntax error"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": "def fetch(config):\n    return {}\n"}, "function test"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": "async def fetch(config):\n    return {}\ndef test(config):\n    return {}\n"}, "async"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY, "../evil.py": "x"}, "unsafe"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY, "/abs.py": "x"}, "unsafe"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY, ".hidden": "x"}, "not allowed"),
    ({"plugin.json": json.dumps(MANIFEST), "plugin.py": GOOD_PY, "a;b.py": "x"}, "not allowed"),
])
def test_bad_archives_are_refused(files, message):
    with pytest.raises(InstallError, match=message):
        read_zip(make_zip(files))


def test_not_a_zip_and_size_limits(monkeypatch):
    with pytest.raises(InstallError, match="not a zip"):
        read_zip(b"hello")
    monkeypatch.setattr(registry, "MAX_ZIP_BYTES", 10)
    with pytest.raises(InstallError, match="too large"):
        read_zip(make_zip(good_files()))
    monkeypatch.setattr(registry, "MAX_ZIP_BYTES", 10**6)
    monkeypatch.setattr(registry, "MAX_UNPACKED_BYTES", 10)
    with pytest.raises(InstallError, match="unpacked"):
        read_zip(make_zip(good_files()))
    monkeypatch.setattr(registry, "MAX_UNPACKED_BYTES", 10**6)
    monkeypatch.setattr(registry, "MAX_FILES", 1)
    with pytest.raises(InstallError, match="too many"):
        read_zip(make_zip(good_files()))


def test_symlinks_in_the_archive_are_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.json", json.dumps(MANIFEST))
        z.writestr("plugin.py", GOOD_PY)
        info = zipfile.ZipInfo("link.py")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    with pytest.raises(InstallError, match="links"):
        read_zip(buf.getvalue())


def test_builtin_ids_are_protected(tmp_path):
    with pytest.raises(InstallError, match="built-in"):
        install(tmp_path, make_zip(good_files(id="proxmox")))
    with pytest.raises(InstallError, match="built-in"):
        uninstall(tmp_path, "asus")


def test_uninstall(tmp_path):
    install(tmp_path, make_zip(good_files()))
    uninstall(tmp_path, "demo")
    assert "demo" not in discover(tmp_path)
    with pytest.raises(InstallError, match="no such"):
        uninstall(tmp_path, "demo")
    with pytest.raises(InstallError):
        uninstall(tmp_path, "../etc")


def test_the_downloadable_example_installs_cleanly(tmp_path):
    result = install(tmp_path, build_example_zip())
    assert result["manifest"]["id"] == "example-router"
