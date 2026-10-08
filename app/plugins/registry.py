"""Finding, installing and removing plugins.

Built-in plugins live inside the application (app/plugins/builtin/<id>/); uploaded ones in
<data dir>/plugins/<id>/ so they survive container updates.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.plugins.contract import ContractError, validate_manifest

BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"
MAX_ZIP_BYTES = 2 * 1024 * 1024
MAX_UNPACKED_BYTES = 8 * 1024 * 1024
MAX_FILES = 200
ALLOWED_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\- ]*$")


class InstallError(ValueError):
    """The uploaded file cannot be installed as a plugin."""


@dataclass
class Plugin:
    id: str
    path: Path
    builtin: bool
    manifest: dict | None
    problem: str | None = None

    @property
    def name(self) -> str:
        return self.manifest["name"] if self.manifest else self.id


def _read_plugin(path: Path, builtin: bool) -> Plugin:
    plugin_id = path.name
    try:
        manifest = validate_manifest(json.loads((path / "plugin.json").read_text(encoding="utf-8")))
    except FileNotFoundError:
        return Plugin(plugin_id, path, builtin, None, "plugin.json is missing")
    except (ValueError, OSError) as exc:  # includes ContractError and bad JSON
        return Plugin(plugin_id, path, builtin, None, f"plugin.json: {exc}")
    if manifest["id"] != plugin_id:
        return Plugin(plugin_id, path, builtin, None, f"the folder is called {plugin_id!r} but plugin.json says id {manifest['id']!r}")
    if not (path / "plugin.py").is_file():
        return Plugin(plugin_id, path, builtin, manifest, "plugin.py is missing")
    return Plugin(plugin_id, path, builtin, manifest)


def discover(data_dir: Path | str | None) -> dict[str, Plugin]:
    """All plugins by id (built-ins first; an uploaded plugin can never replace a built-in one)."""
    found: dict[str, Plugin] = {}
    for path in sorted(BUILTIN_DIR.iterdir()):
        if path.is_dir() and (path / "plugin.json").exists():
            found[path.name] = _read_plugin(path, True)
    user_dir = Path(data_dir) / "plugins" if data_dir else None
    if user_dir and user_dir.is_dir():
        for path in sorted(user_dir.iterdir()):
            if path.is_dir() and path.name not in found:
                found[path.name] = _read_plugin(path, False)
    return found


# ----------------------------------------------------------------------------- install
def _check_syntax(source: str) -> None:
    """Make sure plugin.py parses and defines fetch(config) and test(config); the code is not run."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise InstallError(f"plugin.py has a syntax error on line {exc.lineno}: {exc.msg}") from exc
    functions = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in ("fetch", "test"):
        if name not in functions:
            raise InstallError(f"plugin.py must define a top-level function {name}(config)")
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name in ("fetch", "test"):
            raise InstallError(f"{node.name}(config) must be a normal function, not async")


def read_zip(data: bytes) -> tuple[dict[str, bytes], dict]:
    """Validate an uploaded plugin archive without running anything. Returns (files, manifest)."""
    if len(data) > MAX_ZIP_BYTES:
        raise InstallError(f"the file is too large (max {MAX_ZIP_BYTES // 1024 // 1024} MB)")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InstallError("this is not a zip file") from exc
    infos = [i for i in archive.infolist() if not i.is_dir()]
    if not infos:
        raise InstallError("the zip file is empty")
    if len(infos) > MAX_FILES:
        raise InstallError(f"too many files (max {MAX_FILES})")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
        raise InstallError("the unpacked plugin is too large")

    names = []
    for info in infos:
        if stat.S_ISLNK(info.external_attr >> 16):
            raise InstallError(f"{info.filename}: links are not allowed")
        parts = info.filename.replace("\\", "/").split("/")
        if info.filename.startswith(("/", "\\")) or ".." in parts or ":" in parts[0]:
            raise InstallError(f"{info.filename}: unsafe path")
        names.append(parts)
    # the files are either at the top level or all inside one folder
    prefix = ""
    if not any(p == ["plugin.json"] for p in names):
        tops = {p[0] for p in names}
        if len(tops) == 1 and all(len(p) > 1 for p in names):
            prefix = next(iter(tops)) + "/"
    files: dict[str, bytes] = {}
    for info, parts in zip(infos, names):
        rel = "/".join(parts)[len(prefix):]
        if not rel or any(part.startswith(".") or not ALLOWED_NAME.match(part) for part in rel.split("/")):
            if rel.startswith("__MACOSX/") or rel.split("/")[-1] == ".DS_Store":
                continue
            raise InstallError(f"{info.filename}: this file name is not allowed")
        files[rel] = archive.read(info)
    if "plugin.json" not in files:
        raise InstallError("plugin.json not found (it must be at the top of the zip or in its single folder)")
    if "plugin.py" not in files:
        raise InstallError("plugin.py not found")
    try:
        manifest = validate_manifest(json.loads(files["plugin.json"].decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InstallError(f"plugin.json: {exc}") from exc
    try:
        _check_syntax(files["plugin.py"].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InstallError("plugin.py must be UTF-8 text") from exc
    return files, manifest


def install(data_dir: Path | str, data: bytes, *, replace: bool = False) -> dict[str, Any]:
    """Install an uploaded plugin; returns {"manifest", "sha256", "replaced"}."""
    files, manifest = read_zip(data)
    plugin_id = manifest["id"]
    if (BUILTIN_DIR / plugin_id).exists():
        raise InstallError(f"{plugin_id!r} is the id of a built-in plugin; choose another id")
    target = Path(data_dir) / "plugins" / plugin_id
    exists = target.exists()
    if exists and not replace:
        raise InstallError(f"a plugin with the id {plugin_id!r} is already installed (upload again to replace it)")
    staging = target.with_name(f".{plugin_id}.new")
    shutil.rmtree(staging, ignore_errors=True)
    for rel, content in files.items():
        out = staging / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(content)
    if exists:
        shutil.rmtree(target)
    staging.rename(target)
    return {"manifest": manifest, "sha256": hashlib.sha256(data).hexdigest(), "replaced": exists}


def uninstall(data_dir: Path | str, plugin_id: str) -> None:
    if not re.fullmatch(r"[a-z0-9_-]{1,31}", plugin_id) or (BUILTIN_DIR / plugin_id).exists():
        raise InstallError("built-in plugins cannot be removed (turn them off instead)")
    target = Path(data_dir) / "plugins" / plugin_id
    if not target.is_dir():
        raise InstallError("no such plugin")
    shutil.rmtree(target)
