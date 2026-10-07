"""Static check of the browser modules: every named import must be exported by the file it points to.

A wrong import path or name only fails in the browser (the whole page shows a module error), and
`node --check` cannot see it, so this guards every release.
"""

import os
import re
from pathlib import Path

JS_DIR = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
IMPORT_RE = re.compile(r'import\s*\{([^}]*)\}\s*from\s*"([^"]+)"')
EXPORT_RE = re.compile(r"export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z0-9_$]+)")
EXPORT_LIST_RE = re.compile(r"export\s*\{([^}]*)\}")


def _modules():
    return [p for p in JS_DIR.rglob("*.js") if "vendor" not in p.parts]


def _exports(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    names = set(EXPORT_RE.findall(text))
    for group in EXPORT_LIST_RE.findall(text):
        names |= {part.split(" as ")[-1].strip() for part in group.split(",") if part.strip()}
    return names


def test_all_named_imports_resolve():
    exports = {p.resolve(): _exports(p) for p in _modules()}
    problems = []
    for path in _modules():
        for group, spec in IMPORT_RE.findall(path.read_text(encoding="utf-8")):
            target = (path.parent / spec).resolve()
            rel = path.relative_to(JS_DIR)
            if target not in exports:
                problems.append(f"{rel}: imports from missing file {spec}")
                continue
            for name in (part.split(" as ")[0].strip() for part in group.split(",") if part.strip()):
                if name not in exports[target]:
                    problems.append(f"{rel}: '{name}' is not exported by {spec}")
    assert not problems, "\n".join(problems)


def test_every_route_page_exists_and_exports_render():
    app_js = (JS_DIR / "app.js").read_text(encoding="utf-8")
    pages = set(re.findall(r':\s*"([a-z]+)",?\s*$', app_js.split("const ROUTES = {")[1].split("};")[0], re.M))
    assert {"map", "devices", "scans", "settings", "uptime"} <= pages
    for name in pages:
        page = JS_DIR / "pages" / f"{name}.js"
        assert page.exists(), f"route page {name}.js is missing"
        assert "render" in _exports(page), f"{name}.js must export render"


SHARED = ("util.js", "api.js", "heartbeat.js", "progress.js")


def _local_names(text: str) -> set[str]:
    names = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z0-9_$]+)", text))
    names |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=", text))
    return names


def test_shared_helpers_used_in_a_module_are_imported_there():
    """A helper called without being imported only fails at runtime in the browser."""
    shared = {}
    for name in SHARED:
        for export in _exports(JS_DIR / name):
            shared[export] = name
    problems = []
    for path in _modules():
        if path.name in SHARED:
            continue
        text = path.read_text(encoding="utf-8")
        imported = set()
        for group, _ in IMPORT_RE.findall(text):
            imported |= {part.split(" as ")[-1].strip() for part in group.split(",") if part.strip()}
        local = _local_names(text)
        code = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
        for name in shared:
            if name in imported or name in local:
                continue
            if re.search(r"(?<![\w.$])" + re.escape(name) + r"\s*\(", code):
                problems.append(f"{path.relative_to(JS_DIR)}: uses {name}() (from {shared[name]}) without importing it")
    assert not problems, "\n".join(problems)
