#!/usr/bin/env python3
"""Look for risky code in a plugin (AST based). It cannot prove a plugin safe; it points reviewers at what to read.

Rules marked ERROR fail the index CI unless a trusted reviewer lists the rule in `allow_flags` of the review of that
version (a conscious decision). WARN rules only show up in the report.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# rule id -> (level, message)
RULES = {
    "dynamic-code": ("error", "runs code built at run time (eval/exec/compile/__import__)"),
    "subprocess": ("error", "starts other programs"),
    "native-code": ("error", "loads native code or forks processes"),
    "database": ("error", "touches SQLite (Netlens' database holds every plugin's credentials)"),
    "serialization": ("error", "uses pickle/marshal, which can run code when loading"),
    "file-system": ("warn", "reads or writes files"),
    "environment": ("warn", "reads environment variables"),
    "external-url": ("warn", "contains a URL to a host that is not a placeholder"),
    "obfuscation": ("warn", "decodes data at run time (base64/zlib/codecs), a common way to hide code"),
    "network-server": ("warn", "listens for incoming connections"),
}
BAD_IMPORTS = {
    "subprocess": "subprocess", "pty": "subprocess", "ctypes": "native-code", "cffi": "native-code", "multiprocessing": "native-code",
    "sqlite3": "database", "pickle": "serialization", "cPickle": "serialization", "marshal": "serialization", "shelve": "serialization",
    "importlib": "dynamic-code", "runpy": "dynamic-code", "code": "dynamic-code", "codeop": "dynamic-code",
    "base64": "obfuscation", "zlib": "obfuscation", "codecs": "obfuscation", "binascii": "obfuscation",
}
BAD_CALLS = {"eval": "dynamic-code", "exec": "dynamic-code", "compile": "dynamic-code", "__import__": "dynamic-code"}
OS_CALLS = {"system": "subprocess", "popen": "subprocess", "fork": "native-code", "forkpty": "native-code", "kill": "native-code",
            "remove": "file-system", "unlink": "file-system", "rmdir": "file-system", "rename": "file-system", "chmod": "file-system",
            "getenv": "environment", "putenv": "environment", "listdir": "file-system", "walk": "file-system"}
URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")
PLACEHOLDER_HOSTS = {"example.com", "example.org", "example.net", "localhost", "192.168.0.1", "127.0.0.1", "schemas.upnp.org"}


@dataclass(frozen=True)
class Flag:
    rule: str
    file: str
    line: int
    detail: str

    @property
    def level(self) -> str:
        return RULES[self.rule][0]

    def __str__(self) -> str:
        return f"{self.level.upper():5} {self.file}:{self.line} [{self.rule}] {RULES[self.rule][1]}{(': ' + self.detail) if self.detail else ''}"


def _external(host: str) -> bool:
    if host in PLACEHOLDER_HOSTS or host.endswith((".example.com", ".local", ".lan")):
        return False
    return not re.fullmatch(r"(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\.[0-9.]+", host)


def scan_source(source: str, filename: str = "plugin.py") -> list[Flag]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"{filename}: syntax error on line {exc.lineno}") from exc
    flags: list[Flag] = []

    def add(rule: str, node: ast.AST, detail: str = "") -> None:
        flags.append(Flag(rule, filename, getattr(node, "lineno", 0), detail))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                rule = BAD_IMPORTS.get(alias.name.split(".")[0])
                if rule:
                    add(rule, node, f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            rule = BAD_IMPORTS.get((node.module or "").split(".")[0])
            if rule:
                add(rule, node, f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            owner = func.value.id if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else ""
            if isinstance(func, ast.Name) and name in BAD_CALLS:
                add(BAD_CALLS[name], node, f"{name}()")
            elif owner == "os" and name in OS_CALLS:
                add(OS_CALLS[name], node, f"os.{name}()")
            elif owner in ("shutil",):
                add("file-system", node, f"shutil.{name}()")
            elif isinstance(func, ast.Name) and name == "open":
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                add("file-system", node, f"open(..., {mode!r})" if mode else "open()")
            elif name in ("listen", "bind") and owner:
                add("network-server", node, f"{owner}.{name}()")
            elif name in ("b64decode", "decompress", "decode") and owner in ("base64", "zlib", "codecs"):
                add("obfuscation", node, f"{owner}.{name}()")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            add("environment", node, "os.environ")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for host in URL_RE.findall(node.value):
                if _external(host):
                    add("external-url", node, host)
    return sorted(set(flags), key=lambda f: (f.file, f.line, f.rule))


def scan_files(files: dict[str, bytes]) -> list[Flag]:
    """Scan every .py file of a plugin ({path: bytes})."""
    flags: list[Flag] = []
    for name, content in sorted(files.items()):
        if name.endswith(".py"):
            flags += scan_source(content.decode("utf-8", errors="replace"), name)
    return flags


def blocking(flags: list[Flag], allowed: list[str] | None = None) -> list[Flag]:
    """The ERROR flags that a reviewer has not explicitly allowed."""
    allowed = set(allowed or [])
    return [f for f in flags if f.level == "error" and f.rule not in allowed]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: static_scan.py <plugin folder or .py file>")
        return 2
    path = Path(argv[1])
    files = {p.relative_to(path).as_posix(): p.read_bytes() for p in path.rglob("*.py")} if path.is_dir() else {path.name: path.read_bytes()}
    flags = scan_files(files)
    for f in flags:
        print(f)
    print(f"{len(flags)} flag(s), {len(blocking(flags))} blocking")
    return 1 if blocking(flags) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
