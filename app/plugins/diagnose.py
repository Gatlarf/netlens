"""Diagnostic reports of plugins: what a device answered, in a form that is safe to send to the plugin's author.

A plugin may offer `diagnose(config)` (and `"diagnose": true` in plugin.json). Netlens runs it like test() and fetch(), in the
isolated process, and then removes anything private before showing it: the values of the plugin's own settings (addresses, user
names, API keys, passwords) and MAC addresses. The plugin is expected to describe the *shape* of what it received (field names
and types) rather than the content; this scrub is a second line of defence, not a licence to send content.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
MIN_SECRET_LENGTH = 3
MAX_REPORT_BYTES = 400_000


class DiagnoseError(Exception):
    pass


def _private_values(manifest: dict, config: dict) -> list[tuple[str, str]]:
    """(text to remove, what to write instead) for every text-like setting, plus the host of any address."""
    found: dict[str, str] = {}
    for field in manifest.get("config", []):
        if field["type"] not in ("text", "password"):
            continue
        value = config.get(field["key"])
        if not isinstance(value, str) or len(value.strip()) < MIN_SECRET_LENGTH:
            continue
        value = value.strip()
        found[value] = f"<setting {field['key']}>"
        try:
            host = urllib.parse.urlsplit(value if "://" in value else "//" + value).hostname
        except ValueError:
            host = None
        if host and len(host) >= MIN_SECRET_LENGTH:
            found.setdefault(host, f"<setting {field['key']}>")
    return sorted(found.items(), key=lambda kv: -len(kv[0]))  # longest first, so a URL goes before its host


def scrub(report: Any, manifest: dict, config: dict) -> Any:
    private = _private_values(manifest, config)

    def clean(text: str) -> str:
        for needle, replacement in private:
            if needle.lower() in text.lower():
                text = re.sub(re.escape(needle), replacement, text, flags=re.IGNORECASE)
        return MAC_RE.sub("<mac>", text)

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            return {clean(str(k)): walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, str):
            return clean(value)
        return value

    return walk(report)


def prepare(result: Any, manifest: dict, config: dict) -> dict:
    """The scrubbed report of a plugin's diagnose(), or DiagnoseError."""
    if not isinstance(result, dict):
        raise DiagnoseError("the plugin's diagnose() must return a dictionary")
    report = scrub(result, manifest, config)
    if len(json.dumps(report)) > MAX_REPORT_BYTES:
        raise DiagnoseError("the report is too large to send; the plugin should describe fields, not copy the data")
    return report
