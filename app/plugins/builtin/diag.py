"""Helpers for the diagnostic reports of the built-in plugins (plugins that are shipped separately carry their own copy of `describe`)."""

from __future__ import annotations

import re
from typing import Any, Callable

KEEP_WORDS = {"type", "status", "state", "online", "template", "kind", "version", "release", "role", "model"}
MAC_RE = re.compile(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SAMPLES = 3


def describe(value: Any, key: str = "") -> Any:
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        macs = [k for k in value if isinstance(k, str) and MAC_RE.match(k)]
        out = {k: describe(v, k) for k, v in value.items() if k not in macs}
        if macs:  # rows keyed by MAC address: the addresses are not written down, one example row is described
            out[f"<mac> x {len(macs)}"] = describe(value[macs[0]])
        return out
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and not isinstance(value, (dict, list)):
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if MAC_RE.match(value):
            return "<mac " + ("dashes" if "-" in value else "colons") + (", UPPER" if value.upper() == value and re.search("[A-F]", value) else "") + ">"
        if IPV4_RE.match(value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def mask(text: str) -> str:
    """A configuration string with its structure kept and MAC / IPv4 addresses hidden (for example `virtio=<mac>,bridge=vmbr0`)."""
    text = re.sub(r"(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", "<mac>", text)
    return re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(/\d+)?\b", "<ipv4>", text)


def problem(exc: Exception) -> str:
    return type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]


def make_step(report: dict) -> Callable[[str, Callable[[], Any]], Any]:
    """step(name, call): run one read, record its shape or its failure, return the raw value (or None)."""

    def step(name: str, call: Callable[[], Any], shape: Callable[[Any], Any] = describe) -> Any:
        try:
            raw = call()
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": problem(exc)}
            return None
        report["steps"][name] = {"ok": True, "shape": shape(raw)}
        return raw

    return step
