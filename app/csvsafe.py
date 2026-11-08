"""A cell of a CSV file that comes from outside (a user name, a path, a device name) must not be run as a formula by a spreadsheet."""

from __future__ import annotations

from typing import Any

DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def cell(value: Any) -> Any:
    """The value, with a leading apostrophe when a spreadsheet would take it for a formula. An empty cell stays empty; numbers are left alone."""
    if isinstance(value, str) and value.startswith(DANGEROUS):
        return "'" + value
    return value
