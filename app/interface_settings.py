"""Interface settings: the look and feel options an administrator sets for everybody (Settings → Interface).

They are not secret: the sign-in page asks for them too (through /api/session), so a new user sees the chosen look before choosing one.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app.db import get_setting, set_setting

KEY = "interface.settings"
LOOKS = ("system", "light", "dark", "hud")
DEFAULTS: dict[str, Any] = {
    "default_look": "system",        # what a user sees until they choose a look themselves (the button at the top right)
    "pulse_seconds": 2.0,            # the HUD scanline flashes red when a device goes offline and green when it comes back; 0 = off
    "pulse_scope": "hud",            # "hud": only on the HUD page; "all": on every page while the HUD look is on
    "pulse_for": "all",              # which devices: all, always_on, critical
    "hud_sweep": True,               # the slow scanline that runs down the screen in the HUD look
    "hud_lines": True,               # the fine scanline texture over the screen in the HUD look
    "wan": "",                       # the interface that is the internet connection for the traffic graph: "<device id>|<interface name>"; empty = find it
}
CHOICES = {"default_look": LOOKS, "pulse_scope": ("hud", "all"), "pulse_for": ("all", "always_on", "critical")}


def clean(key: str, value: Any) -> Any:
    if key in CHOICES:
        if value not in CHOICES[key]:
            raise ValueError(f"{key} must be one of {', '.join(CHOICES[key])}")
        return value
    if key == "pulse_seconds":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
            raise ValueError("pulse_seconds is a number of seconds from 0 (off) to 10")
        return round(float(value), 1)
    if key == "wan":
        if not isinstance(value, str) or (value and not re.fullmatch(r"\d+\|.{1,60}", value)):
            raise ValueError("wan is a device id and an interface name, like 1|WAN, or empty")
        return value
    if key in ("hud_sweep", "hud_lines"):
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be true or false")
        return value
    raise ValueError(f"unknown setting {key!r}")


def get(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        saved = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        saved = {}
    out = dict(DEFAULTS)
    if isinstance(saved, dict):
        for key in DEFAULTS:
            if key in saved:
                try:
                    out[key] = clean(key, saved[key])
                except ValueError:
                    pass                                   # a damaged value is replaced by the default
    return out


def save(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    current = get(conn)
    for key, value in data.items():
        current[key] = clean(key, value)
    set_setting(conn, KEY, json.dumps(current))
    conn.commit()
    return current
