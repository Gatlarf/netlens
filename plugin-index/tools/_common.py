"""Shared helpers for the plugin index tools (they run from a checkout of the Netlens repository)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX_DIR = ROOT / "plugin-index"
sys.path.insert(0, str(ROOT))  # the tools reuse Netlens' own contract and installer checks

from app.plugins import index as netlens_index  # noqa: E402
from app.plugins import registry  # noqa: E402
from app.plugins.contract import API_VERSION  # noqa: E402,F401


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def entry_files(index_dir: Path = INDEX_DIR) -> list[Path]:
    return sorted((index_dir / "plugins").glob("*.json"))


def review_files(index_dir: Path = INDEX_DIR) -> dict[str, dict]:
    out = {}
    for path in sorted((index_dir / "reviews").glob("*.json")):
        data = load_json(path)
        out[data.get("id", path.stem)] = data
    return out


def reviewers(index_dir: Path = INDEX_DIR) -> list[str]:
    path = index_dir / "REVIEWERS"
    if not path.exists():
        return []
    return [line.strip().lstrip("@").lower() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]
