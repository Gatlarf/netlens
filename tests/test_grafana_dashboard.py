"""The Grafana dashboard is generated; it must match its generator and only use metrics that Netlens exports."""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRAFANA = ROOT / "contrib" / "grafana"


def _generator():
    spec = importlib.util.spec_from_file_location("build_dashboard", GRAFANA / "build_dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_file_is_what_the_generator_writes():
    assert json.loads((GRAFANA / "netlens-dashboard.json").read_text("utf-8")) == json.loads(json.dumps(_generator().dashboard())), "run: python contrib/grafana/build_dashboard.py"


def test_every_panel_uses_a_metric_netlens_exports():
    exported = set(re.findall(r'"(netlens_[a-z0-9_]+)"', (ROOT / "app" / "metrics.py").read_text("utf-8")))
    exported |= set(re.findall(r'f"(netlens_backup_store_)\{name\}"', (ROOT / "app" / "metrics.py").read_text("utf-8")))
    used = set()
    for panel in json.loads((GRAFANA / "netlens-dashboard.json").read_text("utf-8"))["panels"]:
        for target in panel.get("targets", []):
            used |= set(re.findall(r"netlens_[a-z0-9_]+", target["expr"]))
    assert used and not (used - exported), sorted(used - exported)


def test_panels_do_not_overlap_and_ids_are_unique():
    panels = json.loads((GRAFANA / "netlens-dashboard.json").read_text("utf-8"))["panels"]
    assert len({p["id"] for p in panels}) == len(panels)
    for p in panels:
        g = p["gridPos"]
        assert g["x"] + g["w"] <= 24, p["title"]
    placed = [(p["gridPos"], p["title"]) for p in panels if p["type"] != "row"]
    for i, (a, ta) in enumerate(placed):
        for b, tb in placed[i + 1:]:
            apart = a["x"] + a["w"] <= b["x"] or b["x"] + b["w"] <= a["x"] or a["y"] + a["h"] <= b["y"] or b["y"] + b["h"] <= a["y"]
            assert apart, f"{ta} overlaps {tb}"
