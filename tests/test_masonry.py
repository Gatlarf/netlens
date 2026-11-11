"""The dashboard packs cards of different heights without holes (js/masonry.js: implicit rows, every card spans its height)."""
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_the_dashboard_grid_is_packed_by_row_spans():
    js = (STATIC / "js" / "masonry.js").read_text()
    dash = (STATIC / "js" / "pages" / "dashboard.js").read_text()
    css = (STATIC / "css" / "app.css").read_text()
    assert "gridRowEnd" in js and "ResizeObserver" in js
    assert "masonry(grid)" in dash and "packing.stop()" in dash
    assert ".dash-grid.masonry { grid-auto-rows: 4px" in css and "align-items: start" in css


def test_every_page_of_cards_is_packed_too():
    app = (STATIC / "js" / "app.js").read_text()
    js = (STATIC / "js" / "masonry.js").read_text()
    css = (STATIC / "css" / "features.css").read_text()
    assert "autoMasonry(viewRoot)" in app and '".dev-flow, .stat-grid"' in js
    assert ".dev-flow.masonry, .stat-grid.masonry { grid-auto-rows: 4px" in css and ".dev-panel.dev-flow { display: grid; }" in css
    assert ".info-tip::after { display: none;" in css          # a hidden pop-up must not widen the page
