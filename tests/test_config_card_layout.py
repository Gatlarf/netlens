"""The Configuration card of a device: one line per recommendation or change, opened by a click on its title; the Accept button is in the title line."""
from pathlib import Path

JS = (Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "cards" / "device_config.js").read_text()


def test_recommendations_and_changes_are_collapsed_to_their_title():
    assert 'h("details", { class: `exposure-item' in JS and 'h("details", { class: "config-change" }' in JS
    assert 'h("summary", { class: "config-title" }, h("strong", {}, f.title)' in JS and "e.preventDefault();" in JS and "e.stopPropagation();" in JS
