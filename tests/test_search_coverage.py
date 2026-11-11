"""The search box lists settings by hand (a settings page is only built when opened): every settings section must be findable, or new settings stay invisible."""
import re
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"


def test_every_settings_section_can_be_found_in_the_search():
    sections = set(re.findall(r'key: "([a-z0-9-]+)", label: "', (JS / "pages" / "settings.js").read_text()))
    search = (JS / "search.js").read_text()
    findable = set(re.findall(r'^\s*\["[^"]*", "([a-z0-9-]+)", "', search, re.M)) | set(re.findall(r'"#/settings/([a-z0-9-]+)"', search))
    assert sections, "no settings sections found: did the settings page change shape?"
    assert sorted(sections - findable) == []
