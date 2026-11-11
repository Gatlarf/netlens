"""The plugin guide is rendered in the browser by a small Markdown reader (cards/plugin_guide.js). A table row after a blank line (which cuts the table in two) used to
make that reader loop for ever and hang the tab: keep every table in one piece."""
import re
from pathlib import Path

GUIDE = Path(__file__).resolve().parent.parent / "app" / "plugins" / "PLUGINS.md"


def test_every_table_row_belongs_to_a_table_with_a_header():
    lines = GUIDE.read_text().splitlines()
    in_code = False
    for n, line in enumerate(lines):
        if line.startswith("```"):
            in_code = not in_code
        if in_code or not line.startswith("|"):
            continue
        previous = lines[n - 1] if n else ""
        nxt = lines[n + 1] if n + 1 < len(lines) else ""
        starts = not previous.startswith("|")
        assert not starts or re.match(r"^\|?[\s:|-]+\|?$", nxt), f"line {n + 1} starts a table without a header row (a blank line inside a table?)"


def test_the_reader_always_takes_the_first_line_of_a_paragraph():
    js = (Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "cards" / "plugin_guide.js").read_text()
    assert "const para = [lines[i++]]" in js
