"""The reading chips at the top of a device page (Processor, Memory, Disk ...) go to the graph of that reading: the graphs carry their metric and label for that."""
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"


def test_a_chip_goes_to_its_graph():
    glance = (JS / "cards" / "health_glance.js").read_text()
    graph = (JS / "timegraph.js").read_text()
    device = (JS / "pages" / "device.js").read_text()
    assert 'onclick: () => onOpen(c.metric' in glance
    assert '"data-metric": metric, "data-label": label' in graph
    assert "goToGraph" in device and 'select("health")' in device and "scrollIntoView" in device
