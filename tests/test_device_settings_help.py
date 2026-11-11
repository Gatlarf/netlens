"""The Settings tab of a device keeps its long explanations behind a "?" (ui.js compactHelp), as the Settings pages do."""
from pathlib import Path

DEVICE = (Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "pages" / "device.js").read_text()


def test_the_settings_tab_of_a_device_tucks_its_explanations_away():
    assert 'import { compactHelp } from "../ui.js"' in DEVICE
    assert "compactHelp(panels.settings)" in DEVICE and "new MutationObserver" in DEVICE
