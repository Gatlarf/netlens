"""The Settings tab of a device keeps its long explanations behind a "?" (ui.js compactHelp), as the Settings pages do."""
from pathlib import Path

DEVICE = (Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "pages" / "device.js").read_text()


def test_the_settings_tab_of_a_device_tucks_its_explanations_away():
    assert 'import { compactHelp } from "../ui.js"' in DEVICE
    assert "compactHelp(panels.settings)" in DEVICE and "new MutationObserver" in DEVICE


def test_the_small_sections_of_the_edit_form_sit_side_by_side():
    assert 'h("div", { class: "edit-columns" })' in DEVICE and "form.appendChild(cols)" in DEVICE


def test_the_save_button_is_the_last_thing_of_the_edit_card():
    assert 'class: "btn primary", form: formId' in DEVICE and 'card.appendChild(h("div", { class: "form-actions edit-save" }, saveBtn))' in DEVICE
    assert DEVICE.index("card.appendChild(parentSlot)") < DEVICE.index('class: "form-actions edit-save"')
