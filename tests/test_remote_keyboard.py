"""RDP/VNC on a touch screen (an iPad) has no hardware keyboard: the session gets a Keyboard button that focuses a hidden text box (the system keyboard needs a focused field)
and sends what is typed as key presses. The session itself needs guacd, so this only guards the wiring."""
from pathlib import Path

JS = Path(__file__).resolve().parent.parent / "app" / "static"


def test_a_touch_screen_gets_a_keyboard_button_with_a_text_box_behind_it():
    remote = (JS / "js" / "pages" / "remote.js").read_text()
    assert 'matchMedia("(pointer: coarse)")' in remote and 'id: "remote-kbd"' in remote
    assert "remote-kbd-input" in remote and "autocapitalize" in remote and "sendKeyEvent" in remote
    assert "(kbOpen ? kbInput : screen).focus" in remote          # tapping the screen must not take the keyboard away
    css = (JS / "css" / "features.css").read_text()
    assert ".remote-kbd-input" in css and "font-size: 16px" in css          # 16px: iOS does not zoom in
