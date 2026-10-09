"""Classification by weighing evidence: the cases that were wrong on a real network, and the new device types."""

import pytest

from app.scanner.classify import DEVICE_TYPES, classify_device, classify_evidence


@pytest.mark.parametrize("kwargs,expected", [
    # a printer that nmap believes runs Android: its name wins over nmap's guess
    (dict(hostnames=["hp-laserjet.lan"], os_name="Android 4.1.1", os_type="phone", vendor="HP Inc."), "printer"),
    # a camera with an open SSH port: nmap's product name for it wins over "has SSH, so a server"
    (dict(os_name="Vimtag CP3 PTZ camera", open_ports=[22, 80]), "camera"),
    (dict(os_name="Vimtag CP3 PTZ camera", os_type="webcam", open_ports=[22, 80]), "camera"),
    # a TV tuner that nothing recognised
    (dict(os_name="Silicondust HDHomeRun set top box"), "tv"),
    (dict(os_type="media device"), "tv"), (dict(os_type="game console"), "console"),
    (dict(os_name="Roku OS 9", open_ports=[8060]), "tv"), (dict(os_name="Android TV 12"), "tv"),
    # tablets and phones
    (dict(hostnames=["ipad-bert.lan"], os_name="Apple iOS 15.0 - 15.6"), "tablet"), (dict(hostnames=["iPad Bieke"], vendor=None), "tablet"),
    (dict(hostnames=["iPhone Bert"], os_name="Apple iOS 15.0 - 15.6"), "phone"), (dict(os_name="Apple iOS 15.0 - 15.6"), "phone"),
    (dict(hostnames=["Galaxy-Tab-A8"]), "tablet"),
    # more kinds of device
    (dict(hostnames=["sonos-kitchen"]), "speaker"), (dict(vendor="Sonos, Inc."), "speaker"),
    (dict(vendor="Nintendo Co.,Ltd"), "console"), (dict(hostnames=["PS5-living"]), "console"), (dict(hostnames=["xbox"]), "console"),
    (dict(vendor="iRobot Corporation"), "appliance"), (dict(hostnames=["roomba-j7"]), "appliance"),
    (dict(vendor="Roku, Inc"), "tv"), (dict(hostnames=["bravia-kd55"]), "tv"),
    # virtual machines and containers by MAC prefix (Incus, LXD, Docker)
    (dict(mac="10:66:6a:37:09:9d", os_name="Linux 5.4 - 5.10", open_ports=[22]), "vm"),
    (dict(mac="02:42:ac:11:00:02"), "vm"), (dict(mac="00:16:3e:11:22:33"), "vm"),
    # "IOS" of a Cisco switch is not an iPhone
    (dict(os_name="Cisco IOS 12.4", vendor="Cisco Systems"), "router"),
    # a NAS by name beats "Linux with SSH"
    (dict(hostnames=["truenas"], os_name="Linux 5.4 - 5.10", open_ports=[22, 80, 443]), "nas"),
    # the old behaviour that must stay
    (dict(os_name="Linux 5.4", open_ports=[22]), "server"), (dict(os_name="Windows 10"), "pc"), (dict(vendor="Synology Incorporated"), "nas"),
    (dict(vendor="HP", open_ports=[9100]), "printer"), (dict(open_ports=[554]), "camera"), (dict(), "unknown"),
])
def test_scoring(kwargs, expected):
    result = classify_device(**kwargs)
    assert result in DEVICE_TYPES and result == expected, classify_evidence(**kwargs)


def test_evidence_lists_every_clue_strongest_first_with_a_reason():
    ev = classify_evidence(hostnames=["hp-laserjet.lan"], os_name="Android 4.1.1", os_type="phone", vendor="HP Inc.", open_ports=[22])
    assert [e[0] for e in ev][:2] == ["printer", "phone"] or ev[0][0] == "printer"
    assert ev[0][2].startswith("name contains") and all(isinstance(e[1], float) or isinstance(e[1], int) for e in ev)
    assert [e[1] for e in ev] == sorted((e[1] for e in ev), reverse=True)
    assert {"printer", "phone", "server"} <= {e[0] for e in ev}


def test_all_types_the_classifier_can_return_are_known_types():
    assert {"tablet", "tv", "speaker", "console", "appliance"} <= set(DEVICE_TYPES) and DEVICE_TYPES[-1] == "unknown"
