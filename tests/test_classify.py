import pytest
from app.scanner.classify import classify_device, DEVICE_TYPES


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        # VM MAC prefix
        ({"mac": "52:54:00:aa:bb:cc"}, "vm"),
        # VM vendor keyword
        ({"vendor": "VMware, Inc."}, "vm"),
        # os_type router
        ({"os_type": "router"}, "router"),
        # os_type WAP -> ap
        ({"os_type": "WAP"}, "ap"),
        # os_type printer
        ({"os_type": "printer"}, "printer"),
        # os_type webcam -> camera
        ({"os_type": "webcam"}, "camera"),
        # os_type phone
        ({"os_type": "phone"}, "phone"),
        # os_type storage-misc -> nas
        ({"os_type": "storage-misc"}, "nas"),
        # os_type specialized -> iot
        ({"os_type": "specialized"}, "iot"),
        # vendor NAS keyword
        ({"vendor": "Synology Incorporated"}, "nas"),
        # vendor camera keyword
        ({"vendor": "Hikvision"}, "camera"),
        # vendor printer keyword + printer port
        ({"vendor": "HP", "open_ports": [9100]}, "printer"),
        # vendor iot keyword
        ({"vendor": "Espressif Inc."}, "iot"),
        # vendor Ubiquiti + hostname ap
        ({"vendor": "Ubiquiti", "hostnames": ["unifi-ap-lobby"]}, "ap"),
        # vendor Ubiquiti + hostname switch
        ({"vendor": "Ubiquiti", "hostnames": ["sw-core"]}, "switch"),
        # vendor router keyword + router ports
        ({"vendor": "Belkin International", "open_ports": [22, 53, 80, 443]}, "router"),
        # vendor phone keyword + no ports
        ({"vendor": "Apple", "open_ports": []}, "phone"),
        # printer port only
        ({"open_ports": [631]}, "printer"),
        # camera port only
        ({"open_ports": [554]}, "camera"),
        # nas port only
        ({"open_ports": [5000]}, "nas"),
        # linux server ports
        ({"os_name": "Linux 5.4", "open_ports": [22]}, "server"),
        # linux no ports -> pc
        ({"os_name": "Linux 5.4", "open_ports": []}, "pc"),
        # windows no ports -> pc
        ({"os_name": "Windows 10", "open_ports": []}, "pc"),
        # windows server ports -> server
        ({"os_name": "Windows Server 2019", "open_ports": [445]}, "server"),
        # server port only
        ({"open_ports": [8080]}, "server"),
        # nothing at all -> unknown
        ({}, "unknown"),
        # VM mac wins over os_type router
        ({"mac": "52:54:00:aa:bb:cc", "os_type": "router"}, "vm"),
    ],
)
def test_classify_device(kwargs, expected):
    result = classify_device(**kwargs)
    assert result in DEVICE_TYPES
    assert result == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"vendor": None, "os_name": None, "os_type": None, "open_ports": (), "services": (), "hostnames": (), "mac": None},
        {"vendor": None, "os_name": None, "os_type": None, "open_ports": [22], "services": (), "hostnames": (), "mac": None},
        {"vendor": "HP", "os_name": None, "os_type": None, "open_ports": (), "services": (), "hostnames": (), "mac": None},
        {"vendor": None, "os_name": "Linux", "os_type": None, "open_ports": (), "services": (), "hostnames": (), "mac": None},
        {"vendor": None, "os_name": None, "os_type": "router", "open_ports": (), "services": (), "hostnames": (), "mac": None},
        {"vendor": None, "os_name": None, "os_type": None, "open_ports": (), "services": (), "hostnames": ["test"], "mac": None},
        {"vendor": None, "os_name": None, "os_type": None, "open_ports": (), "services": (), "hostnames": (), "mac": "52:54:00:aa:bb:cc"},
    ],
)
def test_classify_device_none_inputs(kwargs):
    result = classify_device(**kwargs)
    assert result in DEVICE_TYPES