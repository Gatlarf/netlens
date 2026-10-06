import pytest
from app.terminal.policy import target_allowed, pick_port


@pytest.mark.parametrize(
    "ip, ranges, expected",
    [
        ("192.168.1.5", [], True),
        ("10.0.0.7", [], True),
        ("172.16.0.1", [], True),
        ("169.254.1.1", [], True),
        ("8.8.8.8", [], False),
        ("127.0.0.1", ["127.0.0.0/8"], False),
        ("0.0.0.0", [], False),
        ("224.0.0.1", [], False),
        ("192.168.1.5", ["192.168.1.0/24"], True),
        ("192.168.2.5", ["192.168.1.0/24"], False),
        ("10.0.0.7", ["10.0.0.0/20", "192.168.1.0/24"], True),
        ("garbage", [], False),
        ("", [], False),
        ("192.168.1.5", ("192.168.1.0/24",), True),
    ],
)
def test_target_allowed(ip: str, ranges, expected: bool) -> None:
    assert target_allowed(ip, ranges) == expected


@pytest.mark.parametrize(
    "proto, requested, open_ports, expected",
    [
        ("ssh", None, [("tcp", 22)], 22),
        ("telnet", None, [("tcp", 23)], 23),
        ("ssh", 2222, [("tcp", 2222)], 2222),
    ],
)
def test_pick_port_success(proto: str, requested: int | None, open_ports: list[tuple[str, int]], expected: int) -> None:
    assert pick_port(proto, requested, open_ports) == expected


@pytest.mark.parametrize(
    "proto, requested, open_ports",
    [
        ("ssh", None, []),
        ("ssh", 22, [("udp", 22)]),
        ("ssh", 70000, [("tcp", 70000)]),
        ("ssh", 0, [("tcp", 22)]),
        ("rdp", None, [("tcp", 3389)]),
    ],
)
def test_pick_port_raises(proto: str, requested: int | None, open_ports: list[tuple[str, int]]) -> None:
    with pytest.raises(ValueError):
        pick_port(proto, requested, open_ports)