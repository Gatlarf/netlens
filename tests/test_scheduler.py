import pytest
from app.scanner.scheduler import due_kind


@pytest.mark.parametrize(
    "now, started_at, last_quick, last_deep, expected",
    [
        (0, 0, None, None, "quick"),
        (500, 0, 490, None, None),
        (599, 0, 599, None, None),
        (600, 0, 590, None, "deep"),
        (2000, 0, 1900, 1000, None),
        (2000, 0, 1000, 1100, "quick"),
        (90000, 0, 89990, 3000, "deep"),
        (90000, 0, 100, 100, "deep"),
    ],
)
def test_due_kind(now, started_at, last_quick, last_deep, expected):
    quick_interval = 900
    deep_interval = 86400
    result = due_kind(now, started_at, last_quick, last_deep, quick_interval, deep_interval)
    assert result == expected