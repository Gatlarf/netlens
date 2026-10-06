Create tests/test_scheduler.py (under 80 lines, each test written once) with pytest for app.scanner.scheduler.due_kind(now, started_at, last_quick, last_deep, quick_interval, deep_interval) -> "quick" | "deep" | None. Use one @pytest.mark.parametrize table of (now, started_at, last_quick, last_deep, expected) with quick_interval=900 and deep_interval=86400 fixed:
(0,0,None,None,"quick"); (1000,0,990,None,None) [quick fresh, deep never run, 1000s since start >= 600 -> actually deep is due, so expected "deep"]; use these rows precisely:
(0, 0, None, None, "quick"),
(500, 0, 490, None, None),
(599, 0, 599, None, None),
(600, 0, 590, None, "deep"),
(2000, 0, 1900, 1000, None),
(2000, 0, 1000, 1100, "quick"),
(90000, 0, 89990, 3000, "deep"),
(90000, 0, 100, 100, "deep").
