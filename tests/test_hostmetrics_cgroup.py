"""The processor reading of a container: what its own cgroup used, not what /proc/stat shows of the cores it shares with other guests."""

from app.hostmetrics import ssh


def sample(stat, usage, uptime, container="lxc", cpumax="max 100000", cpuset="1,9,11,13", ncpu=4):
    lines = ["##loadavg", "0.5 0.5 0.5 1/100 1", "##stat", stat, "##cgroup"]
    if usage is not None:
        lines.append(f"usage_usec {usage}")
    lines += [f"cpumax {cpumax}", f"cpuset {cpuset}", f"ncpu {ncpu}", "##uptime", f"{uptime} 1.0", "##container", container, "##end"]
    return "\n".join(lines)


def cpu(points):
    return next((v for m, _, v, _ in points if m == "cpu_pct"), None)


def test_a_container_reports_what_its_own_cgroup_used():
    state = {}
    # /proc/stat says the four cores are 90% busy (other guests); the container itself used 0.12 cpu-seconds per second
    first, _ = ssh.parse(sample("cpu 1000 0 1000 100 0 0 0 0", 1_000_000, 100), state)
    assert cpu(first) is None
    points, found = ssh.parse(sample("cpu 90000 0 90000 200 0 0 0 0", 1_000_000 + 12_000_000, 200), state)       # 12 cpu-seconds in 100 s
    assert round(cpu(points), 1) == 3.0 and "cpu" in found


def test_a_quota_or_a_pinned_set_of_cpus_sets_the_capacity():
    state = {}
    ssh.parse(sample("cpu 1 0 1 1 0 0 0 0", 0, 0, cpumax="200000 100000", cpuset="0-3"), state)
    points, _ = ssh.parse(sample("cpu 2 0 2 2 0 0 0 0", 100_000_000, 100, cpumax="200000 100000", cpuset="0-3"), state)     # 100 cpu-seconds in 100 s on 2 cpus
    assert round(cpu(points)) == 50


def test_a_counter_that_went_back_gives_no_reading_instead_of_a_wrong_one():
    state = {}
    ssh.parse(sample("cpu 1 0 1 1 0 0 0 0", 9_000_000, 100), state)
    points, _ = ssh.parse(sample("cpu 2 0 2 2 0 0 0 0", 1_000, 160), state)
    assert cpu(points) is None


def test_a_machine_that_is_not_a_container_still_uses_proc_stat():
    state = {}
    ssh.parse(sample("cpu 100 0 100 800 0 0 0 0", 0, 100, container="none"), state)
    points, _ = ssh.parse(sample("cpu 200 0 200 1000 0 0 0 0", 5_000_000, 160, container="none"), state)
    assert round(cpu(points)) == 50          # 200 busy of 400 new ticks


def test_a_container_without_cgroup_figures_falls_back_to_proc_stat():
    state = {}
    ssh.parse(sample("cpu 100 0 100 800 0 0 0 0", None, 100), state)
    points, _ = ssh.parse(sample("cpu 200 0 200 1000 0 0 0 0", None, 160), state)
    assert round(cpu(points)) == 50


def test_container_reports_no_load_average():
    import inspect
    from app.hostmetrics import ssh
    assert "not in_container" in inspect.getsource(ssh.parse)
