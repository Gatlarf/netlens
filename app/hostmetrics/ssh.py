"""Health readings over SSH from a Linux (or other /proc-based) host: one short command, parsed here.

Nothing is installed on the host and nothing is changed: the command only reads /proc, /sys and `df`. The login can be a
restricted account, a read-only account is enough. The host key is pinned the first time (shared with the web terminal).
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from datetime import datetime, timezone

import asyncssh

from app.hostmetrics.snmp import MAX_INTERFACES, SKIP_MOUNTS, _delta

# One round trip. Plain sh syntax only (the login shell may be anything); the command ends with a marker so a cut-off is noticed.
SCRIPT = (
    'echo "##loadavg"; cat /proc/loadavg 2>/dev/null; '
    'echo "##stat"; grep "^cpu " /proc/stat 2>/dev/null; '
    'echo "##mem"; grep -E "^(MemTotal|MemAvailable|SwapTotal|SwapFree):" /proc/meminfo 2>/dev/null; '
    'echo "##uptime"; cat /proc/uptime 2>/dev/null; '
    'echo "##df"; df -PkT 2>/dev/null; '
    'echo "##net"; cat /proc/net/dev 2>/dev/null; '
    'echo "##temp"; for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "$(cat "$z/type" 2>/dev/null | tr " " "_") $(cat "$z/temp")"; done 2>/dev/null; '
    'echo "##mdstat"; cat /proc/mdstat 2>/dev/null; '
    'echo "##zpool"; PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin" zpool list -H -o name,health 2>/dev/null; '
    'echo "##end"'
)
COMMAND = "sh -c " + "'" + SCRIPT.replace("'", "'\\''") + "'"
SKIP_TYPES = {"tmpfs", "devtmpfs", "squashfs", "overlay", "efivarfs", "ramfs", "iso9660", "proc", "sysfs", "cgroup", "cgroup2", "fuse.lxcfs"}
SKIP_IFACES = re.compile(r"^(lo|veth.*|docker\d*|br-.*|virbr.*|tap.*|cali.*|flannel.*|cni.*)$")


# Windows (the OpenSSH server that comes with Windows 10/11 and Server 2019+): one PowerShell script, sent as an encoded command
# so no quoting of the login shell (cmd.exe) can get in the way. It only reads: processor load, memory, disks, adapters, boot time.
WIN_SCRIPT = (
    # Each part tries WMI first and, when Windows says "Access denied" (an account that is not an administrator), reads the same
    # thing through .NET and performance counters, which an ordinary account may use. The failure is only reported when both fail.
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$r=@{};$e=@();"
    "try{$o=Get-CimInstance Win32_OperatingSystem;$r.mt=[double]$o.TotalVisibleMemorySize;$r.mf=[double]$o.FreePhysicalMemory;"
    "$r.st=[double]$o.TotalVirtualMemorySize;$r.sf=[double]$o.FreeVirtualMemory;$r.boot=$o.LastBootUpTime.ToUniversalTime().ToString('o')}"
    "catch{$m=$_.Exception.Message;try{Add-Type -AssemblyName Microsoft.VisualBasic;$c=[Microsoft.VisualBasic.Devices.ComputerInfo]::new();"
    "$r.mt=[double]$c.TotalPhysicalMemory/1024;$r.mf=[double]$c.AvailablePhysicalMemory/1024}catch{$e+='memory: '+$m}"
    "try{$u=(Get-Counter '\\System\\System Up Time' -ErrorAction Stop).CounterSamples[0].CookedValue;$r.boot=(Get-Date).ToUniversalTime().AddSeconds(-$u).ToString('o')}catch{}};"
    "try{$r.cpu=(Get-CimInstance Win32_Processor|Measure-Object LoadPercentage -Average).Average}"
    "catch{$m=$_.Exception.Message;try{$r.cpu=(Get-Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue}catch{$e+='processor: '+$m}};"
    "try{$r.disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|%{@{id=$_.DeviceID;size=[double]$_.Size;free=[double]$_.FreeSpace}})}"
    "catch{$m=$_.Exception.Message;try{$r.disks=@([System.IO.DriveInfo]::GetDrives()|?{$_.DriveType -eq 'Fixed' -and $_.IsReady}|"
    "%{@{id=$_.Name.TrimEnd('\\');size=[double]$_.TotalSize;free=[double]$_.AvailableFreeSpace}})}catch{$e+='disks: '+$m}};"
    "try{$r.nics=@(Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface|%{@{name=$_.Name;rx=[double]$_.BytesReceivedPersec;tx=[double]$_.BytesSentPersec}})}"
    "catch{$m=$_.Exception.Message;try{$r.nics=@([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|?{$_.OperationalStatus -eq 'Up'}|"
    "%{$t=$_.GetIPv4Statistics();@{name=$_.Description;rx=[double]$t.BytesReceived;tx=[double]$t.BytesSent}})}catch{$e+='network: '+$m}};"
    "try{$r.pd=@(Get-PhysicalDisk|%{@{n=$_.FriendlyName;h=[string]$_.HealthStatus}})}catch{};"
    # automatic services that stopped with an error (a clean stop has exit code 0, 1077 = never started: both are normal)
    "try{$r.sv=@(Get-CimInstance Win32_Service -Filter \"StartMode='Auto' AND State='Stopped' AND ExitCode<>0 AND ExitCode<>1077\"|Select-Object -First 20|%{[string]$_.DisplayName})}catch{};"
    "$r.e=$e;'##netlens-windows';$r|ConvertTo-Json -Compress -Depth 4"
)


def powershell(script: str) -> str:
    """The command line that runs `script` in PowerShell without any quoting problems."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"


WIN_COMMAND = powershell(WIN_SCRIPT)
SKIP_WIN_NICS = re.compile(r"(loopback|isatap|teredo|wan miniport|pseudo|kernel debug|bluetooth)", re.I)


class SshError(Exception):
    pass


def parse_windows(text: str, state: dict, now: float | None = None) -> tuple[list[tuple], list[str]]:
    """Readings from the Windows script (the same shape as `parse`)."""
    now = now if now is not None else time.time()
    at = text.find("##netlens-windows")
    if at < 0:
        raise SshError("the answer from the host was cut off")
    try:
        data = json.loads(text[at + len("##netlens-windows"):].strip())
    except ValueError:
        raise SshError("the answer from the host could not be read") from None
    if not isinstance(data, dict):
        raise SshError("the answer from the host could not be read")
    points: list[tuple] = []
    found: list[str] = []
    problems = [str(x)[:200] for x in (data.get("e") if isinstance(data.get("e"), list) else [data["e"]] if isinstance(data.get("e"), str) else [])]

    def num(v):
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def many(v):
        return v if isinstance(v, list) else ([v] if isinstance(v, dict) else [])

    boot = data.get("boot")
    if isinstance(boot, str):
        try:
            started = datetime.fromisoformat(boot.replace("Z", "+00:00"))
            points.append(("uptime_s", "", max(0.0, now - started.astimezone(timezone.utc).timestamp()), "s"))
            found.append("uptime")
        except ValueError:
            pass
    cpu = num(data.get("cpu"))
    if cpu is not None:
        points.append(("cpu_pct", "", max(0.0, min(100.0, cpu)), "%"))
        found.append("cpu")
    mt, mf = num(data.get("mt")), num(data.get("mf"))
    if mt and mf is not None:
        points.append(("mem_pct", "", 100.0 * (1 - mf / mt), "%"))
        found.append("memory")
        st, sf = num(data.get("st")), num(data.get("sf"))
        if st and sf is not None and st > mt:                       # virtual memory includes the physical memory
            swap_total, swap_free = st - mt, max(0.0, sf - mf)
            if swap_total > 0:
                points.append(("swap_pct", "", max(0.0, min(100.0, 100.0 * (1 - swap_free / swap_total))), "%"))
    disks = []
    for d in many(data.get("disks")):
        size, free, ident = num(d.get("size")), num(d.get("free")), str(d.get("id") or "")
        if ident and size and free is not None and size > 0:
            disks.append(("disk_pct", ident[:40] + "\\", 100.0 * (size - free) / size, "%"))
            disks.append(("disk_free_b", ident[:40] + "\\", free, "B"))
    if disks:
        points.extend(disks[:80])
        found.append("disk")
    traffic, seen = [], False
    for n in many(data.get("nics")):
        name, rx, tx = str(n.get("name") or ""), num(n.get("rx")), num(n.get("tx"))
        if not name or rx is None or tx is None or SKIP_WIN_NICS.search(name):
            continue
        seen = True
        mark = state.get(("if", name))
        state[("if", name)] = (now, rx, tx)
        if mark is None or now - mark[0] <= 0:
            continue
        da, db = _delta(int(rx), int(mark[1]), 64), _delta(int(tx), int(mark[2]), 64)
        if da is None or db is None:
            continue
        dt = now - mark[0]
        traffic.append(("net_rx_bps", name[:40], da * 8 / dt, "bps"))
        traffic.append(("net_tx_bps", name[:40], db * 8 / dt, "bps"))
        if len(traffic) >= MAX_INTERFACES * 2:
            break
    if traffic:
        points.extend(traffic)
        found.append("network")
    elif seen:
        found.append("network")
    storage = []
    for d in many(data.get("pd")):
        name, health = str(d.get("n") or "").strip(), str(d.get("h") or "").strip().lower()
        if name and health in WIN_DISK_LEVEL:
            storage.append(("storage_status", name[:40], float(WIN_DISK_LEVEL[health]), "state"))
    if storage:
        points.extend(storage[:40])
        found.append("storage")
    if isinstance(data.get("sv"), (list, str)):               # the service list was read: a service that is not in it any more is running again
        points.append(("service_stopped", "", 0.0, "state"))
        for name in many(data.get("sv")) if isinstance(data.get("sv"), list) else [data["sv"]]:
            if isinstance(name, str) and name.strip():
                points.append(("service_stopped", name.strip()[:60], 1.0, "state"))
        found.append("services")
    if not points and problems:
        raise SshError("Windows refused the readings: " + "; ".join(problems[:3]) + ". Make the account a member of the local Administrators group, or of Performance Monitor Users (see the setup notes).")
    return points, found


def _sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("##"):
            current = line[2:].strip()
            out[current] = []
        elif current is not None:
            out[current].append(line)
    return out


ZPOOL_LEVEL = {"ONLINE": 0, "DEGRADED": 1, "OFFLINE": 2, "FAULTED": 2, "UNAVAIL": 2, "REMOVED": 2, "SUSPENDED": 2}
WIN_DISK_LEVEL = {"healthy": 0, "warning": 1, "unhealthy": 2}


def parse_mdstat(lines: list[str]) -> list[tuple]:
    """Linux software RAID: 0 for a complete array, 1 when a member is missing or failed, 2 when the array is not active."""
    out, name, state_line = [], None, ""
    arrays: dict[str, dict] = {}
    for line in lines:
        m = re.match(r"^(md\d+)\s*:\s*(\S+)\s+(.*)$", line)
        if m:
            name = m.group(1)
            arrays[name] = {"active": m.group(2), "failed": "(F)" in m.group(3), "missing": False, "has_status": False}
            continue
        if name and arrays.get(name) is not None:
            bracket = re.search(r"\[(\d+)/(\d+)\]\s*\[([U_]+)\]", line)
            if bracket:
                arrays[name]["has_status"] = True
                arrays[name]["missing"] = "_" in bracket.group(3) or bracket.group(1) != bracket.group(2)
    for name, a in arrays.items():
        if a["active"] == "inactive":
            level = 2.0
        elif a["failed"] or a["missing"]:
            level = 1.0
        else:
            level = 0.0
        out.append(("storage_status", name, level, "state"))
    return out


def parse(text: str, state: dict, now: float | None = None) -> tuple[list[tuple], list[str]]:
    """Points (metric, label, value, unit) and the groups that were there. `state` carries the counters of the last round."""
    now = now if now is not None else time.time()
    sec = _sections(text)
    if "end" not in sec:
        raise SshError("the answer from the host was cut off")
    points: list[tuple] = []
    found: list[str] = []

    def add(group, items):
        if items:
            points.extend(items)
            if group not in found:
                found.append(group)

    parts = (sec.get("uptime") or [""])[0].split()
    if parts:
        try:
            add("uptime", [("uptime_s", "", float(parts[0]), "s")])
        except ValueError:
            pass

    # processor: busy share since the previous round (the counters in /proc/stat only grow)
    line = (sec.get("stat") or [""])[0].split()
    cpu = []
    if len(line) >= 8 and line[0] == "cpu":
        try:
            nums = [int(x) for x in line[1:9]]
            total, idle = sum(nums), nums[3] + nums[4]
            before = state.get("cpu")
            state["cpu"] = (total, idle)
            if before and total > before[0]:
                cpu.append(("cpu_pct", "", max(0.0, min(100.0, 100.0 * (1 - (idle - before[1]) / (total - before[0])))), "%"))
            else:
                found.append("cpu")
        except ValueError:
            pass
    load = (sec.get("loadavg") or [""])[0].split()
    if load:
        try:
            cpu.append(("load1", "", float(load[0]), ""))
        except ValueError:
            pass
    add("cpu", cpu)

    mem = {}
    for item in sec.get("mem", []):
        name, _, rest = item.partition(":")
        try:
            mem[name.strip()] = int(rest.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    items = []
    if mem.get("MemTotal") and "MemAvailable" in mem:
        items.append(("mem_pct", "", 100.0 * (1 - mem["MemAvailable"] / mem["MemTotal"]), "%"))
    if mem.get("SwapTotal"):
        items.append(("swap_pct", "", 100.0 * (1 - mem.get("SwapFree", 0) / mem["SwapTotal"]), "%"))
    add("memory", items)

    disks, seen = [], set()
    for item in sec.get("df", [])[1:]:
        cols = item.split(None, 6)
        if len(cols) < 7:
            continue
        fs_type, used, avail, mount = cols[1], cols[3], cols[4], cols[6]
        if fs_type in SKIP_TYPES or mount.startswith(SKIP_MOUNTS) or mount in seen:
            continue
        try:
            used_k, avail_k = int(used), int(avail)
        except ValueError:
            continue
        if used_k + avail_k < 64 * 1024:
            continue
        seen.add(mount)
        disks.append(("disk_pct", mount[:40], 100.0 * used_k / (used_k + avail_k), "%"))
        disks.append(("disk_free_b", mount[:40], avail_k * 1024.0, "B"))
    add("disk", disks[:80])

    traffic, seen_if = [], False
    for item in sec.get("net", [])[2:]:
        name, _, rest = item.partition(":")
        name = name.strip()
        cols = rest.split()
        if not name or len(cols) < 16 or SKIP_IFACES.match(name):
            continue
        try:
            rx, tx = int(cols[0]), int(cols[8])
        except ValueError:
            continue
        seen_if = True
        mark = state.get(("if", name))
        state[("if", name)] = (now, rx, tx)
        if mark is None or now - mark[0] <= 0:
            continue
        da, db = _delta(rx, mark[1], 64), _delta(tx, mark[2], 64)
        if da is None or db is None:
            continue
        dt = now - mark[0]
        traffic.append(("net_rx_bps", name, da * 8 / dt, "bps"))
        traffic.append(("net_tx_bps", name, db * 8 / dt, "bps"))
        if len(traffic) >= MAX_INTERFACES * 2:
            break
    if traffic:
        add("network", traffic)
    elif seen_if and "network" not in found:
        found.append("network")

    temps = []
    for item in sec.get("temp", []):
        name, _, value = item.rpartition(" ")
        try:
            temps.append(("temp_c", (name or "sensor")[:40], int(value) / 1000.0, "°C"))
        except ValueError:
            pass
    add("temperature", temps[:12])
    storage = parse_mdstat(sec.get("mdstat", []))
    for item in sec.get("zpool", []):
        cols = item.split()
        if len(cols) >= 2 and cols[1].upper() in ZPOOL_LEVEL:
            storage.append(("storage_status", cols[0][:40], float(ZPOOL_LEVEL[cols[1].upper()]), "state"))
    add("storage", storage)
    return points, found


def interpret_error(exc: Exception) -> str:
    if isinstance(exc, asyncssh.PermissionDenied):
        return "the login was refused (check the user name and password or key)"
    if isinstance(exc, asyncio.TimeoutError):
        return "no answer in time"
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return "the host key is not the one remembered for this device (it was reinstalled, or this is another machine)"
    if isinstance(exc, (OSError, asyncssh.Error)):
        return f"cannot connect: {getattr(exc, 'strerror', None) or exc}"
    return str(exc)


async def run(host: str, port: int, username: str, password: str | None, private_key: str | None, passphrase: str | None,
              known_fingerprint: str | None = None, timeout: float = 15.0) -> tuple[str, str | None]:
    """Run the readings command. Returns (output, host key fingerprint)."""
    out, _status, fingerprint = await run_command(host, port, username, password, private_key, passphrase, COMMAND, known_fingerprint, timeout)
    return out, fingerprint


async def run_command(host: str, port: int, username: str, password: str | None, private_key: str | None, passphrase: str | None,
                      command: str, known_fingerprint: str | None = None, timeout: float = 15.0) -> tuple[str, int | None, str | None]:
    """Run one command. Returns (output, exit status, host key fingerprint)."""
    seen: dict[str, str] = {}

    class Client(asyncssh.SSHClient):
        def validate_host_public_key(self, host, addr, port, key) -> bool:
            seen["fp"] = key.get_fingerprint("sha256")
            return known_fingerprint is None or seen["fp"] == known_fingerprint

    keys = None
    if private_key:
        try:
            keys = [asyncssh.import_private_key(private_key, passphrase or None)]
        except (asyncssh.Error, ValueError) as exc:
            raise SshError(f"the private key cannot be read: {exc}") from None
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(host, port=port, client_factory=Client, username=username, password=password or None, client_keys=keys,
                             known_hosts=(), agent_path=None, config=None, login_timeout=timeout),
            timeout + 2)
    except Exception as exc:  # noqa: BLE001 - turned into a sentence for the user
        raise SshError(interpret_error(exc)) from None
    try:
        result = await asyncio.wait_for(conn.run(command, check=False), timeout)
    except Exception as exc:  # noqa: BLE001
        raise SshError(interpret_error(exc)) from None
    finally:
        conn.close()
    return str(result.stdout or ""), result.exit_status, seen.get("fp")
