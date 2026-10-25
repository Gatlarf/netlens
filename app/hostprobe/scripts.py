"""The read-only probes that are run on a host, and the files that lock a host down so that it can run nothing else.

A probe answers one question about a host. The catalogue:

  storage  what uses the disk space: biggest folders and files, Docker images/layers/logs, files deleted but still held open
  cpu      what uses the processor: load, pressure, steal, iowait, the busiest processes and containers
  memory   what uses the memory: available memory, swap activity, the biggest processes, kernel out-of-memory kills
  network  what the network does: traffic and errors per interface, TCP health, who talks to whom, can it reach the gateway and the internet
  apps     what is broken: failed services, containers that restart/exit/are unhealthy, the services that log errors
  changes  what changed lately: reboots, installed/upgraded packages, changed files in /etc, recreated containers, new accounts
  schedule what is scheduled: systemd timers and cron jobs with the time they last ran (a spike at 03:00 is often a job)
  hardware disk health (SMART), RAID/ZFS state, temperatures, I/O and memory errors in the kernel log, read-only filesystems, UPS
  security failed and successful logins, accounts and keys, what listens on every interface, pending security updates, clock sync

They only read. They run at the lowest CPU and disk priority and every part has a time limit.
The same text is used in three places: sent directly by Netlens (no set-up on the host), installed on the host as a root-owned
script that an SSH key or certificate is bound to (the host then allows nothing else), and described in the set-up help.
"""

from __future__ import annotations

import base64

PROBES = ("storage", "cpu", "memory", "network", "apps", "changes", "schedule", "hardware", "security")
TITLES = {"storage": "Storage", "cpu": "Processor", "memory": "Memory", "network": "Network", "apps": "Applications", "changes": "Recent changes",
          "schedule": "Scheduled jobs", "hardware": "Hardware health", "security": "Security"}
SCRIPT_VERSION = 4          # raise it when a script changes: a host that has an older copy installed is told so
WRAPPER_PATH = "/usr/local/sbin/netlens-probe"
ENTRY_PATH = "/usr/local/sbin/netlens-probe-entry"
WRAPPER_NAME = "netlens-probe"

# Plain sh syntax only (the login shell may be anything). The marker lines start with ## and are parsed by app/hostprobe/parse.py.
PREAMBLE = r'''PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
R=""
if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then R="sudo -n"; fi
T=""; command -v timeout >/dev/null 2>&1 && T="timeout 100"
N=""; command -v nice >/dev/null 2>&1 && N="nice -n 19"
command -v ionice >/dev/null 2>&1 && N="$N ionice -c3"
D=""
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then D="docker"; elif [ -n "$R" ] && $R docker info >/dev/null 2>&1; then D="$R docker"; fi
fi
'''

LINUX_BODIES: dict[str, str] = {}

LINUX_BODIES["storage"] = r'''echo "##version @VERSION@"
echo "##host"; uname -sr 2>/dev/null; id -u
echo "##df"; df -PkT 2>/dev/null
for M in $(df -PkT 2>/dev/null | awk 'NR>1 && $2 !~ /^(tmpfs|devtmpfs|squashfs|overlay|nfs|nfs4|cifs|smb3|smbfs|fuse.*|9p|proc|sysfs|cgroup.*|ramfs|iso9660|efivarfs|autofs)$/ && $7 ~ /^\// {print $7}' | sort -u | head -n 6); do
  echo "##du $M"; $R $T $N du -xk -d 2 "$M" 2>/dev/null | sort -rn | head -n 45
  echo "##big $M"; $R $T $N find "$M" -xdev -type f -size +200M -printf '%s\t%T@\t%p\n' 2>/dev/null | sort -rn | head -n 25
done
if [ -n "$D" ]; then
  echo "##dockerdf"; $D system df --format '{{.Type}}|{{.TotalCount}}|{{.Active}}|{{.Size}}|{{.Reclaimable}}' 2>/dev/null
  echo "##dockerps"; $D ps -a -s --format '{{.Names}}|{{.Status}}|{{.Size}}' 2>/dev/null
  echo "##dockerlogs"
  for C in $($D ps -aq 2>/dev/null); do $D inspect --format '{{.Name}}|{{.LogPath}}|{{.RestartCount}}' "$C" 2>/dev/null; done | while IFS='|' read -r NAME LOG RC; do
    [ -n "$LOG" ] && echo "$NAME|$($R stat -c %s "$LOG" 2>/dev/null)|$RC"
  done
fi
echo "##deleted"
if command -v lsof >/dev/null 2>&1; then $R $T lsof -nP +L1 2>/dev/null | awk 'NR>1 && $4 ~ /^[0-9]+[urw]/ && $7+0 > 10485760 {n=""; for (i=10; i<=NF; i++) n = n (i>10 ? " " : "") $i; if (n !~ /^\/(memfd:|dev\/shm\/)/) print $7"|"$1"|"n}' | sort -rn | head -n 10; fi
echo "##end"
'''

# every probe that lists processes also maps a process to its container (the 64 hex characters in its cgroup), so "java" becomes "greenbone-gvmd"
CONTAINER_MAP = r'''echo "##containers"
if [ -n "$D" ]; then $D ps --no-trunc --format '{{.ID}}|{{.Names}}' 2>/dev/null | awk -F'|' '{print substr($1,1,12)"|"$2}'; fi
echo "##cgroups"
for P in $PIDS; do C=$(sed -n 's/.*[^0-9a-f]\([0-9a-f]\{64\}\).*/\1/p' /proc/$P/cgroup 2>/dev/null | head -n 1 | cut -c1-12); [ -n "$C" ] && echo "$P|$C"; done
'''

LINUX_BODIES["cpu"] = r'''echo "##version @VERSION@"
echo "##loadavg"; cat /proc/loadavg 2>/dev/null
echo "##cpus"; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null
echo "##pressure"; for F in cpu io memory; do [ -r /proc/pressure/$F ] && echo "$F $(head -n 1 /proc/pressure/$F)"; done
echo "##vmstat"; vmstat 1 2 2>/dev/null | tail -n 1
TOP=$(top -b -n 2 -d 1 -w 200 2>/dev/null | awk '/^top - /{n++} n==2' | head -n 22)
echo "##top"; echo "$TOP"
echo "##ps"; ps -eo pid,pcpu,pmem,rss,etime,user,comm --sort=-pcpu 2>/dev/null | head -n 12
PIDS=$(echo "$TOP" | awk '$1 ~ /^[0-9]+$/ {print $1}' | head -n 10)
[ -z "$PIDS" ] && PIDS=$(ps -eo pid --sort=-pcpu 2>/dev/null | awk 'NR>1 && NR<=11 {print $1}')
@CONTAINER_MAP@
echo "##dockerstats"
if [ -n "$D" ]; then $T $D stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}' 2>/dev/null; fi
echo "##end"
'''

LINUX_BODIES["memory"] = r'''echo "##version @VERSION@"
echo "##meminfo"; grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Slab|SReclaimable|Shmem|AnonPages|Dirty|Committed_AS|CommitLimit):' /proc/meminfo 2>/dev/null
echo "##pressure"; for F in cpu io memory; do [ -r /proc/pressure/$F ] && echo "$F $(head -n 1 /proc/pressure/$F)"; done
echo "##vmstat"; vmstat 1 2 2>/dev/null | tail -n 1
echo "##ps"; ps -eo pid,rss,pmem,etime,user,comm --sort=-rss 2>/dev/null | head -n 12
PIDS=$(ps -eo pid --sort=-rss 2>/dev/null | awk 'NR>1 && NR<=11 {print $1}')
@CONTAINER_MAP@
echo "##oom"
{ $R dmesg -T 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process|invoked oom-killer'; $R journalctl -k --since '-72h' --no-pager -q 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process'; } | tail -n 10 | cut -c1-240
echo "##dockerstats"
if [ -n "$D" ]; then $T $D stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}' 2>/dev/null; fi
echo "##dockeroom"
if [ -n "$D" ]; then for C in $($D ps -aq 2>/dev/null); do $D inspect -f '{{.Name}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{.HostConfig.Memory}}' "$C" 2>/dev/null; done; fi
echo "##end"
'''

LINUX_BODIES["network"] = r'''echo "##version @VERSION@"
echo "##time"; date +%s
echo "##net1"; cat /proc/net/dev 2>/dev/null
sleep 1
echo "##net2"; cat /proc/net/dev 2>/dev/null
echo "##snmp"; grep -E '^(Tcp|Udp|Ip):' /proc/net/snmp 2>/dev/null
echo "##tcpext"; grep -E '^TcpExt:' /proc/net/netstat 2>/dev/null
echo "##states"; ss -Htan 2>/dev/null | awk '{c[$1]++} END{for (k in c) print k"|"c[k]}'
echo "##remote"; ss -Htn state established 2>/dev/null | awk '{ip=$4; sub(/:[0-9]+$/,"",ip); c[ip]++} END{for (k in c) print c[k]"|"k}' | sort -rn | head -n 10
echo "##processes"; $R ss -Htnp state established 2>/dev/null | grep -o 'users:(("[^"]*"' | sed 's/users:(("//; s/"$//' | sort | uniq -c | sort -rn | head -n 8
echo "##listening"; $R ss -Htlnp 2>/dev/null | awk '{print $4"|"$6}' | head -n 25
echo "##route"; ip route show default 2>/dev/null | head -n 2
GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
echo "##ping"
[ -n "$GW" ] && echo "gateway|$GW|$(ping -c 3 -W 1 "$GW" 2>/dev/null | tail -n 2 | tr '\n' ' ')"
echo "internet|1.1.1.1|$(ping -c 3 -W 1 1.1.1.1 2>/dev/null | tail -n 2 | tr '\n' ' ')"
S0=$(date +%s%N 2>/dev/null); getent hosts example.com >/dev/null 2>&1; RC=$?; S1=$(date +%s%N 2>/dev/null)
echo "dns|example.com|rc=$RC ms=$(( (S1 - S0) / 1000000 ))"
echo "##dockerstats"
if [ -n "$D" ]; then $T $D stats --no-stream --format '{{.Name}}|{{.NetIO}}' 2>/dev/null; fi
echo "##end"
'''

LINUX_BODIES["apps"] = r'''echo "##version @VERSION@"
echo "##uptime"; cat /proc/uptime 2>/dev/null
echo "##failed"; systemctl list-units --state=failed --no-legend --plain 2>/dev/null | head -n 15
echo "##failedinfo"
for U in $(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | head -n 8); do systemctl show -p Id -p Result -p ExecMainStatus -p NRestarts -p InactiveEnterTimestamp "$U" 2>/dev/null | tr '\n' ' '; echo; done
echo "##journal"; journalctl -p err --since '1 hour ago' --no-pager -q 2>/dev/null | awk '{u=$5; sub(/\[.*/,"",u); sub(/:$/,"",u); c[u]++} END{for (k in c) print c[k]"|"k}' | sort -rn | head -n 10
echo "##journalsample"; journalctl -p err --since '1 hour ago' --no-pager -q 2>/dev/null | tail -n 6 | cut -c1-200
echo "##docker"
if [ -n "$D" ]; then for C in $($D ps -aq 2>/dev/null); do $D inspect -f '{{.Name}}|{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.RestartCount}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.Config.Image}}' "$C" 2>/dev/null; done; fi
echo "##dockererrors"
if [ -n "$D" ]; then for C in $($D ps -aq 2>/dev/null); do
  I=$($D inspect -f '{{.Name}}|{{.RestartCount}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$C" 2>/dev/null)
  case "$I" in *"|restarting|"*|*"|exited|"*|*unhealthy*|*"|"[1-9]*"|"*) echo "${I%%|*}|$($T $D logs --since 1h --tail 300 "$C" 2>&1 | grep -ciE 'error|exception|fatal|panic')";; esac
done | head -n 12; fi
echo "##end"
'''

LINUX_BODIES["changes"] = r'''echo "##version @VERSION@"
echo "##time"; date +%s
echo "##tz"; date +%z
echo "##boots"; { last -x -F reboot shutdown 2>/dev/null | head -n 8; } | cut -c1-120
echo "##packages"
CUT=$(date -d '3 days ago' +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)
{ cat /var/log/dpkg.log.1 /var/log/dpkg.log 2>/dev/null | awk -v c="$CUT" '$1 >= c && ($3=="install" || $3=="upgrade" || $3=="remove") {print $1" "$2" "$3" "$4" "$5" "$6}' | tail -n 40
  rpm -qa --last 2>/dev/null | head -n 15; } | cut -c1-140
echo "##etc"; find /etc -xdev -type f -mtime -3 -printf '%T@\t%p\n' 2>/dev/null | sort -rn | head -n 25
echo "##docker"
if [ -n "$D" ]; then for C in $($D ps -aq 2>/dev/null); do $D inspect -f '{{.Name}}|{{.Created}}|{{.Config.Image}}|{{.State.Status}}' "$C" 2>/dev/null; done; fi
echo "##users"; awk -F: '($3==0 || $3>=1000) && $7 !~ /(nologin|false)$/ {print $1"|"$3"|"$7}' /etc/passwd 2>/dev/null
echo "##keys"; find /root /home -maxdepth 3 -name authorized_keys -printf '%u|%T@|%p\n' 2>/dev/null | head -n 20
echo "##end"
'''

LINUX_BODIES["schedule"] = r'''echo "##version @VERSION@"
echo "##time"; date +%s
echo "##timers"
for U in $(systemctl list-timers --all --no-legend --plain 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /\.timer$/) {print $i; break}}' | sort -u | head -n 40); do
  L=$(systemctl show -p LastTriggerUSec --value "$U" 2>/dev/null); X=$(systemctl show -p NextElapseUSecRealtime --value "$U" 2>/dev/null); A=$(systemctl show -p Unit --value "$U" 2>/dev/null)
  LE=""; [ -n "$L" ] && LE=$(date -d "$L" +%s 2>/dev/null); NE=""; [ -n "$X" ] && NE=$(date -d "$X" +%s 2>/dev/null)
  echo "$U|$A|$LE|$NE"
done
echo "##cron"
for F in /etc/crontab /etc/cron.d/*; do [ -f "$F" ] && grep -vE '^\s*(#|$)' "$F" 2>/dev/null | sed "s#^#$F: #"; done | head -n 40 | cut -c1-200
echo "##cronrun"; journalctl -u cron -u crond -u cronie --since '-24h' --no-pager -q -o short-unix 2>/dev/null | grep -E 'CMD' | tail -n 40 | cut -c1-220
echo "##crondirs"; for D2 in hourly daily weekly monthly; do echo "$D2|$(ls /etc/cron.$D2 2>/dev/null | tr '\n' ' ')"; done
echo "##end"
'''

LINUX_BODIES["hardware"] = r'''echo "##version @VERSION@"
echo "##virt"; systemd-detect-virt 2>/dev/null
echo "##smart"
for DEV in /dev/sd? /dev/vd? /dev/nvme?n1; do [ -e "$DEV" ] || continue
  H=$($R $T smartctl -H "$DEV" 2>/dev/null | grep -iE 'overall-health|result' | head -n 1 | sed 's/.*: *//')
  A=$($R $T smartctl -A "$DEV" 2>/dev/null | awk '/Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|Wear_Leveling|Media_Wearout|Percentage Used|Temperature_Celsius|^Temperature:|Critical Warning/ {printf "%s=%s ", $2, $NF}')
  echo "$DEV|${H:-unknown}|$A"
done
echo "##mdstat"; cat /proc/mdstat 2>/dev/null
echo "##zpool"; zpool list -H -o name,health,cap 2>/dev/null; zpool status -x 2>/dev/null | head -n 12
echo "##temps"; for Z in /sys/class/thermal/thermal_zone*; do [ -r "$Z/temp" ] && echo "$(cat "$Z/type" 2>/dev/null | tr ' ' '_') $(cat "$Z/temp")"; done 2>/dev/null
echo "##ioerrors"
{ $R dmesg -T 2>/dev/null; $R journalctl -k --since '-72h' --no-pager -q 2>/dev/null; } | grep -iE 'i/o error|ata[0-9.]+: .*(error|failed)|blk_update_request|EXT4-fs error|XFS .*error|Buffer I/O error|nvme.*(timeout|reset)|mce:|hardware error|remounting filesystem read-only|ecc' | tail -n 12 | cut -c1-220
echo "##readonly"; awk '$4 ~ /(^|,)ro(,|$)/ && $3 !~ /^(squashfs|iso9660|proc|sysfs|cgroup2?|tmpfs|devtmpfs|overlay|autofs|fuse.*|tracefs|bpf|securityfs|debugfs|configfs|pstore|efivarfs|mqueue|hugetlbfs|nsfs|ramfs)$/ {print $2"|"$3}' /proc/mounts 2>/dev/null | head -n 10
echo "##ups"; if command -v upsc >/dev/null 2>&1; then for U in $(upsc -l 2>/dev/null | head -n 2); do echo "$U|$(upsc "$U" 2>/dev/null | grep -E '^(ups.status|battery.charge|battery.runtime|ups.load):' | tr '\n' ' ')"; done; fi
echo "##end"
'''

LINUX_BODIES["security"] = r'''echo "##version @VERSION@"
echo "##failedlogins"
{ journalctl -u ssh -u sshd --since '24 hours ago' --no-pager -q 2>/dev/null; grep -h -E 'sshd' /var/log/auth.log 2>/dev/null | tail -n 3000; } | grep -E 'Failed password|Invalid user|authentication failure|Connection closed by authenticating user' | grep -oE 'from [0-9a-fA-F:.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -n 10
echo "##accepted"
{ journalctl -u ssh -u sshd --since '24 hours ago' --no-pager -q 2>/dev/null; grep -h sshd /var/log/auth.log 2>/dev/null | tail -n 3000; } | grep 'Accepted ' | sed 's/.*Accepted \([a-z-]*\) for \([^ ]*\) from \([^ ]*\).*/\1|\2|\3/' | sort | uniq -c | sort -rn | head -n 10
echo "##sudo"; journalctl _COMM=sudo --since '24 hours ago' --no-pager -q 2>/dev/null | grep -c 'COMMAND='
echo "##exposed"; ss -Htln 2>/dev/null | awk '$4 ~ /^(0\.0\.0\.0|\[::\]|\*):/ {print $4}' | sort -u | head -n 30
echo "##dockerports"; if [ -n "$D" ]; then $D ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0|:::' | cut -c1-200; fi
echo "##users"; awk -F: '($3==0 || $3>=1000) && $7 !~ /(nologin|false)$/ {print $1"|"$3"|"$7}' /etc/passwd 2>/dev/null
echo "##admins"; getent group sudo wheel admin docker 2>/dev/null | cut -c1-200
echo "##updates"
if command -v apt-get >/dev/null 2>&1; then echo "apt|$($T apt-get -s upgrade 2>/dev/null | grep -c '^Inst')|$($T apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci security)"; fi
if command -v dnf >/dev/null 2>&1; then echo "dnf|$($T dnf -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.[a-z0-9_]+ ')|"; fi
[ -e /var/run/reboot-required ] && echo "reboot-required|1|"
echo "##timesync"; timedatectl show -p NTPSynchronized -p NTP 2>/dev/null; chronyc tracking 2>/dev/null | grep -E 'System time|Last offset'
echo "##firewall"; for F in ufw firewalld nftables iptables; do echo "$F|$(systemctl is-active $F 2>/dev/null | head -n 1)"; done
echo "##end"
'''


def linux_body(name: str) -> str:
    return LINUX_BODIES[name].replace("@CONTAINER_MAP@", CONTAINER_MAP).replace("@VERSION@", str(SCRIPT_VERSION))


def linux_script(name: str) -> str:
    """The whole text for one probe (preamble + body), for sending directly."""
    return PREAMBLE + linux_body(name)


LINUX_SCRIPT = linux_script("storage")                 # kept: the storage probe is the one most of the tests and the docs talk about
LINUX_COMMANDS = {name: "sh -c '" + linux_script(name).replace("'", "'\\''") + "'" for name in PROBES}
LINUX_COMMAND = LINUX_COMMANDS["storage"]


def locked_command(name: str) -> str:
    """What Netlens asks first; a host that is locked down runs its own script for that name and refuses every other command."""
    return f"{WRAPPER_NAME} {name}"


LOCKED_COMMAND = locked_command("storage")

# ----------------------------------------------------------------------------- Windows (PowerShell 5.1)
WINDOWS: dict[str, str] = {}

# The walk is depth first with a time budget: a very large disk gives a partial answer, flagged as such.
WINDOWS["storage"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"
    "$sw=[Diagnostics.Stopwatch]::StartNew();$budget=100;"
    "$script:big=New-Object System.Collections.ArrayList;$script:dirs=@{};"
    "function Walk([IO.DirectoryInfo]$d,[int]$depth){"
    "if($sw.Elapsed.TotalSeconds -gt $budget){return [int64]0};[int64]$t=0;"
    "try{foreach($f in $d.EnumerateFiles()){$t+=$f.Length;if($f.Length -gt 209715200){[void]$script:big.Add(@{p=$f.FullName;s=[int64]$f.Length;m=$f.LastWriteTimeUtc.ToString('o')})}}}catch{};"
    "try{foreach($s in $d.EnumerateDirectories()){if(($s.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue};$t+=(Walk $s ($depth+1))}}catch{};"
    "if($depth -le 2){$script:dirs[$d.FullName]=$t};return $t};"
    "$r=@{vols=@();dirs=@();big=@();partial=$false;version=@VERSION@};"
    "$vols=@([IO.DriveInfo]::GetDrives()|?{$_.DriveType -eq 'Fixed' -and $_.IsReady});"
    "foreach($v in $vols){$r.vols+=@{id=$v.Name.TrimEnd('\\');size=[int64]$v.TotalSize;free=[int64]$v.AvailableFreeSpace}};"
    "foreach($v in $vols){[void](Walk (New-Object IO.DirectoryInfo $v.RootDirectory.FullName) 0)};"
    "$r.partial=($sw.Elapsed.TotalSeconds -gt $budget);"
    "$r.dirs=@($script:dirs.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 60|%{@{p=$_.Key;s=[int64]$_.Value}});"
    "$r.big=@($script:big|Sort-Object {$_.s} -Descending|Select-Object -First 25);"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 5"
)

# CPU: two samples of the per-process counters 2 seconds apart (a cumulative total says nothing about NOW)
WINDOWS["cpu"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "$cpus=[Environment]::ProcessorCount;$r.cpus=$cpus;"
    "$a=@{};foreach($p in Get-Process){$a[$p.Id]=@{n=$p.ProcessName;c=[double]$p.CPU;ws=[int64]$p.WorkingSet64}};Start-Sleep -Seconds 2;"
    "$rows=@();foreach($p in Get-Process){$o=$a[$p.Id];if($o -and $p.CPU -ne $null){$rows+=@{id=$p.Id;n=$p.ProcessName;cpu=[math]::Round((([double]$p.CPU-$o.c)/2)*100,1);ws=[int64]$p.WorkingSet64}}};"
    "$r.procs=@($rows|Sort-Object {$_.cpu} -Descending|Select-Object -First 12);"
    "try{$r.load=(Get-CimInstance Win32_Processor|Measure-Object LoadPercentage -Average).Average}catch{};"
    "try{$r.queue=(Get-Counter '\\System\\Processor Queue Length' -ErrorAction Stop).CounterSamples[0].CookedValue}catch{};"
    "try{$r.diskq=(Get-Counter '\\PhysicalDisk(_Total)\\Current Disk Queue Length' -ErrorAction Stop).CounterSamples[0].CookedValue}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["memory"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "try{$o=Get-CimInstance Win32_OperatingSystem;$r.total_kb=[double]$o.TotalVisibleMemorySize;$r.free_kb=[double]$o.FreePhysicalMemory;$r.commit_total_kb=[double]$o.TotalVirtualMemorySize;$r.commit_free_kb=[double]$o.FreeVirtualMemory}catch{};"
    "$r.procs=@(Get-Process|Sort-Object WorkingSet64 -Descending|Select-Object -First 12|%{@{id=$_.Id;n=$_.ProcessName;ws=[int64]$_.WorkingSet64;pm=[int64]$_.PrivateMemorySize64}});"
    "try{$r.pagefile=@(Get-CimInstance Win32_PageFileUsage|%{@{n=$_.Name;used=[int64]$_.CurrentUsage;size=[int64]$_.AllocatedBaseSize}})}catch{};"
    "try{$r.events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=2004;StartTime=(Get-Date).AddHours(-72)} -MaxEvents 5|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');m=($_.Message -replace '\\s+',' ').Substring(0,[math]::Min(200,$_.Message.Length))}})}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["network"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "$s1=@{};foreach($a in Get-NetAdapterStatistics){$s1[$a.Name]=$a};Start-Sleep -Seconds 1;"
    "$r.nics=@(Get-NetAdapterStatistics|%{$o=$s1[$_.Name];@{n=$_.Name;rx=[double]($_.ReceivedBytes-$o.ReceivedBytes)*8;tx=[double]($_.SentBytes-$o.SentBytes)*8;rxerr=[double]$_.ReceivedPacketErrors;txerr=[double]$_.OutboundPacketErrors;rxdrop=[double]$_.ReceivedDiscardedPackets;txdrop=[double]$_.OutboundDiscardedPackets}});"
    "$c=@(Get-NetTCPConnection);$r.states=@($c|Group-Object State|%{@{s=[string]$_.Name;c=$_.Count}});"
    "$r.remote=@($c|Where-Object{$_.State -eq 'Established'}|Group-Object RemoteAddress|Sort-Object Count -Descending|Select-Object -First 10|%{@{ip=[string]$_.Name;c=$_.Count}});"
    "$names=@{};foreach($p in Get-Process){$names[$p.Id]=$p.ProcessName};"
    "$r.processes=@($c|Where-Object{$_.State -eq 'Established'}|Group-Object OwningProcess|Sort-Object Count -Descending|Select-Object -First 8|%{@{n=[string]$names[[int]$_.Name];c=$_.Count}});"
    "$r.listening=@($c|Where-Object{$_.State -eq 'Listen'}|Select-Object -First 25|%{@{a=($_.LocalAddress+':'+$_.LocalPort);n=[string]$names[[int]$_.OwningProcess]}});"
    "try{$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Sort-Object RouteMetric|Select-Object -First 1).NextHop;$r.gateway=$gw;"
    "$r.ping=@(@{t='gateway';ip=$gw},@{t='internet';ip='1.1.1.1'}|%{$x=Test-Connection -ComputerName $_.ip -Count 3 -ErrorAction SilentlyContinue;@{t=$_.t;ip=$_.ip;ok=@($x).Count;ms=if($x){[math]::Round(($x|Measure-Object ResponseTime -Average).Average,1)}else{$null}}})}catch{};"
    "$sw=[Diagnostics.Stopwatch]::StartNew();try{[void][Net.Dns]::GetHostAddresses('example.com');$r.dns=@{ok=$true;ms=$sw.ElapsedMilliseconds}}catch{$r.dns=@{ok=$false;ms=$sw.ElapsedMilliseconds}};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["apps"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "try{$r.boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}catch{};"
    "$r.services=@(Get-CimInstance Win32_Service -Filter \"StartMode='Auto' AND State<>'Running' AND ExitCode<>0 AND ExitCode<>1077\"|Select-Object -First 20|%{@{n=[string]$_.DisplayName;state=[string]$_.State;exit=[int]$_.ExitCode}});"
    "try{$e=@(Get-WinEvent -FilterHashtable @{LogName='Application','System';Level=1,2;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 300);"
    "$r.errors=@($e|Group-Object ProviderName|Sort-Object Count -Descending|Select-Object -First 10|%{@{n=[string]$_.Name;c=$_.Count}});"
    "$r.sample=@($e|Select-Object -First 6|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');n=[string]$_.ProviderName;m=(($_.Message -replace '\\s+',' ')+'').Substring(0,[math]::Min(160,(($_.Message+'').Length)))}})}catch{};"
    "try{$r.crashes=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1002;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');m=(($_.Message -replace '\\s+',' ')+'').Substring(0,[math]::Min(160,(($_.Message+'').Length)))}})}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["changes"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "$since=(Get-Date).AddDays(-3);"
    "try{$r.boots=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1074,6005,6006,6008;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 15|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');id=$_.Id}})}catch{};"
    "try{$r.hotfixes=@(Get-HotFix|Where-Object{$_.InstalledOn -ge $since}|Select-Object -First 15|%{@{id=[string]$_.HotFixID;t=$_.InstalledOn.ToUniversalTime().ToString('o')}})}catch{};"
    "try{$r.installs=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';Id=11707,11724;StartTime=$since} -MaxEvents 20|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');m=(($_.Message -replace '\\s+',' ')+'').Substring(0,[math]::Min(140,(($_.Message+'').Length)))}})}catch{};"
    "try{$r.services=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -MaxEvents 10|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');m=(($_.Message -replace '\\s+',' ')+'').Substring(0,[math]::Min(140,(($_.Message+'').Length)))}})}catch{};"
    "try{$r.users=@(Get-LocalUser|Where-Object{$_.Enabled}|%{@{n=$_.Name;pwd=if($_.PasswordLastSet){$_.PasswordLastSet.ToUniversalTime().ToString('o')}else{$null}}})}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["schedule"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "$r.tasks=@(Get-ScheduledTask|Where-Object{$_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*'}|Select-Object -First 60|%{$i=$_|Get-ScheduledTaskInfo;"
    "@{n=($_.TaskPath+$_.TaskName);last=if($i.LastRunTime -and $i.LastRunTime.Year -gt 2000){$i.LastRunTime.ToUniversalTime().ToString('o')}else{$null};next=if($i.NextRunTime -and $i.NextRunTime.Year -gt 2000){$i.NextRunTime.ToUniversalTime().ToString('o')}else{$null};res=[int]$i.LastTaskResult}});"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["hardware"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "try{$r.disks=@(Get-PhysicalDisk|%{$c=$_|Get-StorageReliabilityCounter;@{n=[string]$_.FriendlyName;health=[string]$_.HealthStatus;op=[string]$_.OperationalStatus;temp=$c.Temperature;wear=$c.Wear;rerr=$c.ReadErrorsTotal;werr=$c.WriteErrorsTotal}})}catch{};"
    "try{$r.volumes=@(Get-Volume|Where-Object{$_.DriveLetter}|%{@{d=[string]$_.DriveLetter;health=[string]$_.HealthStatus;size=[int64]$_.Size;free=[int64]$_.SizeRemaining}})}catch{};"
    "try{$r.ioerrors=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7,11,15,51,55,129,153;StartTime=(Get-Date).AddDays(-3)} -MaxEvents 12|%{@{t=$_.TimeCreated.ToUniversalTime().ToString('o');id=$_.Id;m=(($_.Message -replace '\\s+',' ')+'').Substring(0,[math]::Min(160,(($_.Message+'').Length)))}})}catch{};"
    "try{$r.battery=@(Get-CimInstance Win32_Battery|%{@{charge=$_.EstimatedChargeRemaining;status=$_.BatteryStatus}})}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)

WINDOWS["security"] = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';$r=@{version=@VERSION@};"
    "$since=(Get-Date).AddHours(-24);"
    "try{$f=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -MaxEvents 2000);"
    "$r.failed_total=$f.Count;$r.failed=@($f|ForEach-Object{$x=[xml]$_.ToXml();($x.Event.EventData.Data|Where-Object{$_.Name -eq 'IpAddress'}).'#text'}|Where-Object{$_}|Group-Object|Sort-Object Count -Descending|Select-Object -First 10|%{@{ip=[string]$_.Name;c=$_.Count}})}catch{};"
    "try{$r.admins=@(Get-LocalGroupMember -SID S-1-5-32-544|%{[string]$_.Name})}catch{};"
    "try{$r.users=@(Get-LocalUser|Where-Object{$_.Enabled}|%{[string]$_.Name})}catch{};"
    "try{$m=Get-MpComputerStatus;$r.defender=@{enabled=$m.RealTimeProtectionEnabled;sig_age=$m.AntivirusSignatureAge}}catch{};"
    "try{$r.firewall=@(Get-NetFirewallProfile|%{@{n=[string]$_.Name;on=[bool]$_.Enabled}})}catch{};"
    "try{$r.reboot_pending=[bool](Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')}catch{};"
    "try{$r.time=(w32tm /query /status|Out-String).Substring(0,[math]::Min(400,(w32tm /query /status|Out-String).Length))}catch{};"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 4"
)


def windows_script(name: str) -> str:
    return WINDOWS[name].replace("@VERSION@", str(SCRIPT_VERSION))


WINDOWS_SCRIPT = windows_script("storage")


def powershell(script: str) -> str:
    """The command line that runs `script` in PowerShell without any quoting problems."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"


WINDOWS_COMMANDS = {name: powershell(windows_script(name)) for name in PROBES}
WINDOWS_COMMAND = WINDOWS_COMMANDS["storage"]
WINDOWS_WRAPPER_PATH = r"C:\ProgramData\netlens\probe.ps1"


# ----------------------------------------------------------------------------- the host side: what to install so that nothing else can be run
def linux_wrapper() -> str:
    """/usr/local/sbin/netlens-probe: owned by root, not writable by anyone else. `netlens-probe <name>` runs one of the probes above and nothing else."""
    cases = "\n".join(f"  {name}) probe_{name} ;;" for name in PROBES)
    functions = "\n".join(f"probe_{name}() {{\n{linux_body(name)}}}" for name in PROBES)
    return ("#!/bin/sh\n# Installed for Netlens. Read-only: reports on the host (storage, processor, memory, network, applications). Generated by Netlens; do not edit.\n"
            + PREAMBLE + functions + f'\ncase "${{1:-storage}}" in\n{cases}\n  *) echo "unknown probe" >&2; exit 2 ;;\nesac\n')


def linux_entry() -> str:
    """/usr/local/sbin/netlens-probe-entry: what sshd runs for the account whatever the client asks. It accepts exactly `netlens-probe <name>`."""
    names = "|".join(f'"{WRAPPER_NAME} {n}"' for n in PROBES)
    return ("#!/bin/sh\n# Installed for Netlens: the only command the probe account may run. Generated by Netlens; do not edit.\n"
            f'case "$SSH_ORIGINAL_COMMAND" in\n  {names})\n    exec sudo -n {WRAPPER_PATH} "${{SSH_ORIGINAL_COMMAND#{WRAPPER_NAME} }}" ;;\n'
            '  *) echo "refused" >&2; exit 2 ;;\nesac\n')


def linux_setup(user: str, public_key: str | None, ca_public_key: str | None) -> dict[str, str]:
    """The files and lines that lock a Linux host down, for a key (authorized_keys) or for certificates from the Netlens CA (sshd_config)."""
    sudoers = f"{user} ALL=(root) NOPASSWD: " + ", ".join(f"{WRAPPER_PATH} {n}" for n in PROBES) + "\n"
    out = {
        "install": (f"sudo useradd --system --create-home --shell /bin/sh {user}\n"
                    f"sudo install -m 0755 -o root -g root /dev/stdin {WRAPPER_PATH} <<'NETLENS_EOF'\n{linux_wrapper()}NETLENS_EOF\n"
                    f"sudo install -m 0755 -o root -g root /dev/stdin {ENTRY_PATH} <<'NETLENS_EOF'\n{linux_entry()}NETLENS_EOF\n"
                    f"echo '{sudoers.strip()}' | sudo tee /etc/sudoers.d/netlens-probe >/dev/null && sudo chmod 0440 /etc/sudoers.d/netlens-probe && sudo visudo -cf /etc/sudoers.d/netlens-probe\n"),
        "sudoers": sudoers,
        "script": linux_wrapper(),
        "entry": linux_entry(),
    }
    if public_key:
        out["authorized_keys"] = f'command="{ENTRY_PATH}",restrict {public_key.strip()}\n'
    if ca_public_key:
        out["sshd_config"] = (f"# trust certificates signed by the Netlens CA, for the user {user} only, and run the probe entry whatever is asked\n"
                              f"TrustedUserCAKeys /etc/ssh/netlens_ca.pub\nMatch User {user}\n    ForceCommand {ENTRY_PATH}\n    PermitTTY no\n    X11Forwarding no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n")
        out["ca_public_key"] = ca_public_key.strip() + "\n"
    return out


def windows_wrapper() -> str:
    """C:\\ProgramData\\netlens\\probe.ps1: runs one of the probes by the name the client asked for and refuses every other command."""
    names = ", ".join(f"'{n}'" for n in PROBES)
    blocks = "\n".join(f"function Probe-{n} {{\n{windows_script(n).replace(';', ';' + chr(10))}\n}}" for n in PROBES)
    return (f"# Installed for Netlens. Read-only. Generated by Netlens; do not edit.\n{blocks}\n"
            f"$ask = [string]$env:SSH_ORIGINAL_COMMAND\n$name = if ($ask -match '^netlens-probe (\\w+)$') {{ $Matches[1] }} else {{ '' }}\n"
            f"if (@({names}) -notcontains $name) {{ [Console]::Error.WriteLine('refused'); exit 2 }}\n& \"Probe-$name\"\n")


def windows_setup(user: str, public_key: str | None, ca_public_key: str | None) -> dict[str, str]:
    """The same for Windows with the OpenSSH server (Windows 10/11, Server 2019+): a local account that can only run the probe script."""
    script_path = WINDOWS_WRAPPER_PATH
    install = (
        "# run in an elevated PowerShell\n"
        f"New-Item -ItemType Directory -Force 'C:\\ProgramData\\netlens' | Out-Null\n"
        f"Set-Content -Path '{script_path}' -Encoding UTF8 -Value @'\n{windows_wrapper()}\n'@\n"
        f"icacls 'C:\\ProgramData\\netlens' /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' '{user}:(OI)(CI)RX' | Out-Null\n"
        f"$p = ConvertTo-SecureString -AsPlainText -Force ([guid]::NewGuid().ToString())\n"
        f"New-LocalUser -Name '{user}' -Password $p -PasswordNeverExpires -Description 'Netlens read-only probe' | Out-Null\n"
        "# The account sees only what it may read. Grant it read access to the folders or disks that matter (this can take a while on a large disk):\n"
        f"# icacls 'D:\\\\' /grant '{user}:(OI)(CI)RX'\n"
        "# For the Application and System event logs (the applications probe): net localgroup 'Event Log Readers' " + user + " /add\n"
        "# For performance counters (the processor probe):                      net localgroup 'Performance Monitor Users' " + user + " /add\n"
    )
    out = {"install": install, "script": windows_wrapper()}
    force = f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {script_path}'
    if public_key:
        out["authorized_keys"] = (f'# C:\\ProgramData\\ssh\\administrators_authorized_keys is for administrators; for {user} use C:\\Users\\{user}\\.ssh\\authorized_keys\n'
                                  f'command="{force}",restrict {public_key.strip()}\n')
    if ca_public_key:
        out["sshd_config"] = (f"# C:\\ProgramData\\ssh\\sshd_config: trust certificates signed by the Netlens CA, for {user} only, and run the probe whatever is asked\n"
                              f"TrustedUserCAKeys C:\\ProgramData\\ssh\\netlens_ca.pub\nMatch User {user}\n    ForceCommand {force}\n    AllowTcpForwarding no\n")
        out["ca_public_key"] = ca_public_key.strip() + "\n"
    return out
