"""The read-only probes that are run on a host, and the files that lock a host down so that it can run nothing else.

One probe exists: `storage`, which answers "what uses the disk space?": the biggest directories of every local disk, the biggest
files, what Docker holds (images, container layers, container logs) and files that were deleted but are still held open.
It only reads. It runs at the lowest CPU and disk priority and every part has a time limit, so a slow disk cannot make it pile up.

The same text is used in three places: sent directly by Netlens (no set-up on the host), installed on the host as a root-owned
script that an SSH key or certificate is bound to (the host then allows nothing else), and described in the set-up help.
"""

from __future__ import annotations

import base64

PROBES = ("storage",)
WRAPPER_PATH = "/usr/local/sbin/netlens-probe"
WRAPPER_NAME = "netlens-probe"

# Plain sh syntax only (the login shell may be anything). The marker lines start with ## and are parsed by app/hostprobe/parse.py.
LINUX_SCRIPT = r'''PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
R=""
if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then R="sudo -n"; fi
T=""; command -v timeout >/dev/null 2>&1 && T="timeout 100"
N=""; command -v nice >/dev/null 2>&1 && N="nice -n 19"
command -v ionice >/dev/null 2>&1 && N="$N ionice -c3"
echo "##host"; uname -sr 2>/dev/null; id -u
echo "##df"; df -PkT 2>/dev/null
for M in $(df -PkT 2>/dev/null | awk 'NR>1 && $2 !~ /^(tmpfs|devtmpfs|squashfs|overlay|nfs|nfs4|cifs|smb3|smbfs|fuse.*|9p|proc|sysfs|cgroup.*|ramfs|iso9660|efivarfs|autofs)$/ && $7 ~ /^\// {print $7}' | sort -u | head -n 6); do
  echo "##du $M"; $R $T $N du -xk -d 2 "$M" 2>/dev/null | sort -rn | head -n 45
  echo "##big $M"; $R $T $N find "$M" -xdev -type f -size +200M -printf '%s\t%T@\t%p\n' 2>/dev/null | sort -rn | head -n 25
done
D=""
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then D="docker"; elif [ -n "$R" ] && $R docker info >/dev/null 2>&1; then D="$R docker"; fi
fi
if [ -n "$D" ]; then
  echo "##dockerdf"; $D system df --format '{{.Type}}|{{.TotalCount}}|{{.Active}}|{{.Size}}|{{.Reclaimable}}' 2>/dev/null
  echo "##dockerps"; $D ps -a -s --format '{{.Names}}|{{.Status}}|{{.Size}}' 2>/dev/null
  echo "##dockerlogs"
  for C in $($D ps -aq 2>/dev/null); do $D inspect --format '{{.Name}}|{{.LogPath}}|{{.RestartCount}}' "$C" 2>/dev/null; done | while IFS='|' read -r NAME LOG RC; do
    [ -n "$LOG" ] && echo "$NAME|$($R stat -c %s "$LOG" 2>/dev/null)|$RC"
  done
fi
echo "##deleted"
if command -v lsof >/dev/null 2>&1; then $R $T lsof -nP +L1 2>/dev/null | awk 'NR>1 && $7+0 > 10485760 {print $7"|"$1"|"$NF}' | sort -rn | head -n 10; fi
echo "##end"
'''

LINUX_COMMAND = "sh -c '" + LINUX_SCRIPT.replace("'", "'\\''") + "'"
LOCKED_COMMAND = f"{WRAPPER_NAME} storage"        # what Netlens asks first; a host that is locked down runs its own script whatever is asked

# Windows: PowerShell 5.1. The walk is depth first with a time budget: a very large disk gives a partial answer, flagged as such.
WINDOWS_SCRIPT = (
    "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"
    "$sw=[Diagnostics.Stopwatch]::StartNew();$budget=100;"
    "$script:big=New-Object System.Collections.ArrayList;$script:dirs=@{};"
    "function Walk([IO.DirectoryInfo]$d,[int]$depth){"
    "if($sw.Elapsed.TotalSeconds -gt $budget){return [int64]0};[int64]$t=0;"
    "try{foreach($f in $d.EnumerateFiles()){$t+=$f.Length;if($f.Length -gt 209715200){[void]$script:big.Add(@{p=$f.FullName;s=[int64]$f.Length;m=$f.LastWriteTimeUtc.ToString('o')})}}}catch{};"
    "try{foreach($s in $d.EnumerateDirectories()){if(($s.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue};$t+=(Walk $s ($depth+1))}}catch{};"
    "if($depth -le 2){$script:dirs[$d.FullName]=$t};return $t};"
    "$r=@{vols=@();dirs=@();big=@();partial=$false};"
    "$vols=@([IO.DriveInfo]::GetDrives()|?{$_.DriveType -eq 'Fixed' -and $_.IsReady});"
    "foreach($v in $vols){$r.vols+=@{id=$v.Name.TrimEnd('\\');size=[int64]$v.TotalSize;free=[int64]$v.AvailableFreeSpace}};"
    "foreach($v in $vols){[void](Walk (New-Object IO.DirectoryInfo $v.RootDirectory.FullName) 0)};"
    "$r.partial=($sw.Elapsed.TotalSeconds -gt $budget);"
    "$r.dirs=@($script:dirs.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 60|%{@{p=$_.Key;s=[int64]$_.Value}});"
    "$r.big=@($script:big|Sort-Object {$_.s} -Descending|Select-Object -First 25);"
    "'##netlens-probe';$r|ConvertTo-Json -Compress -Depth 5"
)


def powershell(script: str) -> str:
    """The command line that runs `script` in PowerShell without any quoting problems."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"


WINDOWS_COMMAND = powershell(WINDOWS_SCRIPT)
WINDOWS_WRAPPER_PATH = r"C:\ProgramData\netlens\probe.ps1"


# ----------------------------------------------------------------------------- the host side: what to install so that nothing else can be run
def linux_wrapper() -> str:
    """/usr/local/sbin/netlens-probe: owned by root, not writable by anyone else. The SSH key or certificate is bound to running this and nothing else."""
    return "#!/bin/sh\n# Installed for Netlens. Read-only: reports what uses the disk space. Generated by Netlens; do not edit.\n" + LINUX_SCRIPT


def linux_setup(user: str, public_key: str | None, ca_public_key: str | None) -> dict[str, str]:
    """The files and lines that lock a Linux host down, for a key (authorized_keys) or for certificates from the Netlens CA (sshd_config)."""
    wrapper = f"sudo -n {WRAPPER_PATH}"
    sudoers = f"{user} ALL=(root) NOPASSWD: {WRAPPER_PATH}\n"
    out = {
        "install": (f"sudo useradd --system --create-home --shell /bin/sh {user}\n"
                    f"sudo install -m 0755 -o root -g root /dev/stdin {WRAPPER_PATH} <<'NETLENS_EOF'\n{linux_wrapper()}NETLENS_EOF\n"
                    f"echo '{sudoers.strip()}' | sudo tee /etc/sudoers.d/netlens-probe >/dev/null && sudo chmod 0440 /etc/sudoers.d/netlens-probe && sudo visudo -cf /etc/sudoers.d/netlens-probe\n"),
        "sudoers": sudoers,
        "script": linux_wrapper(),
    }
    if public_key:
        out["authorized_keys"] = f'command="{wrapper}",restrict {public_key.strip()}\n'
    if ca_public_key:
        out["sshd_config"] = (f"# trust certificates signed by the Netlens CA, for the user {user} only, and run the probe whatever is asked\n"
                              f"TrustedUserCAKeys /etc/ssh/netlens_ca.pub\nMatch User {user}\n    ForceCommand {wrapper}\n    PermitTTY no\n    X11Forwarding no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n")
        out["ca_public_key"] = ca_public_key.strip() + "\n"
    return out


def windows_setup(user: str, public_key: str | None, ca_public_key: str | None) -> dict[str, str]:
    """The same for Windows with the OpenSSH server (Windows 10/11, Server 2019+): a local account that can only run the probe script."""
    script_path = WINDOWS_WRAPPER_PATH
    install = (
        "# run in an elevated PowerShell\n"
        f"New-Item -ItemType Directory -Force 'C:\\ProgramData\\netlens' | Out-Null\n"
        f"Set-Content -Path '{script_path}' -Encoding UTF8 -Value @'\n{WINDOWS_SCRIPT.replace(';', ';' + chr(10))}\n'@\n"
        f"icacls 'C:\\ProgramData\\netlens' /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' '{user}:(OI)(CI)RX' | Out-Null\n"
        f"$p = ConvertTo-SecureString -AsPlainText -Force ([guid]::NewGuid().ToString())\n"
        f"New-LocalUser -Name '{user}' -Password $p -PasswordNeverExpires -Description 'Netlens read-only probe' | Out-Null\n"
        "# The account sees only what it may read. Grant it read access to the folders or disks that matter (this can take a while on a large disk):\n"
        f"# icacls 'D:\\' /grant '{user}:(OI)(CI)RX'\n"
    )
    out = {"install": install, "script": WINDOWS_SCRIPT}
    force = f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {script_path}'
    if public_key:
        out["authorized_keys"] = (f'# C:\\ProgramData\\ssh\\administrators_authorized_keys is for administrators; for {user} use C:\\Users\\{user}\\.ssh\\authorized_keys\n'
                                  f'command="{force}",restrict {public_key.strip()}\n')
    if ca_public_key:
        out["sshd_config"] = (f"# C:\\ProgramData\\ssh\\sshd_config: trust certificates signed by the Netlens CA, for {user} only, and run the probe whatever is asked\n"
                              f"TrustedUserCAKeys C:\\ProgramData\\ssh\\netlens_ca.pub\nMatch User {user}\n    ForceCommand {force}\n    AllowTcpForwarding no\n")
        out["ca_public_key"] = ca_public_key.strip() + "\n"
    return out
