"""Install, update, check and remove the host probe from within Netlens.

The probes themselves run as an account that can do nothing but run them, so they cannot install themselves: putting the script and the account on a host needs
administrator rights there, once. Netlens does the steps you would do by hand, with an administrator login that you type for that one action:

  * the login is used for this action only. It is never stored and never written to a log or to the audit log (only who used which account on which host);
  * every step is shown; a check changes nothing; every change to the SSH server configuration is backed up and tested (sshd -t) before it takes effect, and
    put back when the test fails;
  * the host is only touched in these places: the account, /usr/local/sbin/netlens-probe*, /etc/sudoers.d/netlens-probe, /etc/ssh/netlens_ca.pub and two marked
    blocks in sshd_config (Windows: C:\\ProgramData\\netlens, the OpenSSH configuration). `remove` takes them out again.

Linux is done through SSH with sudo (or root). Windows through the OpenSSH server with an administrator account (written for PowerShell 5.1, not yet run on a real Windows host).
"""

from __future__ import annotations

import re
import shlex
from typing import Any

from app.hostmetrics import service as hm, ssh
from app.hostprobe import credentials, scripts, service

BLOCK_BEGIN = "# >>> netlens-probe"
BLOCK_END = "# <<< netlens-probe"
CA_FILE = "/etc/ssh/netlens_ca.pub"
SUDOERS_FILE = "/etc/sudoers.d/netlens-probe"
ACTIONS = ("check", "install", "update", "remove")
WINDOWS_STDIN = "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -"          # the script goes in on stdin: it is far too long for a command line


class InstallError(Exception):
    pass


def linux_script(action: str, user: str, ca_public_key: str, password: str | None, sudo_password: str | None, as_root: bool) -> str:
    """The shell script that is sent to the host on stdin. The sudo password is a shell variable in the script (stdin): it is not on a command line and not in the environment."""
    setup = scripts.linux_setup(user, None, ca_public_key)
    pw = shlex.quote(sudo_password if sudo_password is not None else (password or ""))
    sudo = '"$@"' if as_root else "printf '%s\\n' \"$PW\" | sudo -S -p '' \"$@\""
    wrapper, entry, sudoers, ca = setup["script"], setup["entry"], setup["sudoers"], setup["ca_public_key"]
    sshd_global = f"{BLOCK_BEGIN} (global) >>>\nTrustedUserCAKeys {CA_FILE}\n{BLOCK_END} (global) <<<\n"
    sshd_match = (f"{BLOCK_BEGIN} >>>\nMatch User {user}\n    ForceCommand {scripts.ENTRY_PATH}\n    PermitTTY no\n    X11Forwarding no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n{BLOCK_END} <<<\n")
    return f'''PW={pw}
S() {{ {sudo}; }}
say() {{ echo "NETLENS: $*"; }}
ACTION={shlex.quote(action)}
USER_={shlex.quote(user)}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
say "step connected as $(id -un) on $(hostname)"
if ! command -v sudo >/dev/null 2>&1 && [ "$(id -u)" != "0" ]; then say "error sudo is not installed and this login is not root"; exit 3; fi
if ! S true >/dev/null 2>&1; then say "error this login may not use sudo (or the password for sudo is wrong)"; exit 3; fi
INST=""; [ -r {scripts.WRAPPER_PATH} ] && INST=$(grep -m1 'netlens-probe-script-version' {scripts.WRAPPER_PATH} | awk '{{print $NF}}')
say "result installed_version=${{INST:-none}}"
say "result account=$(id "$USER_" >/dev/null 2>&1 && echo yes || echo no)"
say "result sshd_block=$(grep -q '{BLOCK_BEGIN}' /etc/ssh/sshd_config 2>/dev/null && echo yes || echo no)"
say "result ca_file=$([ -r {CA_FILE} ] && echo yes || echo no)"
if [ "$ACTION" = "check" ]; then say "done check: nothing was changed"; exit 0; fi
STAMP=$(date +%Y%m%d%H%M%S)
unmanaged() {{ awk -v b='{BLOCK_BEGIN}' -v e='{BLOCK_END}' '
  index($0, b) == 1 {{ skip = 1 }}
  skip != 1 {{ print }}
  index($0, e) == 1 {{ skip = 0 }}' "$1" | awk '
  /^# Netlens read-only probe \\(added by Netlens/ {{ leg = 1; next }}
  leg == 1 {{ if ($0 ~ /^[[:space:]]*AllowAgentForwarding[[:space:]]+no/) leg = 0; next }}
  {{ print }}'; }}
unmanaged /etc/ssh/sshd_config > "$W/sshd_clean"
if [ "$ACTION" != "remove" ]; then
  OTHER=$(grep -rEi '^[[:space:]]*TrustedUserCAKeys' "$W/sshd_clean" /etc/ssh/sshd_config.d/ 2>/dev/null | grep -v '{CA_FILE}' | head -n 1)
  if [ -n "$OTHER" ]; then say "error this host already trusts another certificate authority ($OTHER): add the Netlens CA public key to that file instead, or use a key login for the probe account"; exit 4; fi
  cat > "$W/probe" <<'NETLENS_SCRIPT_EOF'
{wrapper}NETLENS_SCRIPT_EOF
  cat > "$W/entry" <<'NETLENS_ENTRY_EOF'
{entry}NETLENS_ENTRY_EOF
  cat > "$W/sudoers" <<'NETLENS_SUDO_EOF'
{sudoers}NETLENS_SUDO_EOF
  cat > "$W/ca.pub" <<'NETLENS_CA_EOF'
{ca}NETLENS_CA_EOF
  cat > "$W/global" <<'NETLENS_G_EOF'
{sshd_global}NETLENS_G_EOF
  cat > "$W/match" <<'NETLENS_M_EOF'
{sshd_match}NETLENS_M_EOF
  if ! id "$USER_" >/dev/null 2>&1; then S useradd --system --create-home --shell /bin/sh "$USER_" && say "step created the account $USER_"; fi
  S install -m 0755 -o root -g root "$W/probe" {scripts.WRAPPER_PATH} && say "step installed {scripts.WRAPPER_PATH}"
  S install -m 0755 -o root -g root "$W/entry" {scripts.ENTRY_PATH} && say "step installed {scripts.ENTRY_PATH}"
  S install -m 0440 -o root -g root "$W/sudoers" {SUDOERS_FILE}
  if ! S visudo -cf {SUDOERS_FILE} >/dev/null 2>&1; then S rm -f {SUDOERS_FILE}; say "error the sudoers file was refused by visudo and removed"; exit 5; fi
  say "step installed {SUDOERS_FILE} (checked with visudo)"
  S install -m 0644 -o root -g root "$W/ca.pub" {CA_FILE} && say "step installed {CA_FILE}"
  awk -v g="$W/global" 'BEGIN {{ while ((getline line < g) > 0) block = block line "\\n" }} /^[[:space:]]*Match[[:space:]]/ && !done {{ printf "%s", block; done = 1 }} {{ print }} END {{ if (!done) printf "%s", block }}' "$W/sshd_clean" > "$W/sshd_new"
  cat "$W/match" >> "$W/sshd_new"
else
  cp "$W/sshd_clean" "$W/sshd_new"
fi
if ! cmp -s "$W/sshd_new" /etc/ssh/sshd_config; then
  S cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.netlens-backup-$STAMP && say "step backed up sshd_config as sshd_config.netlens-backup-$STAMP"
  S install -m 0644 -o root -g root "$W/sshd_new" /etc/ssh/sshd_config
  if S sshd -t >/dev/null 2>&1; then
    (S systemctl reload ssh || S systemctl reload sshd || S service ssh reload || S service sshd reload) >/dev/null 2>&1 && say "step the SSH server reloaded its configuration"
  else
    S cp -p /etc/ssh/sshd_config.netlens-backup-$STAMP /etc/ssh/sshd_config
    say "error the SSH server configuration did not pass its own test (sshd -t): the old configuration was put back"; exit 6
  fi
else
  say "step the SSH server configuration was already right"
fi
if [ "$ACTION" = "remove" ]; then
  S rm -f {scripts.WRAPPER_PATH} {scripts.ENTRY_PATH} {SUDOERS_FILE} {CA_FILE} && say "step removed the scripts, the sudoers file and the CA key"
  say "step the account $USER_ and its home folder were left (remove them with: userdel -r $USER_)"
  say "done remove"
else
  NEW=$(grep -m1 'netlens-probe-script-version' {scripts.WRAPPER_PATH} | awk '{{print $NF}}')
  say "result installed_version=$NEW"
  say "done $ACTION"
fi
'''


WINDOWS_TEMPLATE = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function say($m) { Write-Output ('NETLENS: ' + $m) }
$action = '@@ACTION@@'; $user = '@@USER@@'; $enableSshd = $@@ENABLE@@; $allowFrom = '@@ALLOW@@'; $deferRestart = $@@DEFER@@
$dir = 'C:\ProgramData\netlens'; $cfg = 'C:\ProgramData\ssh\sshd_config'; $ca = 'C:\ProgramData\ssh\netlens_ca.pub'; $marker = Join-Path $dir 'installed-sshd.txt'
if ($enableSshd -and -not $allowFrom) { $c = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 5985, 5986, 22 } | Select-Object -First 1; if ($c) { $allowFrom = [string]$c.RemoteAddress } }
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { say 'error this login is not an administrator'; exit 3 }
say ('step connected as ' + $env:USERNAME + ' on ' + $env:COMPUTERNAME)
$svc = Get-Service sshd -ErrorAction SilentlyContinue
$inst = 'none'
if (Test-Path (Join-Path $dir 'probe.ps1')) { $m = Select-String -Path (Join-Path $dir 'probe.ps1') -Pattern 'netlens-probe-script-version' -List; if ($m) { $inst = ($m.Line -split ':')[-1].Trim() } }
say ('result installed_version=' + $inst)
say ('result account=' + [bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue))
say ('result sshd_installed=' + [bool]$svc)
say ('result sshd_running=' + [bool]($svc -and $svc.Status -eq 'Running'))
say ('result sshd_by_netlens=' + (Test-Path $marker))
if ($action -eq 'check') { say 'done check: nothing was changed'; exit 0 }

if ($action -ne 'remove') {
    if (-not $svc) {
        if (-not $enableSshd) { say 'error the OpenSSH server is not installed on this host. It is needed for the locked-down probe: choose "also install the OpenSSH server" (Netlens then restricts it to the probe account and to this Netlens), or install it yourself'; exit 7 }
        say 'step installing the Windows OpenSSH Server (this can take a few minutes)'
        # Windows refuses to install a feature for a remote (WinRM) session ("Access is denied": the Windows Update service will not serve it), so it is done locally, as SYSTEM, by a one-time task
        $log = Join-Path $env:TEMP 'netlens-cap.txt'; Remove-Item $log -Force -ErrorAction SilentlyContinue
        $inner = "try { `$r = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'; ('RESULT: ' + (`$r | Out-String)) | Set-Content '$log' -Encoding UTF8 } catch { ('ERROR: ' + `$_.Exception.Message) | Set-Content '$log' -Encoding UTF8 }"
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner)))
        Register-ScheduledTask -TaskName 'NetlensInstallOpenSsh' -Action $act -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName 'NetlensInstallOpenSsh'
        $t0 = Get-Date
        while (((Get-Date) - $t0).TotalSeconds -lt 600) { Start-Sleep -Seconds 3; if (Test-Path $log) { break } }
        Unregister-ScheduledTask -TaskName 'NetlensInstallOpenSsh' -Confirm:$false -ErrorAction SilentlyContinue
        $res = if (Test-Path $log) { (Get-Content $log -Raw).Trim() } else { 'ERROR: no answer after 10 minutes' }
        Remove-Item $log -Force -ErrorAction SilentlyContinue
        if ($res -like 'ERROR*' -or -not (Get-Service sshd -ErrorAction SilentlyContinue)) { say ('error the OpenSSH server could not be installed: ' + ($res -replace '\s+', ' ')); exit 8 }
        New-Item -ItemType Directory -Force $dir | Out-Null
        Set-Content -Path $marker -Value 'The OpenSSH server was installed by Netlens.' -Encoding ASCII
        say 'step installed the OpenSSH Server'
        $svc = Get-Service sshd
    }
    $weInstalled = Test-Path $marker
    if (-not (Test-Path $cfg)) { Start-Service sshd; for ($i = 0; $i -lt 20 -and -not (Test-Path $cfg); $i++) { Start-Sleep -Seconds 1 }; Stop-Service sshd -ErrorAction SilentlyContinue; say 'step the SSH server created its configuration' }
    $text = Get-Content $cfg -Raw
    $text = [regex]::Replace($text, '(?ms)^# >>> netlens-probe.*?^# <<< netlens-probe[^\r\n]*\r?\n?', '')
    if ($text -match '(?im)^\s*TrustedUserCAKeys\s+(?!C:\\ProgramData\\ssh\\netlens_ca\.pub)') { say 'error this host already trusts another certificate authority: add the Netlens CA public key to that file instead'; exit 4 }
    New-Item -ItemType Directory -Force $dir | Out-Null
    $probe = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@PROBE_B64@@'))
    Set-Content -Path (Join-Path $dir 'probe.ps1') -Value ('# netlens-probe-script-version: @@VERSION@@' + [Environment]::NewLine + $probe) -Encoding UTF8
    say 'step installed probe.ps1'
    if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        $p = ConvertTo-SecureString -AsPlainText -Force ([guid]::NewGuid().ToString() + 'aA1!')
        New-LocalUser -Name $user -Password $p -PasswordNeverExpires -UserMayNotChangePassword -Description 'Netlens read-only probe' | Out-Null
        say ('step created the account ' + $user + ' (a random password nobody knows; it signs in with one-time certificates only)')
    }
    foreach ($sid in 'S-1-5-32-573', 'S-1-5-32-558') { try { Add-LocalGroupMember -SID $sid -Member $user -ErrorAction Stop; say ('step added ' + $user + ' to the read-only group ' + (Get-LocalGroup -SID $sid).Name) } catch { } }
    icacls $dir /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' ($user + ':(OI)(CI)RX') | Out-Null
    Set-Content -Path $ca -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@CA_B64@@'))) -Encoding ASCII
    say 'step installed the CA public key'
    $force = 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $dir + '\probe.ps1'
    $globalBody = 'TrustedUserCAKeys ' + $ca
    if ($weInstalled) { $globalBody += "`r`nAllowUsers " + $user + "`r`nPasswordAuthentication no" }
    $gblock = "# >>> netlens-probe (global) >>>`r`n" + $globalBody + "`r`n# <<< netlens-probe (global) <<<`r`n"
    $mblock = "# >>> netlens-probe >>>`r`nMatch User " + $user + "`r`n    ForceCommand " + $force + "`r`n    AllowTcpForwarding no`r`n# <<< netlens-probe <<<`r`n"
    $first = [regex]::Match($text, '(?im)^\s*Match\s')
    if ($first.Success) { $text = $text.Insert($first.Index, $gblock) } else { $text = $text.TrimEnd() + "`r`n`r`n" + $gblock }
    $text = $text.TrimEnd() + "`r`n`r`n" + $mblock
} else {
    $text = if (Test-Path $cfg) { Get-Content $cfg -Raw } else { '' }
    $text = [regex]::Replace($text, '(?ms)^# >>> netlens-probe.*?^# <<< netlens-probe[^\r\n]*\r?\n?', '').TrimEnd()
}
$stamp = Get-Date -Format yyyyMMddHHmmss
if (Test-Path $cfg) {
    $old = Get-Content $cfg -Raw
    if ($old.TrimEnd() -eq $text.TrimEnd()) { say 'step the SSH server configuration was already right' }
    else {
        Copy-Item $cfg ($cfg + '.netlens-backup-' + $stamp)
        say ('step backed up sshd_config as sshd_config.netlens-backup-' + $stamp)
        Set-Content -Path $cfg -Value $text -Encoding ASCII
        & $sshd -t 2>$null
        if ($LASTEXITCODE -ne 0) { Copy-Item ($cfg + '.netlens-backup-' + $stamp) $cfg -Force; say 'error the SSH server configuration did not pass its own test (sshd -t): the old configuration was put back'; exit 6 }
        say 'step the SSH server configuration passed its own test (sshd -t)'
    }
}
if ($action -eq 'remove') {
    Remove-Item (Join-Path $dir 'probe.ps1'), $ca -Force -ErrorAction SilentlyContinue
    say ('step removed the script and the CA key; the account ' + $user + ' was left (Remove-LocalUser ' + $user + ')')
    if (Test-Path $marker) {
        Stop-Service sshd -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
        Get-NetFirewallRule -Name 'netlens-ssh' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Remove-Item $marker -Force
        say 'step the OpenSSH server that Netlens had installed was stopped and disabled (to remove it completely: Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0)'
    } elseif ($svc) { if ($deferRestart) { Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 4; Restart-Service sshd' } else { Restart-Service sshd }; say 'step the SSH server restarts with the cleaned configuration' }
    say 'done remove'
    exit 0
}
if ($weInstalled) {
    $rule = Get-NetFirewallRule -Name 'netlens-ssh' -ErrorAction SilentlyContinue
    if ($rule) { Remove-NetFirewallRule -Name 'netlens-ssh' }
    $fw = @{ Name = 'netlens-ssh'; DisplayName = 'Netlens probe (SSH)'; Protocol = 'TCP'; LocalPort = 22; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any' }
    if ($allowFrom) { $fw['RemoteAddress'] = $allowFrom }
    New-NetFirewallRule @fw | Out-Null
    Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    say ('step the firewall lets only ' + $(if ($allowFrom) { $allowFrom } else { 'the local network' }) + ' reach the SSH server (port 22)')
}
Set-Service sshd -StartupType Automatic
if ($deferRestart) { Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 4; Restart-Service sshd'; say 'step the SSH server restarts in a few seconds (this connection ends)' }
else { Restart-Service sshd; say 'step the SSH server was (re)started' }
say 'result installed_version=@@VERSION@@'
say ('done ' + $action)
"""


def windows_script(action: str, user: str, ca_public_key: str, enable_sshd: bool = False, allow_from: str = "", defer_restart: bool = False) -> str:
    """PowerShell for a Windows host (run as an administrator): over WinRM, or over SSH on stdin when the OpenSSH server is already there. Uses the OpenSSH server as the locked-down way in:
    when Netlens has to install it, it restricts it to the probe account and (when known) to this Netlens in the firewall."""
    import base64

    return (WINDOWS_TEMPLATE.replace("@@ACTION@@", action).replace("@@USER@@", user).replace("@@ENABLE@@", "true" if enable_sshd else "false").replace("@@ALLOW@@", allow_from)
            .replace("@@DEFER@@", "true" if defer_restart else "false").replace("@@VERSION@@", str(scripts.SCRIPT_VERSION))
            .replace("@@PROBE_B64@@", base64.b64encode(scripts.windows_wrapper().encode()).decode()).replace("@@CA_B64@@", base64.b64encode((ca_public_key.strip() + "\n").encode()).decode()))


def winrm_upload_and_run(script: str, session_factory, total: float = 900.0, chunk: int = 2000) -> tuple[str, str, int]:
    """Run a long PowerShell script over WinRM, which only takes short command lines: the script is compressed, sent in small pieces into a temporary file and run from there."""
    import base64
    import gzip
    import uuid

    packed = base64.b64encode(gzip.compress(script.encode("utf-8"))).decode()
    name = f"netlens-install-{uuid.uuid4().hex[:10]}"
    parts = [packed[i:i + chunk] for i in range(0, len(packed), chunk)]
    for n, piece in enumerate(parts):
        out, err, code = session_factory().run_powershell(f"$f = Join-Path $env:TEMP '{name}.b64'; " + ("Set-Content" if n == 0 else "Add-Content") + f" -Path $f -Value '{piece}' -NoNewline -Encoding ASCII", 60)
        if code not in (0, None):
            return out, err or "could not write the install script on the host", code
    final = (f"$f = Join-Path $env:TEMP '{name}.b64'; $b = [Convert]::FromBase64String((Get-Content $f -Raw)); Remove-Item $f -Force; "
             "$ms = New-Object IO.MemoryStream(, $b); $gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress); "
             "$code = (New-Object IO.StreamReader($gz)).ReadToEnd(); Invoke-Expression $code")
    return session_factory().run_powershell(final, total)


def parse_output(text: str) -> dict[str, Any]:
    log, result, done, error = [], {}, None, None
    for line in (text or "").splitlines():
        if not line.startswith("NETLENS: "):
            continue
        msg = line[9:].strip()
        if msg.startswith("result "):
            k, _, v = msg[7:].partition("=")
            result[k] = v
        elif msg.startswith("error "):
            error = msg[6:]
            log.append("Error: " + error)
        elif msg.startswith("done "):
            done = msg[5:]
            log.append(msg[5:].capitalize())
        else:
            log.append(msg[5:].capitalize() if msg.startswith("step ") else msg)
    return {"log": log, "result": result, "done": done, "error": error}


async def administer(conn, device_id: int, action: str, admin: dict[str, Any], probe_user: str | None = None, enable_sshd: bool = False, allow_from: str = "") -> dict[str, Any]:
    """Check, install, update or remove the probe on a host with an administrator login that is used once (never stored). Returns {"ok", "action", "log", ...}.
    SSH hosts (Linux, or Windows with the OpenSSH server) are reached over SSH; Windows hosts that Netlens monitors over WinRM over WinRM.
    `enable_sshd`: on Windows, also install and start the OpenSSH server when it is missing (restricted to the probe account, and in the firewall to `allow_from`)."""
    import asyncio

    from app.hostmetrics import winrm

    if action not in ACTIONS:
        raise InstallError("action must be one of: " + ", ".join(ACTIONS))
    row = hm.get_monitor(conn, device_id)
    if row is None or row["method"] not in ("ssh", "winrm"):
        raise InstallError("the probe is installed over SSH or WinRM: this device needs a health monitor over SSH or WinRM first (it supplies the address)")
    if not (admin.get("username") and (admin.get("password") or admin.get("private_key"))):
        raise InstallError("give an administrator login for this one action: user name and password (or a private key); it is not stored")
    if row["method"] == "winrm" and not admin.get("password"):
        raise InstallError("over WinRM the administrator login needs a password")
    cfg = service.device_config(conn, device_id)
    user = (probe_user or cfg["username"] or "netlens-ro").strip()
    if not user.replace("-", "").replace("_", "").isalnum() or len(user) > 32:
        raise InstallError("the account name may only hold letters, digits, - and _")
    created = False
    ca = credentials.ca_public(conn)
    if ca is None and action not in ("check", "remove"):
        ca = credentials.ca_create(conn)
        created = True
    secret = await hm.load_secret_async(conn, row)
    as_root = admin["username"] == "root"
    try:
        if row["method"] == "winrm":
            def session():
                return winrm.Session(row["address"], row["port"], row["port"] != 5985, admin["username"], admin["password"], secret.get("auth", "ntlm"), bool(secret.get("verify_tls")), timeout=40)

            script = windows_script(action, user, ca or "", enable_sshd, allow_from, defer_restart=False)
            out, err, _code = await asyncio.to_thread(winrm_upload_and_run, script, session, 900.0)
            parsed = parse_output(out)
            detail = winrm.powershell_error(err) or re.sub(r"\s+", " ", err or "").strip()[:300]
            if not parsed["log"]:
                parsed["error"] = f"the host did not answer the way the install script does: {detail or re.sub(chr(92) + 's+', ' ', out or '').strip()[:200] or 'no output'}"
            elif parsed["done"] is None and parsed["error"] is None and detail:           # the script stopped on an error that PowerShell reported on its error stream
                parsed["error"] = f"the script stopped: {detail}"
                parsed["log"].append("Error: " + parsed["error"])
        else:
            from app.terminal.hostkeys import get_fingerprint

            known = get_fingerprint(conn, device_id)
            platform = (hm._STATES.get(row["id"]) or {}).get("platform") or secret.get("platform", "auto")
            parsed = {"log": []}
            if platform in ("auto", "linux"):
                out, status, _fp = await ssh.run_command(row["address"], row["port"], admin["username"], admin.get("password"), admin.get("private_key"), admin.get("passphrase"), "bash -s",
                                                         known, timeout=120.0, input=linux_script(action, user, ca or "", admin.get("password"), admin.get("sudo_password"), as_root))
                parsed = parse_output(out)
            if not parsed["log"] and platform in ("auto", "windows"):                    # not a Linux host: try it as Windows (OpenSSH server)
                out, status, _fp = await ssh.run_command(row["address"], row["port"], admin["username"], admin.get("password"), admin.get("private_key"), admin.get("passphrase"),
                                                         WINDOWS_STDIN, known, timeout=300.0, input=windows_script(action, user, ca or "", enable_sshd, allow_from, defer_restart=True))
                parsed = parse_output(out)
    except (ssh.SshError, winrm.WinrmError) as exc:
        return {"ok": False, "action": action, "log": [], "error": str(exc), "created_ca": created, "account": user}
    ok = parsed.get("error") is None and parsed.get("done") is not None
    if not parsed["log"]:
        parsed["error"] = parsed.get("error") or "the host did not answer the way the install script does (is this a Linux host with bash, or Windows with the OpenSSH server?)"
        ok = False
    result = {"ok": ok, "action": action, "log": parsed["log"], "error": parsed.get("error"), "installed_version": parsed.get("result", {}).get("installed_version"), "expected_version": scripts.SCRIPT_VERSION,
              "created_ca": created, "account": user, "verified": None, "state": parsed.get("result", {})}
    if ok and action in ("install", "update"):
        if row["method"] == "winrm":
            await asyncio.sleep(3)                                                      # the SSH server has just been (re)started
        result["verified"] = await verify(conn, device_id, user)
        if result["verified"].get("ok") and cfg["provider"] == "static":                # the proof worked: use the locked-down login from now on
            service.save_settings(conn, {"devices": {str(device_id): {"provider": "netlens_ca", "username": user}}})
            result["log"].append(f"Switched the probes of this device to the one-time certificate login of the account {user}")
            result["switched"] = True
    return result


async def verify(conn, device_id: int, user: str) -> dict[str, Any]:
    """Log in as the probe account with a fresh short-lived certificate and run one probe: proves the whole chain works (CA trust, forced command, sudo / the script)."""
    row = hm.get_monitor(conn, device_id)
    port = row["port"] if row["method"] == "ssh" else service.device_config(conn, device_id)["ssh_port"]
    try:
        cred = await credentials.issue(conn, "netlens_ca", {"username": user, "ttl_s": 120}, {})
        from app.terminal.hostkeys import get_fingerprint

        out, status, _fp = await ssh.run_command(row["address"], port, cred.username, None, cred.private_key, None, scripts.locked_command("changes"), get_fingerprint(conn, device_id), timeout=60.0, certificate=cred.certificate)
    except (credentials.CredentialError, ssh.SshError) as exc:
        return {"ok": False, "error": str(exc)}
    from app.hostprobe import parsers

    try:
        data = parsers.parse_probe("changes", "linux", out) if "##end" in out else parsers.parse_probe("changes", "windows", out)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"the probe answered, but not as expected: {exc}"}
    return {"ok": True, "script_version": data.get("script_version"), "mode": "locked", "platform": data.get("platform")}
