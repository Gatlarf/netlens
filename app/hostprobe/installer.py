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


def windows_script(action: str, user: str, ca_public_key: str) -> str:
    """PowerShell for a Windows host with the OpenSSH server (run as an administrator). Not yet run on a real Windows host."""
    import base64

    probe_b64 = base64.b64encode(scripts.windows_wrapper().encode()).decode()
    ca_b64 = base64.b64encode((ca_public_key.strip() + "\n").encode()).decode()
    return (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';function say($m){Write-Output ('NETLENS: '+$m)};"
        f"$action='{action}';$user='{user}';$dir='C:\\ProgramData\\netlens';$cfg='C:\\ProgramData\\ssh\\sshd_config';$ca='C:\\ProgramData\\ssh\\netlens_ca.pub';"
        "$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
        "if(-not $isAdmin){say 'error this login is not an administrator';exit 3};say ('step connected as '+$env:USERNAME+' on '+$env:COMPUTERNAME);"
        "$inst='none';if(Test-Path \"$dir\\probe.ps1\"){$m=Select-String -Path \"$dir\\probe.ps1\" -Pattern 'netlens-probe-script-version' -List;if($m){$inst=($m.Line -split ':')[-1].Trim()}};say ('result installed_version='+$inst);"
        "say ('result account='+[bool](Get-LocalUser -Name $user -ErrorAction SilentlyContinue));"
        "if($action -eq 'check'){say 'done check: nothing was changed';exit 0};"
        "$text=if(Test-Path $cfg){Get-Content $cfg -Raw}else{''};$text=[regex]::Replace($text,'(?ms)^# >>> netlens-probe.*?^# <<< netlens-probe[^\\r\\n]*\\r?\\n?','');"
        "if($action -ne 'remove'){"
        "if($text -match '(?im)^\\s*TrustedUserCAKeys\\s+(?!C:\\\\ProgramData\\\\ssh\\\\netlens_ca.pub)'){say 'error this host already trusts another certificate authority: add the Netlens CA public key to that file instead';exit 4};"
        "New-Item -ItemType Directory -Force $dir|Out-Null;"
        f"$probe=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{probe_b64}'));Set-Content -Path \"$dir\\probe.ps1\" -Value ('# netlens-probe-script-version: {scripts.SCRIPT_VERSION}'+[Environment]::NewLine+$probe) -Encoding UTF8;say 'step installed probe.ps1';"
        "if(-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)){$p=ConvertTo-SecureString -AsPlainText -Force ([guid]::NewGuid().ToString());New-LocalUser -Name $user -Password $p -PasswordNeverExpires -Description 'Netlens read-only probe'|Out-Null;say ('step created the account '+$user)};"
        "icacls $dir /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' (\"${user}:(OI)(CI)RX\")|Out-Null;"
        f"Set-Content -Path $ca -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{ca_b64}'))) -Encoding ASCII;say 'step installed the CA public key';"
        "$force='powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$dir+'\\probe.ps1';"
        "$global=\"# >>> netlens-probe (global) >>>`r`nTrustedUserCAKeys $ca`r`n# <<< netlens-probe (global) <<<`r`n\";"
        "$match=\"# >>> netlens-probe >>>`r`nMatch User $user`r`n    ForceCommand $force`r`n    AllowTcpForwarding no`r`n# <<< netlens-probe <<<`r`n\";"
        "$i=[regex]::Match($text,'(?im)^\\s*Match\\s');if($i.Success){$text=$text.Insert($i.Index,$global)}else{$text=$text+\"`r`n\"+$global};$text=$text.TrimEnd()+\"`r`n`r`n\"+$match};"
        "$stamp=Get-Date -Format yyyyMMddHHmmss;if(Test-Path $cfg){Copy-Item $cfg \"$cfg.netlens-backup-$stamp\";say ('step backed up sshd_config as sshd_config.netlens-backup-'+$stamp)};"
        "Set-Content -Path $cfg -Value $text -Encoding ASCII;"
        "$sshd=Join-Path $env:WINDIR 'System32\\OpenSSH\\sshd.exe';& $sshd -t 2>&1|Out-Null;if($LASTEXITCODE -ne 0){Copy-Item \"$cfg.netlens-backup-$stamp\" $cfg -Force;say 'error the SSH server configuration did not pass its own test: the old configuration was put back';exit 6};"
        "if($action -eq 'remove'){Remove-Item \"$dir\\probe.ps1\",$ca -Force -ErrorAction SilentlyContinue;say ('step removed the script and the CA key; the account '+$user+' was left (Remove-LocalUser '+$user+')')};"
        "say 'step the SSH server restarts in a few seconds (this connection ends)';Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','Start-Sleep 4; Restart-Service sshd';say ('done '+$action)"
    )


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


async def administer(conn, device_id: int, action: str, admin: dict[str, Any], probe_user: str | None = None) -> dict[str, Any]:
    """Check, install, update or remove the probe on a host with an administrator login that is used once (never stored). Returns {"ok", "action", "log", ...}."""
    if action not in ACTIONS:
        raise InstallError("action must be one of: " + ", ".join(ACTIONS))
    row = hm.get_monitor(conn, device_id)
    if row is None or row["method"] != "ssh":
        raise InstallError("the probe is installed over SSH: this device needs a health monitor over SSH first (WinRM hosts run the probes directly with the stored login: nothing to install)")
    if not (admin.get("username") and (admin.get("password") or admin.get("private_key"))):
        raise InstallError("give an administrator login for this one action: user name and password (or a private key); it is not stored")
    cfg = service.device_config(conn, device_id)
    user = (probe_user or cfg["username"] or "netlens-ro").strip()
    if not user.replace("-", "").replace("_", "").isalnum() or len(user) > 32:
        raise InstallError("the account name may only hold letters, digits, - and _")
    created = False
    ca = credentials.ca_public(conn)
    if ca is None and action != "check" and action != "remove":
        ca = credentials.ca_create(conn)
        created = True
    from app.terminal.hostkeys import get_fingerprint

    known = get_fingerprint(conn, device_id)
    secret = hm.load_secret(conn, row)
    platform = (hm._STATES.get(row["id"]) or {}).get("platform") or secret.get("platform", "auto")
    as_root = admin["username"] == "root"
    try:
        if platform in ("auto", "linux"):
            out, status, _fp = await ssh.run_command(row["address"], row["port"], admin["username"], admin.get("password"), admin.get("private_key"), admin.get("passphrase"), "bash -s",
                                                     known, timeout=120.0, input=linux_script(action, user, ca or "", admin.get("password"), admin.get("sudo_password"), as_root))
            parsed = parse_output(out)
            if not parsed["log"] and platform == "auto":                    # not a Linux host: try it as Windows
                out, status, _fp = await ssh.run_command(row["address"], row["port"], admin["username"], admin.get("password"), admin.get("private_key"), admin.get("passphrase"),
                                                         WINDOWS_STDIN, known, timeout=120.0, input=windows_script(action, user, ca or ""))
                parsed = parse_output(out)
        else:
            out, status, _fp = await ssh.run_command(row["address"], row["port"], admin["username"], admin.get("password"), admin.get("private_key"), admin.get("passphrase"),
                                                     WINDOWS_STDIN, known, timeout=120.0, input=windows_script(action, user, ca or ""))
            parsed = parse_output(out)
    except ssh.SshError as exc:
        return {"ok": False, "action": action, "log": [], "error": str(exc), "created_ca": created, "account": user}
    ok = parsed["error"] is None and parsed["done"] is not None
    if not parsed["log"]:
        parsed["error"] = parsed["error"] or "the host did not answer the way the install script does (is this a Linux host with bash, or Windows with the OpenSSH server?)"
        ok = False
    result = {"ok": ok, "action": action, "log": parsed["log"], "error": parsed["error"], "installed_version": parsed["result"].get("installed_version"), "expected_version": scripts.SCRIPT_VERSION,
              "created_ca": created, "account": user, "verified": None}
    if ok and action in ("install", "update"):
        result["verified"] = await verify(conn, device_id, user)
    return result


async def verify(conn, device_id: int, user: str) -> dict[str, Any]:
    """Log in as the probe account with a fresh short-lived certificate and run one probe: proves the whole chain works (CA trust, forced command, sudo)."""
    row = hm.get_monitor(conn, device_id)
    try:
        cred = await credentials.issue(conn, "netlens_ca", {"username": user, "ttl_s": 120}, {})
        from app.terminal.hostkeys import get_fingerprint

        out, status, _fp = await ssh.run_command(row["address"], row["port"], cred.username, None, cred.private_key, None, scripts.locked_command("changes"), get_fingerprint(conn, device_id), timeout=40.0, certificate=cred.certificate)
    except (credentials.CredentialError, ssh.SshError) as exc:
        return {"ok": False, "error": str(exc)}
    from app.hostprobe import parsers

    try:
        data = parsers.parse_probe("changes", "linux", out) if "##end" in out else parsers.parse_probe("changes", "windows", out)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"the probe answered, but not as expected: {exc}"}
    return {"ok": True, "script_version": data.get("script_version"), "mode": "locked" if "##end" in out else "direct"}
