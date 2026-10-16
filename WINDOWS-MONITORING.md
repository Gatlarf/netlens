# Monitoring a Windows computer with a low-privilege account

Netlens reads a Windows computer over **WinRM** (built in, nothing to install): processor, memory, swap, disks, network traffic, uptime, stopped services and the state of the physical disks. It runs one fixed, read-only PowerShell script. This guide sets up a dedicated `netlens` account that is **not an administrator**.

Two layers decide what the account may do:

1. **Getting in**: WinRM only lets administrators open a shell by default. Membership of *Remote Management Users* (plus the setup lines below) lets an ordinary account in.
2. **Reading the data**: most readings come from WMI (namespace `Root\CIMV2`), which an ordinary account may not read. Without WMI rights Netlens falls back to .NET and performance counters, which need *Performance Monitor Users*.

## 1. Switch WinRM over HTTPS on

PowerShell as administrator on the Windows computer. The same lines are in the monitoring form under *How to switch WinRM over HTTPS on*.

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
New-NetFirewallRule -DisplayName 'Netlens WinRM HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
# let 'Remote Management Users' open a shell
$sddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
if ($sddl -notmatch ';;;RM\)') { $dacl, $sacl = $sddl -split 'S:', 2; Set-Item WSMan:\localhost\Service\RootSDDL -Value ($dacl + '(A;;GXGR;;;RM)S:' + $sacl) -Force }
Restart-Service WinRM -Force
```

Open port 5986 only to the machine that runs Netlens if you can (`-RemoteAddress`).

## 2. Create the account and add it to two groups

```powershell
$pw = Read-Host -AsSecureString "Password for netlens"
New-LocalUser -Name netlens -Password $pw -PasswordNeverExpires -UserMayNotChangePassword
# groups by their fixed ids, so this works on Windows in any language
Add-LocalGroupMember -SID S-1-5-32-580 -Member netlens   # Remote Management Users
Add-LocalGroupMember -SID S-1-5-32-558 -Member netlens   # Performance Monitor Users
Get-LocalGroupMember -SID S-1-5-32-580; Get-LocalGroupMember -SID S-1-5-32-558
```

Use a long, unique password. On a domain, create the account in the domain and enter it in Netlens as `DOMAIN\netlens`.

With only these two groups the *Test* button works but reads through performance counters. Memory, processor, disks, network and uptime are there; **disk health, swap and stopped services need WMI** (next step).

## 3. Give the account WMI rights (full readings)

1. Press Win+R and run `wmimgmt.msc`.
2. Right-click *WMI Control (Local)* → *Properties* → tab **Security**.
3. Open **Root → CIMV2** and click *Security*.
4. *Add* the `netlens` user and tick **Enable Account** and **Remote Enable** (both *Allow*).
5. *Advanced* → select the `netlens` entry → *Edit* → *Apply to*: **This namespace and subnamespaces**.
6. OK everywhere. No restart is needed.

Disk health reads the `Root\Microsoft\Windows\Storage` namespace; give the account the same two rights there (the *Storage* node under *Root → Microsoft → Windows*) if the Storage tile stays empty.

## 4. Add it in Netlens

On the device: *Monitoring → Health → WinRM*. User name `netlens`, the password, login **NTLM**, port empty (5986). Leave *Verify the TLS certificate* off for the self-signed certificate, or turn it on if you installed one from your own certificate authority. Press **Test**.

## If the Test button says...

| Message | Cause and fix |
| --- | --- |
| `Access denied` on WMI | Step 3 is missing or the rights are not applied to subnamespaces. Netlens falls back to counters when it can, so the reading may still work with fewer values. |
| `the login was refused` | Wrong password, or the account is not in *Remote Management Users* (step 2), or the `RootSDDL` line of step 1 was not run. |
| `cannot make a secure connection` | No HTTPS listener (step 1), the firewall rule is missing, or port 5986 is blocked. Check with `winrm enumerate winrm/config/listener`. |
| Readings work but disk health, swap and stopped services are empty | The account reads counters only. Do step 3. |

## Security notes

- The account can read system information, not change it. Windows has no read-only role for everything, so keep the firewall rule narrow and the password long.
- Netlens stores the password encrypted. Only the fixed script is ever run.
- Prefer HTTPS (5986). Plain http (5985) is accepted only for addresses on your own network.
