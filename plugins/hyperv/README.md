# Microsoft Hyper-V plugin

Shows your Hyper-V hosts with their virtual machines in Netlens (kind `hypervisor`, like Proxmox, TrueNAS and Docker). Needs Netlens
0.3.115 or newer. It is read-only in what it does: it logs in to Windows Remote Management (WinRM) and runs **one fixed PowerShell
script**, which only calls `Get-VM` (the script is `SCRIPT` at the top of `plugin.py`; nothing else is ever sent).

## What you get

* every virtual machine as a guest of its host: state (running, stopped, paused, saved), processors, memory, start time, generation,
  network switch and whether it starts automatically;
* each VM matched to the device Netlens found: by the **MAC address** of its network cards (an address Hyper-V has not assigned yet is
  ignored), then by the IP address the guest reports, so a VM is one device, linked to its host on the map and in the hierarchy;
* start / stop events, the Statistics page, the map (when containers and guests are shown) and Home Assistant follow automatically.

The IP addresses of a VM are only known to Hyper-V while the guest runs the integration services (Windows and most Linux
distributions do). A VM that is off, or has no integration services, is matched by MAC address alone.

## Set up the Hyper-V machine (once)

Open PowerShell **as administrator** on the Hyper-V host and run the lines from the box on the plugin's settings page (they are
repeated here). Change `$netlens` to the address of the machine Netlens runs on.

```powershell
$netlens = '192.168.0.189'   # the address of the machine Netlens runs on
$pw = Read-Host -AsSecureString 'Password for the netlens user'
New-LocalUser -Name netlens -Password $pw -PasswordNeverExpires -UserMayNotChangePassword -Description 'Netlens (read Hyper-V)'
Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-578') -Member netlens   # Hyper-V Administrators (by id: the name is translated on non-English Windows)
Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-580') -Member netlens   # Remote Management Users
Enable-PSRemoting -Force -SkipNetworkProfileCheck
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force
Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -contains 'Transport=HTTP' | Remove-Item -Recurse -Force
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Disable-NetFirewallRule
New-NetFirewallRule -DisplayName 'Netlens WinRM HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $netlens -Action Allow
foreach ($sid in 'S-1-5-32-580','S-1-5-32-578') { $g = Get-LocalGroup -SID $sid; "$($g.Name): " + ((Get-LocalGroupMember -SID $sid).Name -join ', ') }   # netlens must be listed twice
```

What this does: creates a user `netlens` that is **not** an administrator, may log in remotely (Remote Management Users) and may use
Hyper-V (Hyper-V Administrators). The two groups are looked up by their fixed ids (`S-1-5-32-580` and `S-1-5-32-578`), because their names are
translated on Windows in another language (a command with the English name fails there). The last line prints the members of both groups: `netlens` must be in both; switches on WinRM with an **HTTPS** listener (self-signed certificate, valid ten years); removes the
plain-HTTP listener and its firewall rule; opens port 5986 only to the Netlens machine.

Then in Netlens: *Settings → Plugins → Microsoft Hyper-V*: address `https://<host address>:5986`, user `netlens`, the password, and
press **Test**. Keep *Verify TLS certificate* off while the certificate is self-signed.

### About the permissions

Windows has no read-only Hyper-V role: **Hyper-V Administrators can also start, stop and delete virtual machines.** The plugin never
does that, but the account could, so give it a long random password, keep the firewall rule that limits port 5986 to Netlens and
do not reuse that password. A local user that is not an administrator cannot change anything else on the machine.

## How the connection works (for reviewers)

Plugins can only use the Python standard library, so this one contains a small WinRM client: the SOAP messages of a remote command
shell (create, command, receive, delete) and the login. The login is **NTLMv2** (own MD4 and HMAC-MD5, checked against the published
values of Microsoft's MS-NLMP document in the tests) or **Basic**. NTLM is only used over HTTPS: over plain HTTP Windows insists on
sealing every message, which this client does not implement, so it refuses (and tells you so). Kerberos is not supported.

## Troubleshooting

| Message | What to check |
| :--- | :--- |
| `cannot reach …: Connection refused` / timeout | The HTTPS listener (`winrm enumerate winrm/config/listener` on the host should show Transport = HTTPS), the firewall rule and the address. |
| `cannot make a secure connection` | The listener has no usable certificate; run the `New-SelfSignedCertificate` and `New-Item … Listener` lines again. |
| `says access is denied` | The login worked but the user may not open a remote shell. Run the last line of the setup (it lists the members of both groups): `netlens` must be in *Remote Management Users* **and** *Hyper-V Administrators*. If it is not, run the two `Add-LocalGroupMember` lines (with the ids, they work in any language), then press **Test** again. If the user already existed, the `New-LocalUser` line fails; that is fine, skip it. |
| `refused the login` | User name or password wrong; the user must be in *Remote Management Users*. A local user is just `netlens`, a domain user `DOMAIN\name`. |
| `may not manage Hyper-V` | Add the user to the local group *Hyper-V Administrators* and try again (a new login is needed). |
| `Hyper-V is not installed` | `Get-VM` does not exist: the Hyper-V role and its PowerShell module must be installed on that machine. |
| `does not offer NTLM login` | WinRM's *Negotiate* authentication is off: `Set-Item WSMan:\localhost\Service\Auth\Negotiate $true`. |

The **Run diagnostic** button reports how far the connection gets, as yes/no and counts (no names, addresses or accounts).
