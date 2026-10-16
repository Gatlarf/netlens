# Changelog

The version is `<major.minor from VERSION>.<commits since VERSION last changed>` (`contrib/version.sh`). Each heading below is a release: it covers every build from that number up to the next heading. A leading ★ marks a notable change; those are what the "What's new" popup shows after an update. Netlens reads this file for Settings → About → Changelog, so keep the format (`## 0.2.N — date`, `### Added|Changed|Fixed`, `- ★ **Title**: text`).

## 0.4.30 — 2026-10-16

### Added
- ★ **Auto-update for plugins**: a tick box *Auto-update* per plugin in the *Plugin manager* (off by default). Once an hour Netlens installs a newer version of that plugin by itself, but only when the release is *Reviewed* or *Verified*, never a *Community* one, never a version you rolled back from, and never over a plugin you uploaded by hand. Settings and the on/off state are kept; each update, refusal or failure is an event (*Plugin updated*, *Plugin update held back*, *Plugin update failed*).
- ★ **Warning when a Netlens update may have broken plugins**: after Netlens is upgraded, the *Plugin manager* (and the dashboard) list plugins that cannot be loaded, that the index says only support an older Netlens, or that started failing after the upgrade. Each has an *Update* button when a newer version supports this Netlens, and the text says how to go back to the earlier Netlens image. Plugin releases in the index may now name `max_netlens`, the last Netlens version they are known to work with.

## 0.4.26 — 2026-10-16

### Fixed
- **Plugin diagnostic reports no longer contain server addresses**: *Run diagnostic* is meant to be pasted into public issues, but the error text of a failed step could still contain a bare `host:port`, an IP address or a host name. All 28 older plugins strip them now (new versions: pihole, adguard, powerdns, bind, portainer, swarm, kubernetes, nomad, incus, vsphere, traefik, caddy, kong, haproxy, openwrt, mikrotik, opnsense, vyos, netbox, docker, hyperv, npm, omada, snmp, synology, technitium, truenas, unifi). Update them in *Plugin manager*; the plugin index lists the new versions as *Reviewed*.

## 0.4.23 — 2026-10-16

### Added
- ★ **Seven more plugins**, each tried against the real software on a lab machine (install them from *Plugin store*): **Kea DHCP** (leases and reservations give devices their names), **LibreNMS** (devices, LLDP/CDP links and switch tables as the hierarchy, with the port every device sits on), **Envoy** and **Apache APISIX** (the sites a gateway publishes; APISIX also reports certificate expiry), **HashiCorp Consul** (nodes and service instances with their health), **Pi-hole clients** (the network table: names and manufacturers) and **AdGuard Home clients** (DHCP leases and named clients with their device type).

## 0.4.21 — 2026-10-16

### Changed
- **Containers & guests card**: the dashboard card now counts containers and virtual machines / LXCs separately (the big number is the running containers, a line below gives the VMs and LXCs) instead of one combined total.
- **Windows monitoring guide**: new `WINDOWS-MONITORING.md` explains how to monitor Windows with a low-privilege `netlens` account: WinRM over HTTPS, the groups *Remote Management Users* and *Performance Monitor Users*, the WMI rights on `Root\CIMV2`, and what each Test message means.

## 0.4.20 — 2026-10-16

### Changed
- **Plugin manager and Plugin store**: *Plugins* is now **Plugin manager** and *Browse plugins* is now **Plugin store**. In the Plugin manager each row shows the plugin's last sync, a green **Running**, a red **Failing** or a red **Off** before the Turn on / Turn off button; the on/off and "built in" tags next to the names are gone. The Settings menu no longer lists the categories and the individual plugins: open a plugin from the Plugin manager (its page has a link back).

## 0.4.18 — 2026-10-16

### Changed
- ★ **Plugin lists grouped by category**: with dozens of plugins the lists became long, so **Browse plugins**, the **Plugins** page, the **Settings menu** and the dashboard's *Cards from your plugins* are now organised in six categories (Virtualization & containers, Network devices, DNS, Reverse proxies, Storage & NAS, Documentation). Browse plugins shows one compact line per plugin under collapsible headings (a closed heading lists the plugin names, and opens by itself for updates and search results), with filters for *Installed*, *Updates* and *Verified* and a category selector; the search also finds a plugin by the devices it supports. In the Settings menu the installed plugins sit under category sub-headings (the one with the current page is open), and the Plugins page shows a status dot per plugin and opens the category that has a failing plugin. A plugin index entry may name its `category` (optional).

## 0.4.13 — 2026-10-16

### Added
- ★ **Nineteen new plugins** (Settings → Integrations → Browse plugins), each tested against the real software in a lab where that was possible. Everything is read-only unless it is a DNS plugin (which writes only after you approve) and every plugin has a *Run diagnostic* button.
- ★ **DNS registration** now also works with **Pi-hole** (v6 Local DNS), **AdGuard Home** (DNS rewrites), **PowerDNS Authoritative** (record sets marked with a comment) and **BIND 9** (zone transfer plus signed dynamic updates; every change is guarded by a prerequisite that the server checks, so a record that changed meanwhile is never overwritten). Records on Pi-hole, AdGuard Home and BIND cannot carry a marker, so Netlens only changes records it remembers writing.
- ★ **Hypervisor plugins**: **Portainer** (every Docker environment it manages), **Docker Swarm** (nodes and tasks), **Kubernetes** (nodes and pods, tested on k3s), **HashiCorp Nomad**, **Incus / LXD** (client-certificate login) and **VMware ESXi / vCenter** (tested against the vcsim simulator only). Podman needs no new plugin: the Docker plugin works with Podman's API, see its README.
- ★ **Reverse-proxy plugins**: **Traefik**, **Caddy**, **Kong Gateway** and **HAProxy** show the sites they publish and tie each one to the device or container behind it (HAProxy's statistics have no host names, so you can list them per backend).
- ★ **Topology plugins**: **OpenWrt** (router and access point over ubus, with Wi-Fi stations, band and signal), **MikroTik RouterOS** (bridge hosts with their port, DHCP, ARP, Wi-Fi, MikroTik neighbours), **OPNsense** (ARP and DHCP clients under the firewall), **VyOS** and **NetBox** (your documented devices and cables become the hierarchy). The Wi-Fi parts of OpenWrt and MikroTik, MikroTik neighbours, OPNsense DHCP lists and VyOS DHCP leases follow the vendors' documentation and are covered by simulated answers only: a *Run diagnostic* report is welcome.

## 0.4.12 — 2026-10-15

### Added
- ★ **Search**: press `/` or Ctrl+K (or use the magnifier in the top bar, or *Search settings…* in the Settings menu) to find pages, settings and devices by name, address, manufacturer or a related word ("smtp", "retention", "winrm"). A setting is opened, scrolled to and highlighted.
- ★ **What changed** (Monitoring menu): one timeline of what happened in the last 6 hours up to 30 days: new and removed devices, up and down, alerts, address and port changes, and (for administrators) the changes people made. Filter by kind; entries since your last visit are marked *new*.
- ★ **Stopped Windows services**: an automatic service that stopped with an error (a crash, not a normal stop) is a warning, read over WinRM or SSH together with the other Windows readings, and announced again as running when it is back.
- **Certificates, renewal style**: a certificate check now knows whether the certificate renews itself. *auto* (the default for Let's Encrypt, ZeroSSL and similar, as renewed by Nginx Proxy Manager) goes down below 14 days left, because the renewal should have happened by then; *manual* gives 30 days of notice; or enter a number of days.

### Changed
- **WinRM without administrator rights**: when Windows refuses WMI ("Access denied"), the readings fall back to .NET and performance counters, which an ordinary account in *Remote Management Users* and *Performance Monitor Users* may use. The setup notes say which groups to use.
- The scan progress bar floats at the bottom of the window instead of pushing the page down.

## 0.4.11 — 2026-10-15

### Fixed
- **A refresh no longer disturbs what you are doing**: on a device page the automatic refresh used to rebuild the page, which scrolled it back to the top while you looked at the graphs, and could close an SSH session. The scroll position is now kept, and a console that is open is carried over to the refreshed page as it is. The scan progress bar no longer pushes the page down when a scan starts: it floats at the bottom of the window.

## 0.4.10 — 2026-10-15

### Added
- ★ **Storage health**: a degraded or failed disk set is now an alert, the most expensive failure of a small office. Netlens reads Linux software RAID (`/proc/mdstat`) and ZFS pools (`zpool`) over SSH, the physical disks of Windows (over WinRM or SSH), and the RAID groups and disks of a **Synology** through its SNMP MIB (including disk temperatures). A degraded or rebuilding set raises a warning, a failed one a critical alert, and the device's Health tab shows a *Storage* tile. Smart (SMART) values are not read: they need root on the host.
- ★ **Acknowledge and snooze**: next to a problem on the dashboard and on the Health page there is a *Snooze…* menu (1 hour, 4 hours, 24 hours, 7 days). A snoozed problem is moved to a *Snoozed* list, no longer counts as "needs attention" and its notifications are held back. It ends by itself when the problem is over, and when the time is up a problem that is still there is announced once more. *Wake* ends a snooze by hand.

- ★ **Audit log**: Settings → Audit log lists who changed what and when (settings, devices, users, monitors, backups, snoozes) and every sign-in, failed sign-in and sign-out, with the address it came from. Passwords and request contents are never stored; entries are kept for a year, can be searched and filtered by user, and downloaded as CSV.

### Fixed
- **WinRM**: PowerShell's own progress messages ("Preparing modules for first use") were shown as the error when a reading failed, hiding the real reason. They are suppressed, each part of the Windows script reports its own failure (for example "Access denied" on WMI), and the message says what came back.

## 0.4.9 — 2026-10-15

### Added
- ★ **WinRM for Windows**: health monitoring can read a Windows computer over WinRM (Windows Remote Management, built in) instead of installing anything: processor, memory, swap, disks, traffic per adapter and uptime, plus process and service checks. Choose *WinRM* in the monitoring form; it uses HTTPS (port 5986) with an NTLM login (or Basic), runs one fixed read-only PowerShell script, and the form shows the lines that switch WinRM over HTTPS on. Plain http (port 5985) is only accepted for addresses on your own network.

## 0.4.7 — 2026-10-15

### Added
- ★ **Start page**: under Settings → Account every user (viewers too) can choose the page Netlens opens on: the map, Health, Devices, Reports and others instead of the dashboard. It is kept per user on the server, and only applies when Netlens is opened without a link to a page.
- ★ **Synology plugin** (Settings → Integrations → Browse plugins): a Synology NAS (DSM 7) as a host with its Container Manager containers, Virtual Machine Manager machines and installed packages as guests, matched to your devices by IP or MAC. Read-only; it needs a dedicated administrator account because DSM has no read-only API role, and the plugin's page says how to limit it. Tested against a simulated DSM only: a Run diagnostic report from a real DS923+ is welcome.

## 0.4.6 — 2026-10-15

### Added
- ★ **SNMPv3**: health monitoring can use SNMPv3 with a user name, authentication (MD5, SHA, SHA-256, SHA-512) and encryption (AES or DES). Choose version 3 in the monitoring form. Passwords are at least 8 characters and stored encrypted; the clocks of the device and Netlens are synchronised automatically.
- ★ **Windows over SSH**: a Windows computer with the OpenSSH server can be monitored like a Linux host (processor, memory, swap, disks, traffic per adapter, uptime, and process checks). The form has a *System* choice (detected automatically); one read-only PowerShell command is sent as an encoded command and nothing is installed.
- ★ **Ports of a switch**: a *Ports* table on the Health tab shows the link state, traffic in and out, how full the link is and errors of every port, with the graphs of a port one click away. New limits *Port busy* and *Port errors*. A port without a cable shows as down without an alarm; a port that was switched off on purpose is left out.
- ★ **Manage a remote site from the central Netlens**: the page of a remote site has a *Managed from here* card to set up service checks and health monitors that run at the remote location. The remote Netlens must tick *Accept configuration from the central Netlens*; managed items cannot be edited there, logins are stored encrypted.
- **Home Assistant**: the summary that the integration polls now carries health and remote site numbers (netlens-ha 0.13.0 adds sensors for them, and Health, Processor, Memory, Fullest disk, Temperature and UPS battery sensors for tracked devices).

## 0.4.5 — 2026-10-15

### Added
- ★ **Running out soon**: a new dashboard card and an alert for disks that are filling up. From the growth of the last weeks Netlens works out the day a monitored disk will be full ("Backup server /mnt/datastore: full in about 13 days, around 28 October"). A disk that is steady or shrinking gets no date, one big file does not count as a trend, and a disk needs a few days of history first. A notification is sent when a disk is on course to fill within 14 days (a critical one within 3 days); it is raised once, not on every round, and not for a disk that already has a critical reading of its own.
- ★ **Limits per device**: on a device's Health tab, "Limits for this device" sets other warning and critical limits for that device alone (a NAS that runs at 90% by design, a database server that should warn earlier). Empty boxes follow the general limits. The warnings, the lines in the graphs and the dashboard tiles use them.
- ★ **The history is in the backups**: a backup now carries a trimmed copy of the measurement history (the last day in full, 14 days at 5 minutes, and all the hourly values), and a restore brings it back. Before, losing the data folder lost the graphs and the growth trend.

- ★ **Reports**: new page Monitoring → Reports. The **weekly report** summarises the last seven days in plain language (what was down and for how long, health readings past a limit, disks filling up, new devices, silent remote sites). Turn it on there and choose the day and hour, then tick "Weekly report" on the notification channels that should get it; "Send it now" tries it. The **monthly availability report** shows every device and service for a calendar month with availability, number of outages, longest outage and time down; it can be printed or downloaded as a CSV file for a spreadsheet.

### Changed
- The Health card on the dashboard stays readable with many devices: above 24 monitored devices only the devices that need a look are shown as tiles, and the healthy ones shrink to one small square each (a button shows them as tiles again).

### Fixed
- Graphs of 30 days and longer were nearly empty after an update: the history that was copied in once (and the demo's) stayed in the fine tier, which is trimmed after a week. It is folded into the long tiers now, and an installation that already ran the copy does it once more.

## 0.4.4 — 2026-10-15

### Added
- ★ **Health on the dashboard**: a new Health card shows a heat-map with one tile per monitored device, coloured by its worst level, with three bars for processor, memory and the fullest disk (each in its own level colour). Above it a sentence says how many devices need attention; below it are the readings past a limit, worst first, and when nothing is wrong the busiest device per reading. A tile opens that device on its Health section. It is on the default dashboard; if you arranged your own, add it with Customize.

## 0.4.3 — 2026-10-15

### Fixed
- **Behind Cloudflare**: the interface files now carry a `Cloudflare-CDN-Cache-Control: no-store` header, so Cloudflare no longer serves an old copy of the scripts and styles for hours after an update. If a Cloudflare cache rule overrides the origin's headers, purge the cache once after updating.

## 0.4.2 — 2026-10-15

### Changed
- ★ **A device page with sections**: the page of a device is split into Overview, Health, Network, Console and Settings behind a tab bar that stays in view, so the graphs and the health set-up are one click away instead of far down the page. A row with the headline readings (processor, memory, disk, temperature, traffic, battery), coloured by level, is shown on every section and opens the health graphs when clicked. The chosen section stays when the page refreshes itself.
- The page no longer refreshes itself while the health monitoring form is open, so what you typed is not lost. After saving, the graphs appear straight away.

## 0.4.1 — 2026-10-14

### Changed
- **Graphs in colour**: performance graphs are now coloured by what the value means. A line is green while it is within its limits, amber past the warning limit and red past the critical limit, with the warning and critical parts of the scale tinted and the newest value shown in the colour of its level. Availability is a strip that is green while up and red where it was down. Batteries and printer supplies, where low is bad, are coloured the other way round. Graphs without limits (response time, traffic) are blue.

## 0.4.0 — 2026-10-14

### Added
- ★ **Netlens 0.4: performance, health and remote sites**. This release gathers the monitoring work of 0.3.177 to 0.3.179: **performance graphs** of response time and availability for up to a year, **health monitoring** of switches, NAS boxes, printers, UPS units and servers over SNMP or SSH (processor, memory, disks, traffic, temperature, supplies, battery) with warnings that need a few readings in a row, **certificate and process checks**, alerts **grouped by cause** ("the garden switch is offline, 4 devices behind it cannot be reached"), and **remote sites**: a Netlens at another location reports to this one, which shows its devices, checks, health and history and tells you when the site stops reporting. New pages are Monitoring → Health and Monitoring → Remote sites; Settings has "Report to a central Netlens".

### Changed
- The version number is now `<major.minor>.<commits since VERSION last changed>` (`contrib/version.sh`), so this release is 0.4.0 and the number after it counts from here.

## 0.3.179 — 2026-10-14

### Added
- ★ **Remote sites**: one Netlens can now watch several locations. Install Netlens at the other location (a branch office, a second home, a customer), then on the main one open **Monitoring → Remote sites → Add a remote site** to get a token, and on the remote one enter the address and token under **Settings → Report to a central Netlens**. The remote Netlens keeps scanning and checking its own network as before and sends a report every minute; the connection always goes out from the remote site, so nothing there has to be reachable from the internet, and the token is stored hashed on the main side and encrypted on the remote side. The main Netlens shows each site with its devices, service checks and health problems, graphs of their history, and raises alerts: a device or service going down, a health problem, a new device, and **a site that stops reporting** (its devices are then shown as not watched instead of all going offline). New events for the notification channels, the dashboard "Needs attention" list and Prometheus (`netlens_remote_site_*`) include the sites.

## 0.3.178 — 2026-10-14

### Added
- ★ **Health monitoring**: Netlens can now read the health of a device over **SNMP** (switches, routers, NAS boxes, printers, UPS units, Windows with the SNMP service) or **SSH** (Linux): processor, memory, swap, disks (used and free), network traffic per interface, temperatures, uptime, printer supplies and UPS battery. Nothing is installed on the device and only read requests are sent. Set it up on a device's page (Health monitoring card: Test shows what was found, then Save); the login is stored encrypted. The readings are graphed in the device's Performance card and listed on the new **Monitoring → Health** page, which shows what is past a limit.
- **Warnings that mean something**: a reading has to stay past its limit for a few rounds in a row (so a short peak is not an alarm). Defaults: processor 90 / 98 %, memory 90 / 97 %, disk 85 / 95 % full, temperature 80 / 90 °C, supplies below 15 / 5 %, UPS battery below 50 / 25 % and a UPS running on battery. The limits can be changed on the Health page. New events Health warning, Health critical and Health normal go through the notification channels (critical breaks through quiet hours), respect maintenance windows, and appear on the dashboard under "Needs attention".
- Prometheus (`/metrics`) now carries the readings of monitored devices (`netlens_host_cpu_ratio`, `netlens_host_disk_used_ratio` ...).
- ★ **Certificate and process checks**: two new kinds of service check. *Certificate* reads what a TLS service presents (a web site, a mail server, an RDP host) and goes down when fewer than the chosen number of days are left (default 14) or the certificate has ended; the days left are graphed. *Process* asks a device that has health monitoring whether a program or service runs (SNMP: the list of running programs, Windows services included; SSH: `pgrep` or `systemctl`), for example `nginx`, `sshd` or `sqlservr`.
- ★ **Alerts grouped by cause**: when a switch or a host goes offline, the notification says "sw-garden is offline, so 4 devices behind it cannot be reached: ..." instead of listing five offline devices. This uses the network hierarchy (which device depends on which). Only the messages are grouped: every event is still recorded and Home Assistant and Prometheus see the individual devices. It can be switched off next to the quiet hours (Group alerts by cause).

## 0.3.177 — 2026-10-14

### Added
- ★ **Performance graphs**: Netlens now keeps a time series of what it measures (response time and availability of every device, response time and state of every service check) in its own small database file, `metrics.db`, next to the main one, with full detail for 7 days, 5-minute values for 90 days and hourly values for 2 years. Graphs show the lowest, average and highest value, read-outs under the pointer and ranges from 6 hours to 1 year. The Services page has a Graph button per check; a device page gets a Performance card as soon as it has measurements beyond what the Uptime card shows. The first start after the update fills the graphs from the uptime history Netlens already holds. This is the foundation for the host and probe monitoring of the 0.4 series.

## 0.3.176 — 2026-10-14

### Added
- ★ **Remote access**: a new page under Network lists the devices that have SSH, Telnet, RDP or VNC open, with the sessions on the right in tabs. SSH and Telnet use the existing web terminal. **RDP (Windows) and VNC** are drawn in the browser through an optional helper container (guacd from Apache Guacamole); the page explains how to add it, with lines to copy, and checks that it is reachable. Clipboard works both ways, the screen follows the window size, and a login can be remembered (stored encrypted). Same rules as the terminal: administrators on a direct local connection only, and only devices with that port seen open. Device pages get RDP and VNC buttons.

## 0.3.175 — 2026-10-14

### Changed
- ★ **Stored passwords are encrypted**: plugin credentials (Proxmox, ASUS, TrueNAS, Technitium, NPM, Hyper-V ...) and notification channel secrets (SMTP password, ntfy, Telegram, Discord, Pushover and webhook tokens) were stored in the database as plain text and are now encrypted with AES-256-GCM. The key is created as `secret.key` in the data folder, or taken from `NETLENS_SECRET_KEY`. Existing values are encrypted on the first start (a copy of the database is kept as `netlens.db.pre-encryption`). Backups hold the encrypted values only; Settings → Backup & restore shows the key so you can keep a copy and put it back after a restore, and the dashboard warns when stored passwords cannot be read.
- A **recovery passphrase** (Settings → Backup & restore) puts the key into every backup wrapped with that passphrase, so a restore on a new machine can unlock the passwords by entering it. The leftover plain-text copy of the old e-mail setup is removed.

## 0.3.174 — 2026-10-14

### Changed
- The address check in Investigate no longer assumes TrueNAS. It names the virtualisation product from the MAC prefix (VMware, Hyper-V, Proxmox, QEMU/KVM, VirtualBox, Docker, Incus/TrueNAS) or from a hypervisor plugin (the host it runs on), says where to look for that product, and for a physical device lists the usual causes (a fixed address plus a DHCP lease, extra addresses on one card, a device that answers for others). It also gives the Windows command next to the Linux one.

## 0.3.173 — 2026-10-14

### Changed
- The address check in Investigate explains the 10:66:6a MAC prefix in plain words (TrueNAS and Incus virtual machines and containers) and reads better for two addresses.

## 0.3.172 — 2026-10-14

### Added
- ★ **Investigate checks the address**: the Stability section of a device now also looks at its address history. A device that answers on two addresses at the same time with the same MAC (for example a fixed address plus a DHCP lease from the router, as with a container or VM that is configured twice) is flagged with the addresses involved and what to look for, and so is a device whose address keeps changing. Before, this only showed up as hundreds of "IP changed" events and was invisible in the uptime analysis.

## 0.3.171 — 2026-10-14

### Added
- ★ **Compact map layout**: the dashboard's mini-map view is now available on the Map page as *Compact layout*: small dots in columns from left to right with curved links, nothing folded, a one-line name under each dot. Pick it in the map's own layout menu, or make it the default under Settings → Map.

## 0.3.170 — 2026-10-14

### Changed
- The dashboard card button *Share with everyone* is now simply *Share*.

## 0.3.169 — 2026-10-14

### Fixed
- A custom card that was already on the dashboard did not show under *Your own cards*, so it could not be shared. Own cards are now always listed there (marked "On your dashboard"), and every own card has a share button (⇪) in Customize mode. Shared cards stay listed for the administrator, so they can be changed or unshared.

## 0.3.168 — 2026-10-14

### Added
- ★ **Share dashboard cards with everyone**: an administrator can press **Share with everyone** on a card of their own (Customize → Your own cards). The card then appears under **Shared by your administrator** in every user's card pool, where they add it like any built-in card. The administrator can change it (for everybody), stop sharing it (it goes back to their own cards) or delete it.

## 0.3.167 — 2026-10-14

### Changed
- ★ **A simpler setup guide**: the guide no longer shows the full settings pages. Each step is now a short, plain question with the recommended answer filled in: your network, device names, always-on devices, how to reach you (e-mail, phone notification, Telegram or Discord, with a test message and a choice between "only important things" and "everything"), and the safety checks. Moving on saves the step, and each step links to the full settings page for more options. The last step shows what is set up. While the guide is unfinished, Settings shows a "Back to the setup guide" button.

## 0.3.166 — 2026-10-14

### Changed
- ★ **E-mail is now a notification channel**: the separate *E-mail notifications* page is gone. Under Settings → Alert channels & quiet hours you add an **E-mail (SMTP)** channel the same way as ntfy or Telegram, with its own events, *Send test* button, status line and quiet hours, and you can have several. An existing e-mail setup is converted automatically (same server, password, recipients and events, and it carries on from where it was, so nothing is mailed twice). The old page address opens the channels page.

## 0.3.165 — 2026-10-14

### Added
- ★ **Setup guide**: a step-by-step guide through the settings that matter most on a new install: networks and schedule, better names (passive discovery, DNS), always-on devices, alerts (add a channel right there), network checks, plugins, and users and backups. Every step can be skipped and changes are saved straight away. A fresh install opens it right after the first account is made. Existing installs get a short "Finish setting up" bar on the dashboard (with "Not now"), and everybody can open it again under Settings → System → Setup guide.

## 0.3.164 — 2026-10-13

### Fixed
- The dashboard card *DNS & network checks* always said "DHCP servers: not checked", even though the rogue DHCP check is on by default. It now shows the number of DHCP servers found (and how many you do not trust), "not checked yet" until the first check has run, or "check is off" when you switched it off under Settings → Network checks. Statistics and Home Assistant read the same flag, so their "Last DHCP check" line is right too.

## 0.3.163 — 2026-10-13

### Changed
- The demo now has always-on devices: 20 of its devices (network gear, servers and cameras) are marked, so the Always-on view, the dashboard Uptime card and Statistics show the difference to the phones and tablets, and the chooser suggests a few more.

## 0.3.162 — 2026-10-13

### Added
- ★ **Always-on devices**: mark the devices that should be online all the time (router, switches, servers, NAS, cameras) with *Always-on device* on a device's Edit panel, or in bulk with **Choose always-on devices** on the Uptime page, where Netlens also suggests the ones that have been up 99% of the last 30 days. The availability of phones and tablets that come and go no longer drags your uptime down: the Uptime page has an **All devices / Always-on** switch, the dashboard Uptime card shows the always-on figure and the all-devices figure together, and Statistics, Prometheus (`netlens_core_*`) and Home Assistant (integration 0.12.0) get the always-on figures next to the existing ones.
- ★ **Unstable devices split**: the dashboard card and the attention list now count always-on devices that keep going up and down apart from the others (a phone flapping is only a note), and an always-on device that is not answering is listed as needing attention.

## 0.3.161 — 2026-10-13

### Changed
- ★ **A new Uptime page**: choose **24 hours, 7 days or 30 days** (your choice is remembered), see at a glance how many devices are online, the average availability, how many devices missed a check and the average response time, and read each device on its own row with the Uptime-Kuma style availability bar **and a response-time line** next to it, plus its 24 h, 7 day and 30 day uptime. You can filter, sort by least reliable or slowest, and show only devices with a problem.
- ★ **Point at a bar or the line to see the details**: every uptime graph (Uptime page, a device's Uptime card and the service-check history) now shows an infobox with the time of the measurement, up or down, and the response time. When one bar covers several checks (a longer period) it says how many there were, how many failed and the average and highest response time.
- ★ **The Uptime card of a device** has the same 24 hours / 7 days / 30 days choice and a response-time line with its highest and average value; its 24 h, 7 day and 30 day figures show at once. The Uptime card on the dashboard now shows 24 hours, 7 days and 30 days together.

## 0.3.160 — 2026-10-13

### Changed
- ★ **The dashboard map uses the horizontal layout**: the small map now draws the network left to right like the *Horizontal layout* on the Map page (the top device on the left, every level a column to its right), packed to fill its card.

### Fixed
- The README now explains the Portainer setup step by step, including where to switch on the `NET_RAW` and `NET_ADMIN` capabilities and the host network when you create the container by hand.

## 0.3.158 — 2026-10-13

### Added
- ★ **A starting dashboard for everyone**: an administrator arranges the dashboard (cards, order, even cards of their own) and presses **Use as default for everyone** under *Customize*. Everybody who has not arranged their own dashboard then starts with it, and a notice says so; pressing *Customize* makes it their own, and **Back to the default** returns to it. **Remove the default** goes back to the built-in cards. Viewers can see it but not change it.
- ★ **Dashboard cards for more plugins**: Docker (1.5.0: running, stopped, restarting and paused containers), Nginx Proxy Manager (1.1.0: sites, switched off, proxy hosts, redirections, streams, 404 hosts), TrueNAS (1.3.0: running and stopped apps, containers and VMs) and Hyper-V (1.1.0: running, stopped and paused machines) now offer their own card under *Customize*, next to the status card every plugin has.

## 0.3.157 — 2026-10-13

### Added
- ★ **Make your own dashboard cards**: under *Customize* press **Create a card**. Pick **a value from your data** (search any number Netlens knows, such as uptime, internet speed or unhealthy containers, show it as a big number, a gauge bar or a status light, and set the warning and problem limits that colour it), **a device** (up or down, since when, address, uptime), **a group** of devices (how many are online and which are not), **a service check**, or **notes and links** (text plus shortcuts to Grafana, Portainer, your router and so on). A live preview shows the card while you make it. Your cards are saved with your dashboard, so they follow you to every browser, and every user has their own.
- ★ **Cards from plugins**: every enabled plugin now offers a status card (working or failing, last sync, guests or sites it reported) under *Customize*, and a plugin can declare more cards in its `plugin.json` (`dashboard`, see the plugin guide); a plugin runs no code for a card. The built-in Proxmox plugin (now 1.4.0) offers a *Proxmox guests* card with running, stopped, virtual machines and containers.

## 0.3.156 — 2026-10-12

### Changed
- ★ **Your dashboard follows you**: the cards you choose and their order are now saved per user on the server instead of in the browser, so the same dashboard shows on every browser and device you sign in on. The layout you already made in this browser is moved to your account the first time you open the dashboard. Every user, viewers included, arranges their own; *Reset to default* clears yours. (In the demo, where nothing can be saved on the server, the layout stays in the browser.)

## 0.3.155 — 2026-10-12

### Added
- ★ **Internet speed on the dashboard, in Statistics, Home Assistant and Prometheus**: the dashboard has an *Internet speed* card (download, upload, ping and when it was measured; on by default for new layouts, and under *Customize → Add a card* for an existing one). Statistics has a *Speed tests* section with the internet speed over the chosen period, the lowest, average and highest values, and the latest iperf3 and browser tests. The statistics summary (`/api/stats/summary`) has a new `speed` block, which the Home Assistant integration 0.11.0 turns into *Internet download speed*, *upload speed* and *ping* sensors (plus jitter and last test time, disabled by default). `/metrics` has `netlens_speedtest_download_bits_per_second`, `_upload_bits_per_second`, `_latency_seconds`, `_jitter_seconds`, `_timestamp_seconds`, `_last_ok`, `_failures_24h` and `netlens_iperf_last_bits_per_second`, and the Grafana dashboard has two new panels. These show the latest scheduled or manual internet test, so switch on the automatic test under Network → Speed tests to keep them current.

## 0.3.154 — 2026-10-12

### Added
- ★ **Speed tests** (Network → Speed tests): three kinds of test on one page, with a history of every result.
  - **Internet speed**: delay, jitter, download and upload against Cloudflare's nearest test server (about 20 seconds, no account or extra program). Run it by hand or let Netlens test every 1, 3, 6, 12 or 24 hours (off by default); the history chart shows the trend, and a *Internet speed* card can be added to the dashboard.
  - **iperf3 server inside Netlens**: switch it on (port 5201 by default) and the page shows the exact `iperf3 -c <address>` line to run on any other computer; every test that connects is added to the results. It stays on after a restart and is off until you switch it on.
  - **iperf3 client**: pick a device or type an address and Netlens tests against an iperf3 server there, in one or both directions.
  - **Test from this device**: any browser (a phone, tablet or PC, no installation) measures download, upload and delay between itself and Netlens, and can be saved with a label such as "Wi-Fi in the kitchen". Viewers can do this too.
  The Docker image now includes iperf3. See the README.

## 0.3.152 — 2026-10-12

### Added
- ★ **Dashboard start page**: Netlens now opens on a dashboard of cards: devices online, uptime, unstable devices, services, containers and guests, sites and certificates, plugins, backup and scans, DNS and network checks, security, a *Needs attention* list, the recent events and a small map of the network (click it to open the full map). Press **Customize** to reorder the cards (drag them, or use the arrows), remove them, or add more: least reliable devices, 14-day trend, events per day, device types, groups, Wi-Fi, new devices, certificates, available updates and quick scan buttons. The layout is remembered per user in the browser. Everything refreshes every 30 seconds. Viewers see it too.

### Changed
- ★ **A tidier top bar**: the page links are grouped into **Dashboard**, **Network** (Map, Devices, Hierarchy), **Monitoring** (Uptime, Services, Statistics, Scans & events) and **Settings**, so the bar no longer overflows on a small screen such as an older iPad. The *Buy me a coffee* button shows in the bar only on wide screens (it is always in the account menu), and the light/dark switch stays in the bar on every screen size, right of the Scan button. On a narrow screen the menu lists the groups under headings.

### Fixed
- **Settings menu works again from the dashboard**: after opening a Settings page (for example from a dashboard card), the Settings menu and the page links stopped reacting. The new grouped top bar shared a name with the Settings menu.


## 0.3.149 — 2026-10-12

### Added
- ★ **Demo mode**: start the same image with `NETLENS_DEMO=on` to get a made-up network of 46 devices with a month of history (outages, flaky devices, a power cut), fictional DNS registration, plugins, reverse-proxy sites and service checks, kept moving by a small simulator. Visitors can look at every page but change nothing, and the data starts over hourly or daily (`NETLENS_DEMO_RESET`). Nothing real is scanned or sent. See `docker-compose.demo.yml` and the README.


## 0.3.147 — 2026-10-12

### Fixed
- ★ **Share links work again after a scheduled backup**: once a scheduled backup had run, the share page said "The page could not be loaded" and the statistics summary and `/metrics` failed, because the backup time was stored in a format those pages could not read. The time is now stored in the standard format and older values are read as well.


## 0.3.143 — 2026-10-12

### Changed
- ★ **New license: PolyForm Noncommercial 1.0.0**: from version 0.3.143 Netlens is free for noncommercial use (home, hobby, study, research, charity) and needs a commercial license for anything commercial. Versions 0.3.142 and earlier stay available under the MIT License. See the *License* section of the README for how to ask for a commercial license.


## 0.3.129 — 2026-10-12

### Fixed
- **"Latest published" is fresh after an update**: Settings → About → Updates could show an older latest version than the one you run (the answer was cached for a day). Netlens now looks for the newest version right after it starts, and asks again when the cached answer was made by a different version than the one running or is older than it.
- ★ **Hyper-V plugin works for a normal user (1.0.2)**: tested on a real Windows 11 host. Windows refuses `Get-VM` for an account that is not an administrator, so the plugin now reads the VMs through Hyper-V's management data (CIM), which a member of *Hyper-V Administrators* may read. The setup lines also let *Remote Management Users* open a remote shell (WinRM only admits administrators by default), give the groups by their fixed ids (so they work on Windows in any language) and print the members to check. Update it under Settings → Plugins → Browse.
- ★ **Backups include the plugins**: a backup now contains the installed plugins (their code) next to their settings, so restoring into a fresh container brings everything back as it was, with the plugins switched on as before. Older backups restore as they did; for plugins with saved settings but no files, the Plugins page lists them with an *Install again from the index* button, and installing keeps their settings (a plugin whose code differs from the saved one starts off).

### Added
- **Buy me a coffee**: a yellow coffee button at the top of every page (just the cup on narrow screens), plus links in the account menu and Settings → About, for anyone who wants to support the project. Nothing is hidden or limited without it.
- ★ **Vertical map layout**: next to the horizontal layout the map can now be arranged top to bottom, with the router at the top, one row per level and a card per device. Folding clients, *Fit* and the right-angle links work as in the horizontal layout. Pick it in the map's layout menu, or as the default under Settings → Map.
- ★ **Service check from an open port**: the Open ports table on a device page has a Check column. **Add check** creates a service check for that port in one click (a web check for ports 80, 443, 8080 and 8443, a plain port check for the rest), pre-filled with the device and its address. Once a check exists the column shows its status dot and a **Remove check** button.

### Changed
- **Settings menu tidied**: *Plugins* and *Browse plugins* now sit together, and the Plugins page has a *Browse plugins* button next to *Upload plugin*. *DNS registration*, *Ignored devices*, *Users & tokens* and *Web terminal* moved to General. The plugin guide is no longer in the menu; it is linked from the Plugins page.
- **The unused SNMP line is gone from About**: Settings → About showed "SNMP disabled" and `NETLENS_SNMP_COMMUNITY` existed from before there were plugins, but nothing ever used it. SNMP switches (MAC table and LLDP) are handled by the SNMP plugin under Settings → Plugins. An old `NETLENS_SNMP_COMMUNITY` in a compose file is simply ignored.
- **Update instructions in About, and the manufacturer database moved**: Settings → About → Updates now explains how to update (Netlens cannot update itself from the inside; you pull the newest image and recreate the container, your data stays) with the commands for compose, Portainer, Synology and docker run. The *Update now* button of the manufacturer (vendor) database was just above the Updates section and looked like a Netlens update button; it now has its own card under Settings → Scan performance.
- ★ **Simpler install and update**: `docker-compose.yml` now pulls the published image instead of compiling the source, keeps its data in a Docker volume and no longer needs `DOCKERDIR` or a `.env` file; `docker-compose.image.yml` is gone (use `docker-compose.simple.yml` or paste the service into your own compose file or Portainer stack, see the README). Update with `docker compose pull && docker compose up -d`; pin a version with `NETLENS_IMAGE_TAG`; keep a host folder with `NETLENS_DATA`. If you used the old `DOCKERDIR` files, set `NETLENS_DATA=<DOCKERDIR>/appdata/netlens` to keep your data. Developers build from source with the new `docker-compose.build.yml` override.

## 0.3.121 — 2026-10-11

### Added
- ★ **Failed-login alert**: when an address enters five wrong passwords or tokens within a minute, or a user name collects 20 wrong passwords within 15 minutes, Netlens logs a *Failed logins* event (with the address and the last user name tried) once per burst. It is on for new notification channels; for an existing channel tick **Failed logins** in its event list.

## 0.3.120 — 2026-10-11

### Changed
- ★ **Safer when Netlens is reachable from the internet**: found by a security review of the public address. (1) Behind a reverse proxy every visitor looked like the proxy, so the login throttle was shared: a stranger's wrong guesses blocked you too. Set `NETLENS_TRUSTED_PROXIES` to the proxy's address and the throttle (5 wrong attempts a minute) counts each real visitor; the limit per user name is now 20 in 15 minutes so a stranger typing your name cannot lock you out. (2) The API documentation pages (`/docs`, `/redoc`, `/openapi.json`) are off unless `NETLENS_API_DOCS=on`. (3) The version number is only shown to logged-in visitors. (4) Over HTTPS Netlens now sends `Strict-Transport-Security`.

## 0.3.119 — 2026-10-11

### Added
- ★ **Newer-image check for Docker containers**: switch on *Check for newer images* in the Docker plugin (the socket proxy needs `IMAGES: 1`) and Netlens asks the registry of each image (Docker Hub, ghcr.io, your own) every few hours which image the tag points to now. Containers that run an older one are marked *newer image available* on the host's page and under *Needs attention* in Statistics, and you get an *An update becomes available* event (the first result after switching it on is not reported). Only image names are sent; images pulled by digest, built locally or from a registry that needs a login are skipped. Off by default.
- ★ **Reverse proxy sites and certificates in the summary and Prometheus**: `GET /api/stats/summary` has a `sites` block (sites, not tied to a device, down, certificates, expiring, expired, days to the next expiry) and `/metrics` has `netlens_sites`, `netlens_sites_unmatched`, `netlens_sites_down`, `netlens_certificate_days_left`, `netlens_certificate_expires_timestamp_seconds` and `netlens_containers_image_updates`. The Grafana dashboard has panels for certificates and sites, and `contrib/prometheus` has alert rule examples.
- The summary's `guests` block has `image_updates` (containers with a newer image).

## 0.3.118 — 2026-10-11

### Added
- ★ **Containers in the hierarchy**: the Network hierarchy page now lists the containers and apps that plugins report (for example from Docker) below the host they run on, with their state and an *unhealthy* mark. A container that is a device of its own (macvlan) already appears as one. The "N below" counts include them, the name leads to the host's page, and **Show containers** above the tree switches them off (remembered per browser). The API has `GET /api/hierarchy?guests=true`.

## 0.3.117 — 2026-10-11

### Changed
- **A calmer Browse plugins page**: every plugin is one short line (name, type, review badge, version) with its first sentence and the Install button; the full description, what it works with, who reviewed it, what's new and the not-reviewed warning are under **Details**, and the explanation of the badges is a collapsed note at the top.

## 0.3.116 — 2026-10-11

### Added
- ★ **Reverse proxy plugins, with Nginx Proxy Manager as the first**: a new kind of plugin (`proxy`) reports the sites a reverse proxy publishes. The **Nginx Proxy Manager** plugin (needs Netlens 0.3.116 or newer; install it from Settings → Integrations → Browse plugins) reads the proxy hosts, redirections, streams and 404 hosts with their certificates through a view-only user. Netlens ties every site to the device or Docker container behind it, using the upstream address and port (a container that publishes that port, a container with that name on the proxy's Docker network, a macvlan container's own address, or a device with that address or name): the device page gets a *Published through the proxy* card, the proxy's page lists *Sites served*, and sites Netlens cannot place are flagged *not found*. The plugin also warns about an account that sees only its own items or can change things.
- ★ **Certificate expiry events**: a certificate that a site uses gives a *certificate expiring* event 14 days before it ends (you can change the number of days), again at 7, 3 and 1 days and when it has expired. It goes to your notification channels like other events.
- **A check for every site**: the plugin can keep one HTTPS (or HTTP) check per enabled site under Services. The check asks the proxy for the site's domain (it does not depend on DNS), counts any answer below 500 as up and reports a server error such as 502 as *service down*. Checks come and go with the proxy's list; you can still change their interval or turn one off. A service check now understands `alive` (any answer below 500) as its expected result.
- **DNS names for the sites**: *Give the sites of a reverse proxy a name* in Settings → DNS registration makes a CNAME to the proxy's host for every domain that falls inside one of your zones. It is off by default, goes through the same preview and approval as other DNS changes, and never touches a name that already exists.

## 0.3.115 — 2026-10-11

### Added
- **Setup help in a plugin's settings**: a plugin can show a collapsed box with the text and the code to copy that it needs set up elsewhere. The Docker plugin (1.3.0, needs Netlens 0.3.115 or newer) uses it to show the docker-compose lines for the read-only socket proxy that every Docker host needs.

## 0.3.114 — 2026-10-11

### Added
- ★ **Maintenance windows** (Settings → Notifications → Maintenance windows): tell Netlens when devices are expected to be unreachable, for example a mesh node that reboots on Monday, Wednesday and in the weekend at 3 a.m. A window covers everything, groups or chosen devices (and optionally the devices behind them) and runs weekly on the days you choose (also past midnight) or once; it follows your time zone, and the times can be changed at any time. While a device is covered, its offline, online and service down/up events are still recorded but marked *maintenance* and are not sent to e-mail or notification channels; if the device is still offline when the window ends, the normal offline message follows then. Devices show an *In maintenance* badge on their page and the map, and every device page has a **Maintenance…** menu to start a window of 30 minutes to 24 hours right now. The events list and the API show which window held an event back (`maintenance`).

## 0.3.113 — 2026-10-11

### Fixed
- **Containers on the map in the horizontal layout**: the map failed to draw (an error about a missing address) and showed no links; containers have no address and are labelled by name now. When containers are shown, the map also fits the whole picture on the screen once.

## 0.3.112 — 2026-10-11

### Changed
- **Scan schedule and web terminal are separate settings pages**: *Scan schedule* (General) and *Web terminal* (System), each saving and resetting only its own part.

## 0.3.109 — 2026-10-11

### Added
- ★ **One way to enter servers in every plugin**: Technitium, Docker, TrueNAS, Proxmox and SNMP now have a list with one line per server (its address and its own key or token), a **Test** button on every line that tests just that server, a **+ Add server** button for another line and a **−** button to remove one, and **Test all connections** at the bottom tests every line and shows each answer on its own line. TrueNAS and Proxmox can now read several systems (VMs numbered the same on two clusters are kept apart). Existing settings are carried over automatically; nothing to re-enter. Plugin versions: Technitium 1.2.0, Docker 1.2.0, TrueNAS 1.2.0, Proxmox 1.3.0, SNMP 1.1.0 (these need Netlens 0.3.109 or newer).
- ★ **Containers on the map**: Settings → Map has *Show containers and apps under their host* (off by default), and the map's own menu has *Show / Hide containers* for one browser. Running containers and apps that are not a device themselves are drawn as small dashed dots under the host they run on (unhealthy ones outlined in red); click one for its status, image and a link to the host. Virtual machines are devices and stay on the map as before.

## 0.3.0 — 2026-10-11

### Added
- ★ **Netlens 0.3: Docker, and one view of everything that runs on your hosts.** The new Docker plugin shows your Docker hosts with their containers (state, health, restarts, image and its age, compose project, published ports; macvlan and ipvlan containers are matched to the devices your scans found), Proxmox, TrueNAS and Docker now report the same guest details, and Statistics, the events, Prometheus and Home Assistant follow. Containers can get DNS names, the app is readable on a phone, and this window and the changelog in Settings → About tell you what changed after every update. The details are in the releases below (0.2.100 to 0.2.106).

## 0.2.106 — 2026-10-11

### Added
- ★ **Proxmox, TrueNAS and Docker report the same things now**: every guest can carry resources (CPU, memory, disk), system, tags, start time, start at boot, and an app's version with *update available*; Docker also reports how old a container's image is (with `IMAGES=1` on the socket proxy; images older than a year are flagged), and TrueNAS apps report the ports they publish, so the host's *Open ports* table names the app behind a port. Proxmox plugin 1.2.0, TrueNAS plugin 1.1.0, Docker plugin 1.1.0. New events for every guest that is not a container: `guest_stopped`, `guest_started` and `guest_update_available` (off by default in notification channels). Statistics has one section, **Virtual machines, containers & apps**, with counts per kind, updates available, old images and a *Needs attention* list; the summary API has `guests`, Prometheus has `netlens_guests{kind,state}`, `netlens_guests_update_available` and `netlens_containers_old_images`, and Home Assistant (0.9.0) has *Guests running* and *Guest updates available*.
- **DNS names for containers that share their host's address** (Settings → DNS registration, off by default): a running Docker container on a bridge or host network that publishes a port gets a CNAME to its host (`web.home.example.com` pointing to the host), following the host if its name changes. Never over an existing name, never for a host Netlens does not register itself. The Technitium plugin handles CNAME records (1.1.0).

## 0.2.105 — 2026-10-11

### Added
- ★ **Container health everywhere**: a container whose health check starts failing, that keeps restarting, or that crashes raises an event (`container_unhealthy`, `container_restarting`, `container_stopped`) that your notification channels can send, once per change. Statistics has a **Containers** section (running, stopped, restarting, unhealthy, published on all interfaces, and the containers with a problem), the summary API carries `containers` (additive), Prometheus has `netlens_containers{state}`, `netlens_containers_unhealthy`, `netlens_containers_exposed` and `netlens_container_hosts` (a Grafana panel and an alert example are included), and the Home Assistant integration (0.9.0) has *Containers running*, *Unhealthy containers* and *Restarting containers* sensors. Unhealthy or restarting containers count as a problem.
- **Container names for devices**: a macvlan / ipvlan container that Netlens matched to a device gives that device its container name (as a name, and as its host name when it had none), so it is shown and registered in DNS under that name instead of its address.

## 0.2.103 — 2026-10-10

### Added
- ★ **Docker plugin** (`plugins/docker`): shows your Docker hosts with their containers (state, health, restarts, image, compose project, published ports). Containers on a macvlan / ipvlan network are matched to the device their scans found, bridge containers are listed under their host, and the host's *Open ports* table names the container behind each port. Read-only, through a read-only socket proxy (the README has the recipe; the Docker API itself gives full control of a host). Plugins can now report extra details about a guest (schema version 17).

## 0.2.102 — 2026-10-10

### Changed
- ★ **Easier to read on a phone**: nothing is wider than the screen any more (the uptime, scans and device pages used to scroll sideways), the device list is a list of two-line rows with a *Sort* menu instead of a ten-column table, the filters of the Devices and Map pages fold behind a *Filters* button, and spacing and sizes are tighter. Screens wider than 700 px (computers, iPad) look exactly as before.
- **The version in the account menu is a link** to Settings → About (and its changelog).

## 0.2.100 — 2026-10-10

### Added
- ★ **What's new after an update, and a changelog in the app**: after the container is updated, a window lists the notable changes since the version you last saw (once per browser, never on a first visit), and Settings → About → Changelog keeps every release readable, with a switch for notable changes only.

### Changed
- **Technitium plugin 1.0.1** (verified on real Technitium 15.5.1 servers, primary and secondary): a PTR delete that finds nothing left counts as done, because Technitium removes the PTR together with its A record.

## 0.2.96 — 2026-10-10 and earlier 0.2 builds

### Added
- ★ **Second look before marking a device offline** (Settings → Scan performance, on by default): a previously online device that the sweep did not see is asked for once more on its own (`nmap -sn`, 4 retries) before it is marked offline. A switch whose management processor answers ARP late was missed by the big sweep in most scans while it answered 8 of 8 when asked alone; such devices no longer flap. The live test of the Stability card also runs a real quick scan of the single device.
- ★ **Flapping investigation**: the Uptime card on the device page has a collapsible **Stability** section (administrators; the page stops refreshing while it is open). *Investigate* analyses the scan history (gaps, whether the devices behind it stayed up, whether the whole network missed the same scans, periodicity, time of day, slow answers before a gap) and lists findings; *Run live test* asks the device 8 times by ARP, ping and TCP.

### Added
- ★ **DNS registration** with a new plugin kind `dns` and a **Technitium DNS** plugin: Netlens registers the devices it knows (A and reverse records) and follows address changes, after a preview and your approval (or automatically after every scan). It only changes records it created (comment marker plus its own memory), never records made by anything else such as Windows machines that register themselves, waits a grace period before registering, registers only known devices, names nameless devices (`tv-samsung-a1b2`) with a DNS name you can override, and supports a primary and secondary server as well as a Technitium cluster. Per-device *Automatic / Always / Never*, zones per network, DNS events for the notification channels. Schema version 16. Tested against a simulated Technitium server only.
- ★ **SNMP switches plugin** (`plugins/snmp`, in the plugin index as *Community*): reads managed switches over SNMP v1 / v2c (MAC address table, LLDP) and shows **Connected to: <switch> · port <name>** on the device page, and puts the switches and the devices behind them in the hierarchy. A topology plugin can now report a client's `port` (new contract field); Netlens stores where each client is connected (schema version 15) for every topology plugin, so the ASUS, Omada and UniFi plugins also fill *Connected to* with their node. Tested against simulated switches only.

### Changed
- ★ **Top bar**: one slim row (52 px; it was two rows on a desktop and up to five on a phone). Quick scan, Deep scan and Scan settings are in a **Scan** menu; the moon / sun switch stays in the bar; the version, update notice (with a dot on the menu button) and Log out are in the account menu. Below 1040 px the pages and the account menu move into one menu behind a burger button, and on a phone the bar slides away while scrolling down and returns on scrolling up. The Statistics section bar and the Settings side menu follow the bar's real height, the Settings page list folds into one button naming the current page on a phone, and the map legend no longer widens the page on a phone.
- ★ **Statistics page**: a sticky row of buttons jumps to every group and highlights the one in view, the page keeps your scroll position when it refreshes, and there are new groups: *How well Netlens knows its devices* (unknown type, private address, no manufacturer / name / OS, set by hand, gentle, passive listening) and cards for devices by group, backups, DHCP servers, database schema and the manufacturer registry. The summary API (`/api/stats/summary`, still `api: 1`, additive) carries `devices.flapping`, `identification`, `backup`, `netchecks` and `passive`, a failed backup counts as a problem, and Prometheus has new metrics (`netlens_devices_flapping`, `_devices_by_type`, `_devices_by_group`, `_identification_devices`, `_backup_*`, `_dhcp_servers`, `_passive_*`, `_scans_failed_24h`, `_database_size_bytes`, `_vendor_registry_entries`, `_database_rows`) with matching panels in the Grafana dashboard and alert examples.
- **Device page layout**: uptime and service checks come first in the right column, the Edit card is collapsed by default (and compact when open) and now contains *Network position*, and the console is the last card of the left column.

### Added
- ★ **Web terminal: safer and easier to reach**: it now works only on a direct connection from the local network; requests through a reverse proxy / HTTPS address are refused unless `NETLENS_TERMINAL_REMOTE` is `lan` or `any` (environment only, so nobody connecting from outside can open it up), and the terminal switch in Settings can only be changed from the local network. The console moved to the left column under the details (with a *Wide view* button), the device page has an **SSH** (and Telnet) button at the top that jumps to it and focuses the username, Enter connects, and the page's automatic refresh no longer wipes the connection form.
- ★ **Gentle scanning** (device page): a device marked gentle is only checked for open ports; scans never connect to them to identify the service, and skip scripts, OS detection and traceroute for it. Stops devices such as Samsung TVs from asking "a smart device wants to connect" after every deep scan. Schema version 14. Samsung devices with ports 8001 and 8002 open are now recognised as TVs.
- ★ **Installable app (PWA)**: over HTTPS (or on localhost) the browser offers to install Netlens as an app with its own icon and window, and it opens faster. A small service worker caches only the public interface files, network first, so an update shows at once; the API, share links and metrics are never cached or intercepted, so no data is stored on the device and everything still needs a login. Works behind a reverse proxy under a sub-path too.
- **Clear plugin on/off**: a plugin's page starts with a green *ON* or orange *OFF* banner with a *Turn on / Turn off* button (an installed plugin does nothing until it is on), and the plugin list tags every plugin *on* or *off*.
- ★ **Identification, second batch**: the device page has a **Why this type?** card listing every clue with its weight; **identification scripts** (opt-in under Scan performance) add nmap's `http-title`, `ssl-cert`, `nbstat`, `smb-os-discovery`, `upnp-info` and `banner` to deep scans (exact Windows version and computer name, certificate owner, page title, UPnP model); topology plugins may report a client's `vendor`, `os`, `model` and `device_type` (the ASUS plugin now passes the DHCP vendor class and printer flag); **passive listening** reads DHCP requests (name, vendor class, option 55 fingerprint), mDNS and UPnP announcements through a kernel-filtered raw socket (needs `NET_RAW`; switch under Scan performance) and names and types devices that use a private Wi-Fi address; and manual types teach Netlens: two or more devices of a manufacturer set to the same type make that the guess for its other devices.
- ★ **Better device identification**: the vendor now comes from the IEEE registry when nmap's older table does not know it (a copy ships with Netlens, refreshed monthly, with an *Update now* button under Settings → About), virtual-machine and container prefixes (Proxmox, Incus, LXD, Docker, QEMU, VMware...) are recognised, and private (randomized) Wi-Fi addresses are labelled *Private address* instead of *Unknown*. The type is decided by weighing all the evidence (names, mDNS/UPnP hints, nmap's device class and OS name, manufacturer, ports, OS family) instead of the first matching rule, nmap's device class is kept between scans, and there are five new types: tablet, TV / media, speaker, game console, appliance. Known devices are re-classified at startup. Schema version 13.
- **Diagnostics for every plugin**: the built-in Proxmox and ASUS plugins (1.1.0), UniFi (1.0.1) and TrueNAS (1.0.1) now have the **Run diagnostic** button too, the plugin guide (`PLUGINS.md`) tells authors to include `diagnose(config)` (with a copy-paste helper), the plugin template and the downloadable example plugin contain one, and `check_plugin.py` notes a plugin that has none.
- **Plugin diagnostics**: a plugin can offer `diagnose(config)` (`"diagnose": true` in `plugin.json`). Its settings page then has a **Run diagnostic** button that runs it in the isolated process with the form's values, removes the plugin's own settings and every MAC address from the report, and shows it to copy or download, so testers who cannot run scripts can send the plugin's author a report of what their device answered. The Omada plugin (1.0.2) is the first; `check_plugin.py` runs it too.
- ★ **TrueNAS plugin** (`plugins/truenas`, in the plugin index as *Community*): shows a TrueNAS Community Edition (25.04 or newer) as a host with its containers, VMs and apps as guests, over the JSON-RPC WebSocket API with a read-only API key (always over TLS: TrueNAS revokes keys used over plain http). The device page labels app and VM guests.
- ★ **Network checks** (Settings → Network checks): a periodic DHCP discover lists every DHCP server on the network and raises **Rogue DHCP?** for a new, untrusted one; **Gateway changed** when the MAC address behind the default gateway changes. Both break through quiet hours; schema version 11.
- ★ **Groups** (rooms, floors, owners): Settings → Groups, a group per device (device page, Devices page filter, column and bulk *Set group*), *Colour by group* and a group filter on the map, `group` in the summary API and as the suggested area in Home Assistant; schema version 12.
- **HTTPS guidance** in the README: reverse proxy recipes for Synology, Caddy, nginx, Nginx Proxy Manager and Traefik, with the WebSocket and `Host` details the terminal needs.

### Changed
- **Simpler install**: `docker-compose.simple.yml` runs the pre-built image with a Docker volume, needing no `.env` file, no `DOCKERDIR` folder (and no `chown`) and no token; the README has short recipes for Docker, Portainer (for example on DietPi) and Synology Container Manager. The earlier files stay as the *advanced* routes (host folder, build from source).
- **`NETLENS_TOKEN` is optional.** A new install shows a **first-start wizard** (administrator account, networks to scan, first scan); installs that already set the token keep working unchanged with no wizard, and the Users page suggests moving to a user account. `python -m app.cli reset-password | create-admin | list-users` recovers a forgotten password from inside the container. Prometheus and Home Assistant should use an API token from Settings → Users & tokens.

### Added
- ★ **Omada and UniFi plugins** (in `plugins/`, listed in the plugin index as *Community*): **TP-Link Omada** (controller 5.1 or newer) and **Ubiquiti UniFi** (UniFi OS consoles and classic controllers) read which switch or access point every client and device is connected to, with Wi-Fi signal, band and link rate. Read-only, one login per sync. They were written from the public APIs and tested against simulated controllers only, so they are marked *not yet tested on hardware*; each has a tester checklist and a `diagnose.py` that writes an anonymised description of what the controller answers. `plugins/build_zip.py` builds the release zip.
- **Logo and favicon**: a Netlens mark in the top bar, the browser tab, the Apple touch icon, the README and the Home Assistant integration.
- **Domain suffix and map labels**: Settings → Map takes a domain suffix to hide (`blueiris.home.example.com` is shown as `blueiris` everywhere; the full name stays in the database, in tooltips and on the device page), and the map toolbar chooses what is written under each device: name and IP, IP only, or name only (the IP when a device has no name).
- **Scheduled backups**: Settings → Backup & restore makes a consistent copy of the database every 6 hours to every week, keeps the newest 1-60 in `<data>/backups` (private files), lists them with download, restore and delete, and raises a *backup failed* event (also sent to the notification channels) when one fails.
- **Port baselines**: accept a device's current open ports as normal (device page, or *Set baselines* on the Devices page). A port outside the baseline then logs `port_unexpected`, a baseline port that disappears logs `port_missing`, and a port that closes on any device logs `port_closed` (deep scans). The Devices page can filter on changed ports. Schema version 8.
- **Wake-on-LAN, ping and traceroute** buttons on the device page (`POST /api/devices/{id}/wake|ping|trace`); a wake logs a `wake_sent` event.
- **Multiple users**: Settings → Users & tokens adds users with the role *administrator* or *viewer* (read-only: the map, devices, statistics and services, no settings, secrets, exports, backups or terminal). Passwords are stored as scrypt hashes, logins are server-side sessions that end at logout, password change, disable or delete, and login attempts are rate-limited per address and per user name. **API tokens** per user (shown once) work as Bearer tokens with the user's role, so Home Assistant or Prometheus can use a read-only viewer token. `NETLENS_TOKEN` keeps working as a built-in administrator. Schema version 9.
- **Share links**: Settings → Share links makes a secret read-only address that shows the map and device list, or only a status page, without a login. IP and MAC addresses are hidden unless chosen, links can expire and are revoked by deleting them. Schema version 10.
- **Uptime history** (Uptime Kuma style): heartbeat bar per device, 24 h / 7 d / 30 d uptime, response times, an Uptime overview page, and an uptime card on every device page. Kept for 90 days.
- **E-mail notifications** for new and offline devices (one digest per scan), SMTP settings and a test button in Settings, and a per-device switch for offline mails.
- **Proxmox connector**: read-only sync of VMs and containers, matching to devices by MAC/IP, exact `host-of` links on the map, and Proxmox details on the device pages. API token or password login.
- **Plugin index**: *Settings → Browse plugins* lists community plugins from `plugin-index/index.json` in this repository, with review levels (Verified / Reviewed / Community), install with a pinned SHA-256, update notices, rollback to the previous version and a custom or switched-off index. The repository holds the submission process (`plugin-index/README.md`), a plugin template, a local checker (`tools/check_plugin.py`) and CI that verifies every download, scans the code, keeps published versions immutable and limits review records to trusted reviewers (`REVIEWERS`, `CODEOWNERS`). The built-in Proxmox and ASUS plugins and an `example-router` plugin are the first entries.
- **Netlens update notice**: a badge and an Updates card when a newer image has been published (checked once a day, can be switched off); `GET /api/update`; `update` in the statistics summary and `netlens_update_available` in the metrics.
- **Known / unknown devices** (existing devices are all known after the upgrade; new ones start unknown), an *Unknown only* filter, *Trust all unknown*, an **IP reused** event; schema version 7.
- **Better identification**: UPnP descriptions and mDNS service types and friendly names as discovery hints (kept per device), names from the router, and word rules on device names; an SSDP product token is no longer used as a hostname.
- **Wi-Fi details**: signal, node, band and link rate per client from topology plugins (new optional client fields `rssi`, `tx_mbps`, `rx_mbps`), a Wi-Fi card with history and roaming events on the device page, a Wi-Fi group in the statistics.
- **Service checks** (HTTP, TCP, DNS) with history, events and a Services page.
- **Notification channels** (ntfy, Telegram, Discord, Pushover, webhook) with per-channel events, a test button and **quiet hours**; e-mail also reports service changes.
- **Prometheus `/metrics`** and a Grafana dashboard under `contrib/`.
- **Statistics page** with groups for history, composition, availability, ports and services (counts only), network structure, scans, events and system, with 24 h / 7 d / 30 d / 90 d periods; `GET /api/stats`, a small versioned `GET /api/stats/summary` for integrations, and `since_id` on `GET /api/events`. A daily snapshot table (schema version 6) keeps the long-term history.
- **Plugins**: the Proxmox and ASUS connectors are now plugins of two kinds (`hypervisor`, `topology`) that only fetch data in a fixed, validated format; Netlens does the matching and linking. Each plugin can be turned on or off, has a settings page generated from its `plugin.json`, runs in its own isolated process with a time limit, and a failing or invalid plugin keeps its last good links without disturbing the others. **Upload your own plugins** (zip) under Settings → Plugins; the plugin guide (`app/plugins/PLUGINS.md`, also in the app) documents the package and the exact output, and an example plugin can be downloaded. API: `/api/plugins` (replaces `/api/proxmox` and `/api/asus`). Database schema version 5 migrates the old settings, guests and links automatically; the hierarchy source `proxmox` is now `hypervisor`, and the device page's Proxmox box is *Virtualization*.
- **Settings pages**: every entry of the Settings menu is its own page with its own address, grouped under General / Notifications / Integrations / Data / System (the long single page and its scroll-spy are gone; the old `#/settings/proxmox` and `#/settings/asus` addresses still work).
- **ASUS router / AiMesh connector** (Settings → ASUS router): reads which device is connected to which mesh node and adds `uplink` links, so the hierarchy and the map show the real network position of every wired and Wi-Fi client (and the mesh nodes below the main router). Read-only, over the router's HTTPS web interface: one login, two reads and a logout per sync, never SSH, so no sessions stay open on the router. A refused login pauses automatic syncing so the router does not lock the account.
- **Horizontal map layout** (Omada style): left-to-right columns, a card per device with its name and address, right-angle parent links, and busy branches folded into `▸ N more` (double-click or the details panel to open them, plus Collapse clients / Expand all / Fit). **Settings → Map** chooses the layout the map opens with (`GET/PUT /api/map-settings`); a layout picked in the map itself is remembered per browser and wins.
- **Backup and restore** of the whole database from Settings.
- **Live scan progress** (current nmap step, percentage, hosts found) with elapsed time and the typical (median) duration of recent scans of the same type, shown in a strip under the header while a scan runs.
- **Scan performance settings** (Settings → Scan performance): nmap timing, number of top ports or a custom port list for quick and deep scans, version detection (full/light/off), OS detection, traceroute, reverse DNS and a per-host timeout, with Default/Fast/Fastest presets, the resulting command lines and the duration of the last scans. A **Scan settings** button next to the scan buttons opens it.
- **Dark / light mode** switch at the right of the top bar (remembered per browser, follows the system until you choose); the map canvas follows the theme. Dark mode was tuned for legibility and is verified by measured contrast: links use one themed blue, every text meets 4.5:1, map device colours and link colours meet 3:1 against the canvas, map labels have a halo, offline devices have a dashed outline, and the map legend shows the real colour and line style of each link type.
- **Delete a device** from its page, optionally ignoring it in future scans; **Settings → Ignored devices** lists them and lets you undo. Database schema version 4.
- **Full scan of a single host** (all TCP ports, versions, OS, traceroute) from the device page, with progress, cancel and a `full <ip>` entry in the scan history.
- **Network hierarchy**: every device gets a parent (manual choice, Proxmox host, traceroute, default gateway), shown on a new **Hierarchy** page, as a *Hierarchy links* view and *Tree layout* on the map (Proxmox guests now hang under their host), and editable per device under **Network position**. Loops are impossible. API: `GET /api/hierarchy`, `parent_mode`/`parent_device_id` on devices. Database schema version 3 (migrates automatically).
- **Host timeouts** for scans (default 120 s for quick and 900 s for deep scans, editable under Scan performance): nmap gives up on a host that takes too long, so one slow device can no longer hold a scan up for an hour. A timed-out host stays online, keeps its known ports, and logs a "Host timeout" event.
- **Cancel scan** button in the scan strip (and `POST /api/scans/cancel`): kills nmap, marks the scan `cancelled`, saves nothing.
- **Settings menu**: a sticky index on the left of the Settings page links to every section and follows your scrolling; sections can be deep-linked (`#/settings/proxmox`).
- **Settings in the browser** for scan ranges, quick/deep scan interval and the web terminal switch (no restart needed).
- Friendly scan error messages (missing capabilities, nmap missing, timeout, no ranges).
- Version shown in the UI and API; the version rises with every build. LICENSE (MIT).
- CI runs the test suite before the Docker image is published.
- Static test that every browser module only imports helpers that exist and are imported.

### Changed
- Scan options: the single host timeout became separate quick and deep timeouts (settings saved by earlier builds still load).
- Static files are served with `Cache-Control: no-cache` so an update is picked up immediately.
- The web terminal is switched on and off at runtime instead of at startup.
- Database schema version 2 (migrates automatically; existing data is kept).

### Fixed
- Settings menu and deep links: a section scrolled to the top is no longer hidden behind the sticky top bar (also on narrow screens, where the bar wraps).
- Dragging a node on the map now opens its details panel.
- Device page: duplicated content, repeated "Failed to load device" toasts and a false "Save failed" message.
- Map: error on open/refresh, filters that never worked, and the empty details panel after clicking a device.
- nmap capability mismatch that stopped scans from starting in the container.

## 0.1.0 — first builds

### Added
- First release: scanning, device inventory, classification, network map, web terminal, Docker image.
