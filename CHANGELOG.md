# Changelog

The version is `<major.minor from VERSION>.<commits since VERSION last changed>` (`contrib/version.sh`). Each heading below is a release: it covers every build from that number up to the next heading. A leading ★ marks a notable change; those are what the "What's new" popup shows after an update. Netlens reads this file for Settings → About → Changelog, so keep the format (`## 0.2.N — date`, `### Added|Changed|Fixed`, `- ★ **Title**: text`).

## 0.4.215 — 2026-10-24

### Added
- ★ **Quick checks between the scans.** A scan finds and describes devices (every 15 minutes by default) and used to be the only thing that said whether a device was up. Netlens now also pings the always-on devices once a minute (one nmap host discovery for all of them), records every answer, marks a device offline after three missed answers in a row (about three minutes instead of up to fifteen, and one lost packet is not an outage) and online again at the first answer. Service checks already had their own interval (60 seconds by default) and are unchanged. Set the interval, the number of misses and whether every device or only the always-on ones get the quick check under Settings → Scan schedule; 0 switches it off. The rows of quick checks are kept for three days; the hourly roll-up keeps their counts, so the uptime figures and graphs get one measurement a minute.
- ★ **Bars that show how much was missed.** A bar in the Uptime-Kuma-style strips that stands for several checks (a slice of 15 minutes, or of a day) is now coloured on a scale from green to red by how many of its checks failed: one lost check in fifteen is yellow-green, half is orange, all is red. The tooltip says "Partly down · 2 of 15 checks failed (13%)". The service bars now show the last 24 hours in 60 slices the same way.

### Changed
- Availability percentages of a single device (device page) come from the hourly roll-up like the overview already did, so they include the quick checks. Flapping, the monthly report and the scan statistics keep counting the scans only.

## 0.4.212 — 2026-10-24

### Changed
- ★ **One way to arrange cards on every page that has them.** The dashboard, the device page (each tab) and Statistics now work like the Overview beta page did: Customize opens a drawer on the right with a tick box and a small picture for every card (tick one to show it, untick to hide it), and in editing mode every card has a grip to drag it anywhere (also by touch), a ↔ button that makes it narrow, wide or full width, and a ✕ to remove it. Changes are saved on the server as you make them, per user (and per device type on the device page). Administrators can push the arrangement as the starting point for everybody (the dashboard default, or a template for a device type or all devices); everybody can still change it for themselves and go back with Reset.
- The same arrangement is on **Insights, Network health, Vulnerabilities and each Remote site page** (a Customize button in the page header).
- Device and Statistics cards are laid out in a grid of up to four columns instead of flowing columns, so the order you choose is the order you see.

## 0.4.209 — 2026-10-24

### Changed
- **The device Edit card is always open and easier to read.** Settings → Edit no longer hides behind an arrow: it is a full-width card in four groups (Identity, Monitoring and reports, Scanning, DNS registration). The network position (parent and port) is part of the same card and saved by the one Save button. Every explanation is now text under its field instead of a tooltip, every label is tied to its field for screen readers and tapping, and the fields sit in columns that fit the screen.

## 0.4.208 — 2026-10-24

### Fixed
- **Open ports on the device page** no longer runs over the card next to it: the card is full width by default and its table scrolls inside the card when it is still too wide.
- **Plugin pages have one switch.** The "Enabled" tick box next to the ON/OFF banner is gone; the banner's Turn on / Turn off button is the only way, so there is no way to get them out of step.

## 0.4.204 — 2026-10-24

### Changed
- **The AI settings are two pages**, each with one Save button: "AI language model" and "AI agents (assistant, MCP)".
- **Hierarchy starts without the containers**, so the tree shows your devices; the "Show containers" box brings them back and remembers the choice.
- **Share links**: the options of a new link sit side by side in groups; every create or add button is blue like the save buttons. Delete buttons inside a table row are outlined so a column of them does not shout.
- **Plugin manager**: the "report a plugin as a problem after N failed syncs" setting is one line, and the status of a failing plugin has room to be read. Narrow screens (iPad portrait) keep the last columns of the Services table in view.
- **Remote access** lists the devices one per line. The design rules for every page are written down in contrib/UI-RULES.md.
- **Backup list** shows the newest six, with a button for the older ones. The summary figures on pages like Smart home fit one row when they can.

### Fixed
- The audit log wrote "{0}" instead of the plugin or site name for plugin settings and remote-site commands.

## 0.4.202 — 2026-10-24

### Changed
- ★ **DNS settings moved to Settings → DNS registration.** The DNS page now only shows what Netlens would register: the state figures filter the list when you click them, and it links to the settings. The DNS conflict warning on the dashboard opens the DNS page.
- **One look for buttons.** The button that saves is always blue and first in its row, Cancel, Reset and Close are plain, and delete buttons are red and last. Settings forms put their fields side by side instead of one long column of full-width fields. The list of unacknowledged escalations shows the newest eight.

## 0.4.200 — 2026-10-24

### Changed
- **Better use of wide and ultra-wide screens.** The dashboard fills the width with up to six columns instead of four stretched ones, the device page shows three or four columns of cards, the Uptime list runs in two or three columns, Statistics cards get more room for their tables, and form fields on the Settings pages no longer stretch across the whole screen. Buttons and single-line fields in forms (plugin manager, speed test schedule and others) keep a sensible width instead of spanning the card.

## 0.4.199 — 2026-10-24

### Changed
- ★ **A dashboard that is about monitoring.** The default dashboard now starts with what needs attention, then devices online, uptime, services, health, unstable devices, your storage and backups (when you have them), vulnerabilities, recent events, the least reliable devices, the 14-day trend and the capacity forecast. The map, the internet speed and the infrastructure summary are still available as cards but are no longer there by default; a layout you arranged yourself is not touched. A new Storage card shows the health of your storage systems and links to the problems.
- **The Overview page is part of the dashboard.** All its statistics (devices by type, vendors, Wi-Fi, applications, traffic, availability, internet speed and more) are cards you can add to the dashboard with Customize, and the separate Overview page and its menu item are gone (an old link opens the dashboard).
- **Settings in one place.** The setting of the version check against the CVE list moved from the Vulnerabilities page to Settings → Version check; the Vulnerabilities page starts with the results and links to it.

### Fixed
- Long host names no longer push tables and the "What changed" list out of their frame (a sideways scroll bar on Statistics and What changed).

## 0.4.197 — 2026-10-24

### Added
- ★ **Customize the device page.** A Customize button on every device page opens a drawer where you hide cards, change their order and make them full width, per section (Overview, Health, Network, Settings). Your layout is saved on the server (so every browser and iPad shows it) per device type, so Windows devices can look different from switches. An administrator can save the current arrangement as the template for a device type, or for all devices; everybody starts from it and can still change it for themselves, with a button to go back.

## 0.4.196 — 2026-10-24

### Changed
- ★ **A problem always leads to where you can see it.** Storage problems (unhealthy systems, failed disks, filling pools, open alerts) now appear in "Needs attention" on the dashboard; they and the backup problems open the Storage or Backups page with the affected systems already expanded and scrolled into view. The problem figures at the top of those pages are clickable too and do the same.

## 0.4.195 — 2026-10-24

### Changed
- **One look for corners and spacing.** Containers (cards, tiles, dialogs, table frames) share one corner radius and controls another, instead of a mix of 4 to 14 pixel values. Tables now have the same soft frame on every page. Cards, page margins, grid gaps and the side menu are a little tighter, so more fits on the screen.

## 0.4.194 — 2026-10-24

### Changed
- ★ **The menu only shows what you use.** Backups, Storage, Smart home, Vulnerabilities, DNS and Remote sites appear in the menu once a matching plugin is switched on or the page already has data. Nobody sees empty pages for things that are not set up; an administrator gets a "+ More features" link to the Plugin store. Direct links and search keep working.

## 0.4.193 — 2026-10-24

### Changed
- ★ **Faster start, especially from the home screen of an iPad.** The scripts and style sheets of the installed app now come from the device itself instead of from the server (they never change within a version), so opening the shortcut no longer waits for dozens of requests; files of older versions are cleaned up automatically. The loading screen also shows a progress bar under the spinner while the files come in.

## 0.4.192 — 2026-10-24

### Changed
- **Storage and Backups pages: no box around the system list.** The list of systems now uses the full width of the page instead of sitting inside a framed card.

## 0.4.191 — 2026-10-24

### Changed
- **Backups page: one line per backup server.** Like the Storage page, every backup server is now one line (state, fullest store, guests backed up, failed, late, newest backup); click a line to open its stores, the backup of each guest and its recent problems. The guests without a backup and the remote sites stay as they were.

## 0.4.190 — 2026-10-24

### Changed
- **Storage page: one line per storage system.** The page now lists every system in a compact table (state, fullest pool, number of pools, volumes, disks and open alerts); click a line to open its pools, controllers, volumes, disks and alerts. The open lines are kept when the page refreshes.

## 0.4.188 — 2026-10-23

### Added
- ★ **iSCSI for Synology and NetApp ONTAP.** Synology plugin 1.2.0 lists the LUNs of SAN Manager (size, space used, volume) and links the hosts that are logged in to their target to their devices; tested on a virtual DSM 7.2 with a real iSCSI login. NetApp ONTAP plugin 1.1.0 does the same through the iSCSI sessions and LUN mappings (simulator only). QNAP is not done yet: its iSCSI calls are not documented well enough to write without a QNAP to test on.

### Fixed
- **Open alerts on the Storage page are no longer cut short or full of HTML.** Alert texts such as TrueNAS's "deprecated REST API" warning were cut at 300 characters and showed `<br>` tags. Netlens now turns the markup into plain text and keeps up to 600 characters; TrueNAS plugin 1.6.1 stops cutting the text before it arrives.

## 0.4.186 — 2026-10-23

### Added
- **TrueNAS plugin 1.6.0 shows the boot pool and unused disks.** The operating-system disks appear as the pool *boot-pool* (with its size and fill level), so they are no longer missing from the disk list, and a disk that belongs to no pool is listed as *not in a pool*.

## 0.4.184 — 2026-10-23

### Fixed
- **TrueNAS plugin 1.5.1:** the size of a file-backed iSCSI LUN is read when TrueNAS sends it as text (a LUN on a zvol was already right). Confirmed on a real TrueNAS 25.10.6: pools, disks, shares, alerts and an iSCSI LUN with the PC that is logged in to it.

## 0.4.182 — 2026-10-23

### Added
- ★ **TrueNAS plugin 1.5.0 shows iSCSI.** Every iSCSI LUN (extent) appears on the Storage page with its size, how much is used and the pool it lives in, and the hosts that are logged in to its target are linked to their devices, so a PC that boots from or uses a TrueNAS disk shows "uses iSCSI <LUN> on <NAS>" on its device page. Needs the *Run diagnostic* report from a real TrueNAS if a LUN or its client does not show: the iSCSI calls were written from the middleware's documented API.

## 0.4.180 — 2026-10-23

### Added
- ★ **NAS plugins can fill the Storage page too.** A plugin of any kind (for example a hypervisor plugin for a NAS or a hyperconverged system) may now add a `storage` part to its answer, so a NAS shows its containers and virtual machines *and* its pools, volumes, disks and shares. Updated plugins: TrueNAS 1.4.0 (pools, their disks, NFS and SMB shares, open alerts), Synology 1.1.0 (storage pools, volumes, disks, shared folders; the volumes were read from a real DSM 7.2.2), OpenMediaVault 1.1.0 (file systems, S.M.A.R.T. status, shares), Unraid 1.1.0 (array, cache, disks, shares), Rockstor 1.1.0 (Btrfs pools, disks, shares), QNAP 1.1.0 (volumes, disk health) and UGREEN 1.1.0 (volumes, disk health). Same read-only access as before. Everything but the Synology volumes was tested against simulators, so send a *Run diagnostic* report if a Storage page stays empty. The contract is described in `app/plugins/PLUGINS.md`.

## 0.4.178 — 2026-10-23

### Added
- ★ **Storage: a new plugin kind and a Storage page.** A storage plugin reports a storage system with its controllers, pools, volumes, disks and open alerts. Netlens finds the array and its controllers on the network by address or MAC, shows the pools with their fill level, and links the hosts that use a volume (NFS clients, iSCSI initiators) to their devices, so a device page tells which volumes it uses and a volume tells who depends on it. Events: a system, pool or disk becomes unhealthy or recovers, a pool passes 85 and 95 percent, a new critical alert (Storage problem, Storage recovered). The contract is in `app/plugins/PLUGINS.md` (kind `storage`).
- ★ **Three storage plugins in the Plugin store: Redfish, NetApp ONTAP and Ceph.** *Redfish* reads servers and arrays through their management controller (Dell iDRAC, HPE iLO, Lenovo XClarity, Supermicro, Cisco CIMC ...): health, power supplies, fans, drives and RAID volumes, with the BMC and the network cards matched to your devices by address and MAC; it was run against the official DMTF Redfish mockup server. *NetApp ONTAP* shows nodes, aggregates, volumes, LUNs, disks and the NFS clients of every volume (simulator only, so Community level). *Ceph* shows health and its checks, hosts, pools, OSDs, CephFS with its clients and RBD images; it was tested on a real Ceph 19.2.7 cluster. The new plugin category *Server hardware* holds Redfish.

## 0.4.177 — 2026-10-23

### Added
- ★ **Five NAS plugins in the Plugin store: OpenMediaVault, Unraid, Rockstor, QNAP and UGREEN.** Each shows the NAS as a host with its Docker containers (state, image, published ports, and the address of a container with its own IP) as guests; OpenMediaVault and Unraid also show virtual machines, QNAP its LXD containers, Rockstor the containers of its Rock-ons. Read-only. OpenMediaVault is verified on a real system (containers); the other four were written from published schemas, source code and community API notes and are tested against simulators only, so they show as Community: please send a *Run diagnostic* report from a real NAS.

## 0.4.175 — 2026-10-23

### Added
- ★ **A side menu replaces the top menu.** The pages sit in a menu at the left, grouped (Overview and Dashboard, Network, Monitoring, Analysis, Automation, Configuration); the top bar keeps the Scan menu, search, the light/dark switch and the account menu. The button at the left of the top bar folds the menu away (remembered), and on iPad and phone it slides over the page.
- ★ **Overview (beta).** A new first page in the menu with tabs of widgets: device counts, devices over time, availability, ports, Wi-Fi quality, speed tests and traffic (about 30 widgets). Use the gear to choose the widgets of a tab, drag the grip of a widget to move it, the arrow button to make it 1, 2 or 3 columns wide, and 1D / 1W / 1M for the period. You can add tabs of your own. It is a first version: the layout is kept in the browser.

## 0.4.174 — 2026-10-22

### Fixed
- **The menu button on a phone is on screen again.** The site selector pushed the burger button out of the top bar; on narrow screens the selector now sits on a row of its own under the bar.

## 0.4.167 — 2026-10-22

### Added
- **Open a remote device in the site's own interface.** On a remote site's page every device has an *Open* button (when the site allows viewing and is connected) that opens that device's page, with all its tabs, in the site view.
- **The Network tab of a device arranges its cards itself**: they flow over two columns, so the Applications card sits at the top left and short cards no longer leave holes.

## 0.4.165 — 2026-10-22

### Added
- ★ **Remote sites with the same pages as a local site.** A remote Netlens can allow the central one to show it (Settings > Report to a central Netlens > *Let the central Netlens show this site*, off by default). The central Netlens then has a site selector in the top bar: pick a site and every page shows that site's own data, live and read only (devices with their pages, graphs, ports, applications, statistics, map, uptime, events). Nothing is copied: the remote keeps one request open to the central one and answers the pages' requests from its own data, so the connection still always goes out from the remote site. Accounts, backups, the licence and other secrets are never shown. Only administrators of the central Netlens can use it; *Remote sites > Open this site* does the same.

## 0.4.161 — 2026-10-22

### Added
- ★ **Application statistics are optional and off by default** (Settings > Traffic statistics). In some countries this data may not be collected, so nothing is read from a router and nothing is stored until an administrator ticks the box; switching it off again deletes everything stored. The router plugins are told, so the ASUS router is not even asked while it is off. If you used the statistics before this version, tick the box once.
- ★ **Applications per device.** A device's Network tab has an Applications card: which applications that device used (today, 7 or 30 days) and the traffic per day. The ASUS plugin (1.3.0) reads this for the 25 busiest devices, the Omada plugin (1.3.0) for every client it reads; only administrators see it.
- ★ **Port graphs on the Network tab.** The Ports card (traffic in and out, how full the link is, errors, and a graph per port) moved from the Health tab to the Network tab of a switch, next to the Switch ports and the faceplate. Ports a plugin reads now also get a Busy figure (the busier direction against the negotiated link speed).
- Traffic figures are shown in GB and TB where they were MB.

## 0.4.159 — 2026-10-22

### Added
- ★ **Omada: application statistics.** The Omada plugin (1.2.0) can fill Statistics > Network > Applications with the controller's DPI figures. Omada only offers them through its Open API, so enter an Open API client ID and secret (Omada: Settings > Platform Integration > Open API, Client Credentials, Viewer) in the plugin's settings and switch DPI on at the gateway; leave them empty and nothing changes. The figures are read per client and added up, so Netlens shows applications and devices. Written from the API the Home Assistant Omada integration uses and tested against a simulated controller only: *Test connection* and *Run diagnostic* report whether it works on your controller.

## 0.4.154 — 2026-10-22

### Added
- ★ **Statistics > Applications**: which applications and which devices used the traffic, as the router counts it. The ASUS plugin (1.2.0) reads the router's **Traffic Analyzer** (Adaptive QoS > Traffic Analyzer; switch it on in the router, the first figures appear after about an hour): bytes up and down per application (Netflix, DNS, Claude, BitTorrent ...) and per device, per day, with the day ending at the router's own midnight. Statistics shows the top applications, the top devices and the traffic per day for the chosen period. Plugin API: a topology plugin can report `usage` (a list of days with `applications` and `clients`, each with `rx_bytes` and `tx_bytes`).
- ★ **Omada: switch ports and the port of every wired client.** The Omada plugin (1.1.0) now reads the ports of every switch (link up or down, speed, duplex, byte counters), so the switch's page gets the Switch ports card, the faceplate and traffic graphs per port, and a *link down* / *link up* event when a port changes. A wired client now shows which switch **port** it sits on. The controller's own application statistics (DPI) are not read: that part of its API is not documented.
- ★ **Version check against the CVE list** (Vulnerabilities page, a licensed feature): a light first look without a scanner. Netlens takes the product and version of every service its deep scans found (deep scans now also record the CPE name nmap derives from the banner), asks the public NVD which known vulnerabilities affect that version, keeps those whose affected range really contains the version, and lists them as findings (plugin *cvecheck*) next to those of Greenbone and the other scanners, worst first. Off by default; once a day; results cached for a week; an optional free NVD API key (stored encrypted) makes the first run fast. Only the product name and version leave Netlens, nothing is sent to your devices. It judges the version number only, so a finding on a distribution package (Debian, Ubuntu, Red Hat ...) says that it may already be patched. Set it up on the Vulnerabilities page.
- **Port byte counters in the plugin API**: a switch port can report `tx_bytes` and `rx_bytes`; they become traffic graphs in bits per second (before, only packet counters were possible).

## 0.4.152 — 2026-10-22

### Added
- ★ **Firewall plugins: Fortinet FortiGate, Palo Alto Networks and Check Point** (Community; built from the public API documentation and tested against simulated firewalls, not yet against real ones). FortiGate and Palo Alto report the firewall as the gateway with its interfaces and the devices behind it (DHCP leases, ARP, and on FortiGate its own device inventory with vendor, operating system and kind of device). Check Point reads the gateways, clusters and servers a management server manages, with version and operating system. Read-only, with a read-only token, key or session.
- ★ **Firewall card** on the device page: firmware version and serial number, high availability (which unit is primary, whether the pair is in sync), VPN tunnels up or down, and licences and support with days left. New events: *firewall failover*, *VPN down*, *VPN up* and *firewall licence ends soon*, which can go through the notification channels and the SIEM forwarding. Plugin API: a topology node can carry a `firewall` part, and a node without a MAC address can be given by its `ip`.

## 0.4.151 — 2026-10-22

### Fixed
- ★ **Insights: "Why is example.com offline?"** now finds the website (also when it is typed as "example. com" or without the word *service*) and looks at the reverse proxy: when the site is **disabled in the proxy** (nginx proxy manager), that is the answer, instead of the TLS or 502 error the check sees as a result. It also says when the proxy forwards to a device that is offline. New question tool `site`, also available to the model.

## 0.4.150 — 2026-10-22

### Changed
- When the switch already sits below a device in the network tree (the gateway, for example), connecting that device to a port now offers three choices: only record the port and leave the tree as it is, turn the tree around, or cancel. The gateway then shows on that port as *towards the gateway*, and the switch's card says which of its ports leads there.

## 0.4.149 — 2026-10-22

### Changed
- Connecting a device to a port of a switch that currently sits below that device (for example to refine "below the server" into "on port 14 of the switch") now asks first, and then turns it around in one go: the switch is no longer placed below the device, the parent you had set for it is removed, and the device is connected to the port.

### Fixed
- The device page no longer refreshes itself while you fill in the connection forms (*Connected devices* and *Network position*), so what you type is not lost.

## 0.4.148 — 2026-10-22

### Added
- ★ **Which device is behind which switch port**: the switch's page has a new *Connected devices* card with a faceplate (one block per port: link, speed and the device on it), a list of what is on the chosen port, and devices that sit below the switch with no known port. A port that leads to a second switch lists the devices behind it. The *Switch ports* table has a *Connected* column, and the map shows the port of a device's link in its tooltip and side panel.
- ★ **Set the connection by hand** for switches that cannot tell (TP-Link Easy Smart): choose the switch and the port in the *Network position* card of the device, or pick a device from the faceplate. Several devices can share a port, and a device behind a second switch is connected to that switch. The device also sits below the switch in the network map. A plugin never overwrites a connection you set; if the plugin reports something else, both are shown.
- Links from switch plugins now remember the switch as a device of its own, so the port list of an SNMP switch works without a port inventory.

### Fixed
- On a device page, the refresh every 20 seconds closed the open port graphs and could throw the page back to the top. Open ports stay open and the page keeps its scroll position while cards fill in.

## 0.4.147 — 2026-10-21

### Added
- ★ **Graphs per port for TP-Link Easy Smart switches**: every sync now records packets per second (sent and received), errors per second and the link state of each port as time series. They appear as graphs in the *Ports* card of the switch's page (click a port), with the period selector, and can be kept for as long as other measurements. A port that never had an error gets no error graph, and a port the administrator switched off is not shown as down. The *Switch ports* card keeps the link speed, errors in the last 24 hours and link changes.

## 0.4.146 — 2026-10-21

### Changed
- Documentation: the SNMP plugin's page (SNMPv3, Cisco per-VLAN tables, CDP), the plugin overview in the repository, and the README note on CDP are up to date.

## 0.4.144 — 2026-10-21

### Fixed
- ★ **Device pages did not open** ("Cannot declare a const variable twice: 'portsSlot'") since 0.4.139, when the Switch ports card reused a variable name. A new test parses every interface script with Node, so a mistake like this fails the build instead of the page.

### Added
- ★ **SNMPv3 in the SNMP switch plugin (1.3.0, in the repository, not yet released in the plugin store)**: choose *v3* and enter a user, an authentication protocol (SHA, SHA-2, MD5) and an encryption protocol (AES-128 or DES), each with a password. Version v1 and v2c work as before. The ciphers are written in plain Python because plugins cannot use packages; they match the standard test vectors and a reference implementation, and the client was tested against a real net-snmp 5.9.3 agent with every combination. A wrong password or unknown user stops the automatic syncing until you correct it, and the error says which one it is.

## 0.4.143 — 2026-10-21

### Added
- **SNMP plugin 1.2.0 (in the repository, not yet released in the plugin store)**: a Cisco Catalyst keeps one MAC address table per VLAN, so the plugin now reads every VLAN with `community@vlan` (setting *Cisco VLAN indexing*), and it uses Cisco's CDP neighbours as links between switches when LLDP is not there. Neighbours are matched to your switches by LLDP MAC, CDP management address or name. Tested against a simulated Catalyst; not yet against a real one.

## 0.4.140 — 2026-10-21

### Added
- **TP-Link Easy Smart switch plugin 1.0.0 is in the plugin store** with the *Verified* badge (tested on a real TL-SG1016PE). Needs Netlens 0.4.139 or newer.

## 0.4.139 — 2026-10-21

### Added
- ★ **TP-Link Easy Smart switch plugin** (TL-SG105E, TL-SG108E, TL-SG1016PE...): these switches have no SNMP, so the plugin reads their web pages. The switch appears as a node, with a new **Switch ports** card on its device page (link state and speed, packets per second, bad packets in 24 hours, link changes) and `link_down` / `link_up` events. Topology plugins can now report `ports` for a node (see `app/plugins/PLUGINS.md`). Tested on a real TL-SG1016PE; use *Run diagnostic* if another model does not work.

## 0.4.138 — 2026-10-21

### Changed
- ★ **Gentle scanning is chosen per kind of device**: Settings → Scan performance now shows a tick box for every kind (printers, smart devices, cameras, TVs, speakers, consoles, appliances, phones, NAS, computers, servers, network gear...). Tick only the TV if nothing else minds being probed; **Scan everything fully** restores the previous behaviour, **Recommended** the defaults of 0.4.137.

## 0.4.137 — 2026-10-21

### Fixed
- ★ **An update showed the old version** (seen with Portainer): editing or duplicating a container copies all its environment variables into the new one, including the `NETLENS_VERSION` the previous image had set, so the new image kept reporting, and serving the interface files of, the old version (the browser caches those per version). The version is now also written into the image as a file, and that file wins over the variable. A leftover variable is ignored and mentioned in the System log.

### Changed
- ★ **Gentle scanning is on by default for printers, smart devices (IoT), cameras, TVs, speakers, game consoles and appliances.** Deep scans only check which ports are open on these (no service detection, scripts or OS detection), because the probes made some printers print rubbish and can hang or reboot cheap cameras and smart plugs. Quick scans were never affected. Change the list under Settings → Scan performance → Gentle device types (empty = scan everything fully), or untick *Gentle scanning* on one device's page. Consequence: service names, versions and the OS of these devices are no longer refreshed; run a full scan on one when you want them.

## 0.4.136 — 2026-10-20

### Changed
- **Portable SQL** (preparation for running the database on its own server): the application code no longer uses SQLite-only statements. `INSERT OR REPLACE/IGNORE` became `ON CONFLICT`, new row ids come from `RETURNING id` instead of `lastrowid`, case-insensitive sorting and searching use `LOWER()` instead of `COLLATE NOCASE` and a case-sensitive `LIKE`, date arithmetic is done in Python instead of `datetime('now', ...)`, and everything that is specific to one engine (listing tables, copying the database, refreshing statistics) sits in `app/dbengine.py`. Nothing changes for you, except that the audit log clean-up and the IPv4 health event counts now use exact ISO times (they compared against a differently formatted time before).
- The device search and the audit log search ignore case explicitly (they relied on SQLite's `LIKE` doing so).

### Added
- `docs/SQL-RULES.md` (the portable SQL rules) and `tests/test_portable_sql.py`, which fails when a SQLite-only construct appears outside the few modules that are SQLite files by nature (schema, metrics store, file backup, file upkeep).

## 0.4.135 — 2026-10-20

### Changed
- ★ **Far fewer database round trips for the busy pages** (preparation for running the database on its own server): the dashboard needed 312 statements on a 500-device network and now needs 134, the statistics summary 274 → 97, the monitors page 210 → 11, the service checks list 203 → 5, and the availability report 7,716 → 94. The graphs now read the newest value of all series of all devices at once instead of one query per series, the lists look up the 24-hour uptime and device names in one statement, the availability report fetches the checks of 50 devices per statement, and a connection no longer asks the database for the name of its own file. The answers are unchanged. On the local SQLite file this is a little faster; with a database server on the network (0.5 ms per statement) the dashboard goes from about 0.36 s to 0.26 s and the availability report from 4.7 s to 0.8 s.

### Added
- **Slow-query log**: set `NETLENS_SLOW_QUERY_MS` (for example `50`) and every database statement slower than that is written to the system log (Scans & events → System log) with its duration, the place in the code and the statement. Off by default.
- **`tools/dbbench.py`**: counts the statements each page runs and shows how long it would take if every statement cost an extra 0.5 or 2 ms (a database on the same host, on a LAN, over a VPN). A new test (`tests/test_query_budget.py`) fails when a page runs more statements in a bigger network or goes over its budget, so a query inside a loop cannot come back unnoticed.

## 0.4.134 — 2026-10-20

### Added
- ★ **MCP server**: AI agents (Claude, OpenClaw, Cursor and other Model Context Protocol clients) can now use Netlens as a set of tools at `/mcp`. 40 tools look (dashboard, devices, events, what changed, remote sites and their availability, scans, logs, plugins, alert channels ...) and 42 change things (start scans, ping, scan or wake a device, edit devices and groups, service checks, snoozes, maintenance windows, notification channels, quiet hours, remote sites and their managed checks, scan ranges and intervals, retention, database maintenance, the weekly report), plus `api_request` for any other call the token may make. Every tool is one call to Netlens' own API with the agent's assistant token, so the assistant limits and the audit log apply unchanged. **Settings → AI → MCP server** switches it on (it is off by default), allows or forbids changes, sets a calls-per-minute limit, turns groups of tools off, makes a token and shows the settings for Claude Code, JSON-configured agents and `mcp-remote`.

### Fixed
- An assistant token could not end a snooze (`DELETE /api/snoozes?subject=...`), although the assistant documentation says it may; it can now.

## 0.4.133 — 2026-10-20

### Fixed
- ★ **The last administrator can no longer lock everybody out**: the web interface (and the API) refuses to change the role of, disable or delete the last enabled administrator. In Settings → Users & tokens the buttons are greyed out with the reason; create or promote another administrator first. A disabled administrator does not count.

## 0.4.131 — 2026-10-20

### Added
- ★ **Synology plugin 1.0.2** (Plugin store): tested against a real DSM 7.2.2. DSM's container list has no ports or networks, so the plugin now reads them per container: the published ports (also for a stopped container) and the address of a container on a macvlan network.
- **A README section and website page for Synology ext4 volumes**: how to recognise the aufs problem, and the two fixes (a btrfs volume, or the root work-around with `DAC_OVERRIDE`) with the full project file and what the work-around costs.

## 0.4.128 — 2026-10-20

### Fixed
- ★ **The Synology problem is explained and named**: Container Manager uses the *aufs* storage driver on ext4 volumes, and aufs drops the file capability the image puts on nmap, so scans fail with `dnet: Failed to open device`. Reproduced on a virtual DSM; btrfs volumes are not affected. The Scans page diagnosis now says "aufs" and shows the container's file system; the README gives the check (`docker info | grep 'Storage Driver'`) and the tested work-around (`user: "0:0"` plus `DAC_OVERRIDE`), or a btrfs volume.

## 0.4.126 — 2026-10-20

### Changed
- The Synology notes are now honest about what was tested: a current Synology DSM 7.2.2 with Container Manager 24.0.2 (a virtual DSM in the lab) runs Netlens with the standard compose file, and scans work. The lost-capability work-around stays documented for set-ups where `getcap` shows the capability missing, and the Troubleshooting entry says what to send when it is present and scans still fail.

## 0.4.125 — 2026-10-20

### Fixed
- ★ **Corrected the work-around for a lost nmap capability**: running the container as root with `user: "0:0"` alone stops Netlens at start-up (a root without `DAC_OVERRIDE` cannot write its data folder). The README, the compose file and the Scans page now say to add `DAC_OVERRIDE` as well, and spell out what the work-around costs (the whole app, not only nmap, then holds `NET_ADMIN`) and that it is only for a container whose nmap really lost its capability (`docker exec netlens getcap /usr/bin/nmap` prints nothing). Tested on a container with the capability removed.

## 0.4.124 — 2026-10-20

### Added
- ★ **Netlens now says why raw scans fail**: when nmap reports `dnet: Failed to open device ...` the Scans page and the container log show what Netlens found inside the container (capabilities, user, no-new-privileges, nmap's file capability, interfaces) and the most likely cause. On NAS systems that drop file capabilities (seen on a Synology) the fix is `user: "0:0"` on the netlens service; the README and the compose file explain it.

## 0.4.122 — 2026-10-20

### Fixed
- Links to the Codeshrimp website now use the public address www.codeshrimp.com.

## 0.4.121 — 2026-10-20

### Changed
- **Settings → Database uses the whole screen**: summary tiles on top, the retention and the maintenance tools side by side, and the tables in a scrolling list, instead of one narrow column.

## 0.4.120 — 2026-10-20

### Changed
- ★ **Resizable columns in every table**: drag the edge of any column heading in any table (devices, services, reports, statistics, settings ...); double-click it to go back to automatic widths. Widths are remembered per table in your browser. A table can opt out with the class `no-resize`.

## 0.4.119 — 2026-10-20

### Added
- ★ **System log** (Scans & events → System log, administrators): the application's own log, kept across restarts in a small rotating file (`/data/logs/netlens.log`), with an Errors / Warnings / Everything filter, search and download. The same lines now also reach the container log, which showed almost nothing of the application before. `NETLENS_LOG_LEVEL` sets how much is written.
- ★ **Resizable columns**: drag the edge of a column heading (double-click to reset); the widths are remembered per table in the browser. It starts on the scan list, and text such as a scan error now wraps in the space available instead of being cut off after 40 characters.

## 0.4.118 — 2026-10-20

### Fixed
- ★ **A missing NET_RAW / NET_ADMIN is now explained properly**: the scan error starts with "A container setting is missing" and says where to add the settings (compose file, Portainer tabs, Synology Project). The Scans page shows a notice with the steps instead of an error cut off after 40 characters (click an error to read all of it), and the container log gets one plain ERROR line.

### Changed
- The Portainer and Synology instructions are rewritten: where `cap_add` goes in the file (annotated example, common mistakes), the Portainer *Capabilities* tab, why a Synology needs a Project, and how to check that it worked.

### Added
- ★ **A remote site tells its own people when the central Netlens is unreachable**: after 10 minutes of failed reports it raises an alert on its own channels with the reason, and another when the link is back. A short break says nothing.
- ★ **Which devices of a remote site raise offline alerts**: per site, choose automatic (always-on devices when the site marks any), only always-on, all, or none, and *Mute* single devices.
- ★ **Retention per remote site**: keep the history of a site for 30 days to 2 years, or follow the general retention. The weekly upkeep (and Settings → Database → Remove old data) removes the older graph points and alerts of that site.

## 0.4.117 — 2026-10-20

### Added
- ★ **Settings → Database**: sizes of both database files, every table with rows and size, and the tools to keep them healthy: remove old data (with a preview), clean up leftovers, optimize, rebuild indexes, compact (VACUUM) and check integrity. A weekly run does the safe parts by itself.
- ★ **Retention for events and scans**: they used to grow for ever. Events are now kept 2 years and finished scans 1 year by default; presence checks, service check results and the audit log are configurable too. 0 keeps events and scans for ever.
- ★ **Removing a remote site cleans up after it**: its devices and checks, their graph history, its snooze, the configuration and commands waiting for it, its place in maintenance windows and customer logins (a customer login that only saw that site is disabled). You choose whether its alerts stay in the history, and Netlens says what was removed.
- ★ **Customer logins for remote sites**: a viewer can be limited to chosen remote sites and then sees only those, with their graphs, checks, events and monthly availability.
- ★ **Maintenance windows can cover remote sites**, including a site that stops reporting.
- ★ **A central Netlens with a self-signed certificate**: trust its certificate by fingerprint (Settings → Report to a central Netlens). Exactly that certificate is accepted; a replaced one is refused with a clear message.
- **Managed checks and monitors can be edited** (address, port, interval, alerts) without losing the saved login.
- Two indexes on the events table; removing a device or site no longer reads every event.

## 0.4.116 — 2026-10-20

### Added
- ★ **Monthly availability per remote site**: on the page of a site, choose a month and see the availability per device and per check, the outages and the time down, for all devices or only the always-on ones, with a CSV download. Time in which the site did not report is listed separately.
- **More of a site on its page**: the last scan, the backups, the monitored devices, and per device the address, system, open ports and first-seen date.

### Changed
- ★ **Remote sites alert only for always-on devices**: when a site marks any device as always-on, only those raise "went offline" and "back online" alerts. Sites that mark none behave as before.

## 0.4.115 — 2026-10-20

### Added
- ★ **Scan now at a remote site**: the page of a remote site has a *Scan now* button. The remote Netlens starts a quick scan with its next report (it must have *Accept configuration and commands from the central Netlens* ticked).
- ★ **Snooze a whole remote site**: for planned work at a location, *Snooze* on the site page holds back every alert of that site (devices, checks, health readings, silence) for a while. The events are still recorded and marked as snoozed.
- **Recent events on the site page**: the alerts raised about that site, newest first.
- **Clock check**: when the clock of a remote machine is more than two minutes off from the central Netlens, both sides say so (the measurements of a site with a wrong clock are shifted or not kept).

### Changed
- The tick box on the remote Netlens now reads *Accept configuration and commands from the central Netlens*.

## 0.4.114 — 2026-10-19

### Added
- **What changed can show only the always-on devices**: a tick box "Only always-on devices" leaves out what happened to phones, tablets and other devices that are not marked always-on. Changes made by people stay. The choice is remembered in your browser.

## 0.4.113 — 2026-10-19

### Changed
- **Plugins are lines in the services table**: no separate box any more; the plugins follow the service checks in the same table and the same type, under a thin "Plugins" divider.

## 0.4.112 — 2026-10-19

### Added
- ★ **Plugins are monitored like services**: the Services page has a Plugins section with a heartbeat bar of every switched-on plugin's latest syncs, the share of good syncs in 24 hours, the sync time and the last sync, and a click opens the same graph (sync success and sync time over time). It tells a slow or unreachable system from a broken plugin. Every sync is recorded (kept 30 days) and Ask your network can answer "how are the plugins doing?".

### Fixed
- **A timeout is no longer blamed on the Netlens upgrade**: the warning "Some plugins may not work with this Netlens" skipped no failure before; now an error about the network (timed out, cannot reach, connection refused, name not found ...) is not taken as a sign that the upgrade broke the plugin.

## 0.4.111 — 2026-10-19

### Changed
- **Click a line to see its graph**: on Services, clicking a line opens the same history graph as the Graph button; on Uptime, clicking a device opens its response-time and availability history under the row. Clicks on the device link, the heartbeat bar or the response line, and the buttons keep their own meaning.
- **A narrower Services table**: the Target column is gone (the target shows when you point at the name), the device name has the domain name removed when one is set in the settings, and the buttons are shorter ("Run" instead of "Run now").

## 0.4.110 — 2026-10-19

### Fixed
- **A repeated service alert in the AI report** no longer cuts the service name at its own bracket.

## 0.4.109 — 2026-10-19

### Changed
- **The AI report names services and merges repeats**: an alert about a service or a site (which has no device behind it) now carries the name the alert gave, and the same alert coming again and again is one finding that counts the times and gives the first and last time, instead of a nameless line per time.
- **Documentation**: new Insights section in the README (always-on filtering, memory predictions, weekly report summary switches); the website has pages for Insights, language model providers, the AI report, the AI assistant and free OpenRouter models.

## 0.4.108 — 2026-10-19

### Changed
- ★ **The AI report counts the devices marked always-on**: incidents, devices that keep failing and "same time every day" patterns about phones, tablets and other devices that come and go are left out, like in Ask and the Insights incidents. The tick box "Include phones, tablets and other devices that come and go" on the report (shared with the one on Insights) brings them back.

## 0.4.107 — 2026-10-19

### Fixed
- **Only devices marked always-on count in Ask and the incidents**: a VM, server or printer that is not marked always-on was still treated as important because of its type. When at least one device is marked always-on, the marking alone decides; the type is only a stand-in while nothing is marked.

## 0.4.106 — 2026-10-19

### Changed
- **The Insights settings are part of "Ask your network"**: the separate Settings card is gone; the model note, the "Check the model" button and the language-model switch sit at the bottom of the question card.
- **Insights is no longer listed under Automation** as well as Analysis.

## 0.4.105 — 2026-10-19

### Changed
- ★ **Memory is only called a leak when the history says so**: the prediction now looks at up to 60 days of daily medians. A date ("would run out in ...") is given only for a steady, straight rise over at least a week. Memory that levels off (a cache that fills), is given back now and then (restarts, clean-ups) or moves irregularly gets no date and is mentioned only when it is nearly full.
- ★ **Insights incidents and unusual readings count the devices that should always be on**: alerts of phones, tablets and other devices that come and go no longer make a week look worse than it was, and the incident text only mentions the devices that count. A tick box on the incidents (and on the question) brings them back. The weekly summary uses the same rule.
- ★ **The weekly report has its own AI switches** (Reports → Weekly report): start with a short summary, and let the language model word it. They no longer depend on the Insights page, which keeps only its own switch for answers and incident summaries.
- **The Insights settings are at the top** of the page instead of folded away at the bottom.

## 0.4.104 — 2026-10-19

### Changed
- ★ **Ask your network cares about what matters**: by default the answers are about the devices that should always be on (servers, routers, switches, NAS, cameras, printers, anything marked always-on), the services and the network problems. A phone or tablet going offline no longer shows up. A box under the question, "Include phones, tablets and other devices that come and go", brings them back; asking about a device by name always works.
- ★ **The AI report is part of Reports**: it is now a tab next to the monthly and weekly reports (Analysis → Reports → AI report), no longer a card on the Insights page.
- **Insights is under Analysis**, no longer under Automation.
- **Model name above the Load models button**, and the locked name box has the right dark colour in dark mode.

## 0.4.103 — 2026-10-19

### Changed
- **Model choice is a dropdown**: after Load models, the model is picked from a list with "Custom ..." as the last choice. The name box below it only takes typing when Custom is chosen; otherwise it is greyed out and shows the selected model. For your own server the choice starts on Custom with the box open.

## 0.4.101 — 2026-10-19

### Fixed
- **Anonymised names come back with capable models**: a model that tidies a placeholder such as `<device13>` into `device13` no longer leaves it in the answer; the real name is put back.

### Added
- ★ **Choose your AI provider**: Settings → AI → Language model has a Provider box with Anthropic (Claude), OpenAI (ChatGPT), Google (Gemini), Mistral (Le Chat), xAI (Grok), DeepSeek, Groq, OpenRouter, your own server and any OpenAI-compatible address. Picking one fills in the address, and **Load models** shows the models your key can use. Anthropic is called through its own API. A saved key is forgotten when you switch to another provider, so it is never sent to the wrong company.
- A refusal from a provider now says why when it explains itself (for example an unsupported setting), instead of only "HTTP 400".

## 0.4.99 — 2026-10-19

### Changed
- **AI report is clearer**: findings now name the devices and the time, minor one-off outages of phones and the like rank last, a device that keeps failing is told once ("12 times in 24 hours") instead of as many single events, and the same switch behind several incidents is one finding. A finding about a service no longer starts with an empty name. The first request to a language model that must still be loaded into memory may take a few minutes; the report now waits for it.

## 0.4.98 — 2026-10-19

### Added
- ★ **AI report**: Insights → AI report tells what happened in the last 6 hours, 24 hours, 3 days or 7 days and how it connects. Netlens finds the connections itself (alerts of one incident, devices behind the same switch, changes made shortly before a problem, problems that keep coming back at the same hour) and numbers them as findings; a language model, when set up, writes the report from them. Every sentence must name its findings, and anything it makes up (an unknown finding, a number that is not in the findings) is removed, so even a small model cannot invent a cause. Without a model you get the findings themselves.

## 0.4.97 — 2026-10-19

### Changed
- **One AI page**: the language model and the AI assistant are now two parts of a single page, Settings → AI, with a short menu entry. The old address of the assistant page still works.

### Fixed
- **A refused API key is no longer a "poor" model**: when OpenRouter refuses the key, asks for credit, or no exam gets any answer, the model is reported as "could not be tested" and nothing is saved. A refused key now says so ("refused the API key") instead of only "HTTP 401".

## 0.4.96 — 2026-10-19

### Changed
- **Clearer AI settings**: the settings menu has a new group **AI** with two cards. **Language model** (before: Digital engineer) is the model Netlens itself uses for the digital engineer and for Insights, including the free OpenRouter models. **AI assistant** is for an outside assistant that calls Netlens to help you set it up or find a problem. The two cards say how they differ.

## 0.4.95 — 2026-10-19

### Fixed
- **The model exams were too harsh on free models**: a model that first answers in plain text now gets the same one-time reminder to answer in JSON that the real questions give, and a busy OpenRouter (HTTP 429, free allowance used up) is waited for. If it is still busy, the model is reported as "could not be tested" and nothing is saved, instead of being marked poor.

## 0.4.94 — 2026-10-19

### Added
- ★ **AI assistant**: Settings → AI assistant makes a token and ready-made instructions for an AI assistant (Claude, ChatGPT, a local model) that helps you set up Netlens, change it later or find out why something is red. It reads a guide written for language models (`/api/assistant/guide`) and works through the API, one change at a time, with every change in the audit log. A read-only token can look; a token that may change settings still cannot reach users, passwords, backups, sharing, single sign-on, remote sessions, remediation rules or updates.
- ★ **Free language models on OpenRouter**: Settings → Digital engineer lists the free models OpenRouter offers right now, lets you test each with Netlens's own exams and use one with a click. Free models change often, so the list is read live and Netlens checks once a day that your model is still offered and free; if not, you get a warning, a dashboard item and an event.
- A language model that answers HTTP 404 or 429 now says what that means (the model has gone, or today's free allowance is used up).

## 0.4.93 — 2026-10-19

### Added
- **Choose how many failed syncs make a plugin a problem**: Settings → Plugin manager has a field for it (1 to 48, default 3).

## 0.4.92 — 2026-10-19

### Changed
- ★ **A plugin must fail a few times in a row before it counts as a problem**: a timeout or a busy server (a reverse proxy that now and then does not answer) no longer turns the dashboard and the problem count red after one missed sync. A plugin is flagged after 3 failed syncs in a row, about 45 minutes with the usual scan interval, and the plugin card says "Failure 1 of 3" while it is retrying. A refused login is still reported at once. The number can be changed with the setting `plugins.failure_grace` (1 to 48).

## 0.4.91 — 2026-10-19

### Added
- ★ **Share links you can shape**: choose exactly what a link shows (counts, services, availability history, map, devices, recent events), which device columns and services are included, whether names are hidden, and add a message and a title for your visitors. A link can have a PIN, start at a chosen moment, use a light or dark theme, and show only the devices of some groups; your own brand name and colour can replace Netlens.
- **Edit a share link** without changing its address, and **New address** to replace a link that got into the wrong hands (the old address stops working at once).
- A share page marks devices in planned maintenance, and the events list shows only that a device went offline or came back, never addresses or details.

## 0.4.90 — 2026-10-19

### Changed
- **Editions**: the Supporter key is now a yearly key (30 days of grace, like the business editions) and takes in 3 remote sites. Single sign-on, log forwarding, operators and customer views, and on-call schedules are part of the Small business and Enterprise editions (and the free trial); Supporter keeps auto-remediation, Insights, the digital engineer, escalation and the vulnerability scanners. Escalation and on-call schedules are separate switches now.

## 0.4.89 — 2026-10-19

### Changed
- **Operators and customer views are business features**: creating or changing an operator, or limiting a viewer to some groups, needs a licence or the free trial (Settings → Licence), like escalation and single sign-on. Administrators and viewers stay free. Nothing is removed when there is no licence: an operator acts as a viewer until a licence is applied, and a limited viewer keeps the limit.

## 0.4.88 — 2026-10-19

### Added
- **Benchmark and API reference tools** in the repository: `tools/bench.py` measures Netlens on a made-up network of any size, `tools/api_reference.py` writes the API reference from the application's own description.

## 0.4.87 — 2026-10-19

### Changed
- ★ **Much quicker on big networks**: the statistics, dashboard, uptime page, summary, Prometheus numbers and the weekly and monthly reports no longer add up every check ever made. An hourly roll-up of the uptime history gives the same numbers from thousands of rows instead of millions (it is built in the background after this update; until then everything works the slower way). With 2,000 devices and a week of history the dashboard opens in 0.8 s instead of 3.2 s and the statistics in 1.2 s instead of 3.1 s; with 10,000 devices the hierarchy page opens in 0.2 s instead of 11 s and saving a scan takes 6 s instead of 17 s. Measured numbers for 500, 2,000 and 10,000 devices are in the README.
- A page that is a little out of date (under two minutes) is shown at once while a fresh one is made in the background.
- Saving a scan commits every 250 devices instead of for every device (about four times faster on a big network; progress is still saved in steps).
- The flapping count looks at the changes inside the last 24 hours (a change between the last check before that window and the first one in it is no longer counted).

## 0.4.86 — 2026-10-19

### Added
- ★ **On-call schedules** (Settings → On-call schedule): who is notified, by day and hour. People with their channels, shifts (days, hours, taking turns weekly or daily), overrides for swaps and holidays, and a fallback. Choose **Whoever is on call** in a level of the escalation policy and the alert goes to the people on call at that moment. The card shows who is on call now and the coming week. When nobody is on call, the alert stays open and is retried.
- ★ **Quiet hours per person**: a channel can have its own quiet hours (channel form → *Own quiet hours*) that replace the general ones for that channel only.

## 0.4.85 — 2026-10-19

### Added
- ★ **Operator role**: a user who looks and acts. An operator can scan, test, send Wake-on-LAN, acknowledge and snooze alerts, plan maintenance, approve or decline fixes and edit a device's name, type and group, but cannot reach settings, users, credentials, backups, plugins, the terminal or remote access, and cannot delete anything. Single sign-on can use it as the default role.
- ★ **Customer view**: a viewer can be limited to some groups (Settings → Users & tokens → *Limit to groups*). That user sees only the devices of those groups, their pages, history and events, and the Uptime page; the interface offers nothing else and the server refuses everything else. API tokens of such a user keep the limit.

### Changed
- The Users page lists the three roles, shows which viewers are limited, and the Scan button is also shown to operators. Existing users and tokens are kept (the users table is rebuilt once at the update).

## 0.4.84 — 2026-10-19

### Added
- ★ **SNMP traps and syslog from devices**: Settings → Device messages. A switch that loses a link, a UPS that goes on battery or a router that logs an error now shows up as an event on that device, in your alert channels and in log forwarding. SNMP v1 and v2c traps and informs (UDP 1162, community names you list) and RFC 3164 / 5424 syslog (UDP 1514, from known devices, at or above the severity you choose). Both are off until you switch them on; a sender is limited to 60 events a minute. New events: link down, link up, device restarted, SNMP trap, device log.
- ★ **Fan and power-supply health**: the SNMP health monitor has a *Hardware sensors* group (the standard sensor table of switches, routers, NAS boxes and servers): temperatures, fan speeds, voltages, and a *Fan or power supply problem* alert when a fan stops or a sensor reports a failure. Also in Prometheus (`netlens_host_fan_speed_rpm`, `netlens_host_voltage_volts`, `netlens_host_sensor_fault`).
- **Vendor-specific readings**: a *Vendor-specific readings* group adds APC UPS (battery, runtime, temperature, load) and MikroTik (voltage, board and CPU temperature, fans). Written from the vendor MIB documentation and tested against simulated devices only.
- **UPS load** as a reading with its own limit (warning 80 %, critical 95 %).

## 0.4.83 — 2026-10-19

### Added
- **Read-only API tokens**: when you create an API token (Settings → Users & tokens) you can make it read-only. It then only reads, even when its user is an administrator, which is what Prometheus, Grafana and dashboards need.
- **Per-interface metrics in Prometheus**: `netlens_host_interface_up`, `netlens_host_interface_utilization_ratio` and `netlens_host_interface_errors_per_second` next to the traffic numbers, per interface, for devices with an SNMP or SSH health monitor.
- **Grafana dashboard**: the ready-made dashboard gets sections for interface traffic, utilisation, errors and link state, and for the processor, memory, disk and temperature of monitored devices, with a Device drop-down.
- **API reference**: every endpoint listed and grouped in the documentation, generated from the application's own API description.

## 0.4.82 — 2026-10-19

### Added
- **Explanations on the Analysis page**: every card now has a small **?** next to its title. Hover it, tap it or focus it with the keyboard to see in a sentence or two what the card shows, for example what "Most active devices" or "Flapping" means.

## 0.4.81 — 2026-10-18

### Fixed
- **Preview of a report in the installed app**: the network documentation preview opened in a new window, and an installed app (PWA) has no browser buttons to leave it again. The preview now opens full screen inside Netlens with its own **Back**, **Print** and **Download** buttons; the phone's back gesture and the Esc key close it too. The same goes for the documentation of a remote site.

## 0.4.80 — 2026-10-18

### Fixed
- **Greenbone plugin 1.0.1**: a Greenbone user only sees the scan tasks that are shared with it, so the Netlens user must be added under *Observers* in every task. The plugin now says so when its user sees no tasks, and the README and the plugin's set-up text explain it.

## 0.4.79 — 2026-10-18

### Added
- **Greenbone (OpenVAS) plugin in the Plugin store**: shows what a Greenbone scanner found on your devices (needs Netlens 0.4.73 or newer). Tested against a real Greenbone Community 22.7, so it is listed as *verified*.

## 0.4.78 — 2026-10-18

### Added
- **Vulnerability scanner plugins in the Plugin store**: **Tenable Nessus** and **Rapid7 InsightVM** show what the scanner found on your devices (needs Netlens 0.4.73 or newer). Both were written from the vendors' API documentation and tested against a simulated server only, so they are listed as *reviewed*, not *verified*: use *Run diagnostic* on the plugin's page and send the report if a real installation answers differently.

## 0.4.77 — 2026-10-18

### Added
- ★ **Vulnerabilities of remote sites**: a remote Netlens with a vulnerability scanner now tells the central Netlens the counts, the devices at risk and its few critical findings (no addresses). The central shows them on the site card and the site page, adds the number of critical vulnerabilities to the totals of a customer, puts them under Needs attention on the dashboard, announces a site whose critical count grows as a *New vulnerability* event, and includes them in the documentation of that site.

## 0.4.76 — 2026-10-18

### Added
- ★ **Customers for remote sites**: give a remote site a customer (when you add it, or with *Set customer* on its page). The Remote sites page then groups the sites by customer, with one line of totals per customer (sites, devices online, checks down, health problems), and alerts name the customer ("Bakery Janssens / Shop: printer went offline"). Useful when you look after the networks of several customers.
- **Documentation per remote site**: the page of a remote site has a *Documentation* button that makes the network documentation of that site (devices, monitored services and open points) from what the site reports, under its customer's name and with your logo.

## 0.4.75 — 2026-10-18

### Added
- ★ **Network documentation** (Analysis → Reports → Network documentation): one page about the network, ready to hand to a customer or to keep for yourself. It lists the devices (address, MAC, vendor, type, system, group, notes), the subnets, the monitored services, the certificates, the backups, the vulnerabilities and the open points of the network health checks, with your own logo, colour, company, contact and footer. Preview it, or download it as one file without scripts or external files; it prints to PDF from the browser. Made from what Netlens knows at that moment, and left out for devices marked *Leave out of reports*.

## 0.4.74 — 2026-10-18

### Added
- **Known exploited vulnerabilities**: when a vulnerability scanner is connected, Netlens fetches the public CISA list of vulnerabilities that attackers are using, once a day, and marks every finding that has one of those CVE numbers as *known to be exploited*. Nothing about your network is sent, and nothing is fetched while no scanner is connected.

## 0.4.73 — 2026-10-18

### Added
- ★ **Vulnerabilities** (Analysis → Vulnerabilities): a new kind of plugin for vulnerability scanners. A scanner plugin reports what it found per host; Netlens matches each finding to a device and shows them worst first, with the CVE numbers, a score, whether the vulnerability is known to be exploited, and what to do about it. A device page shows its own findings, the dashboard has a Vulnerabilities card, critical findings (and high ones that are known to be exploited) appear under Needs attention, and a **New vulnerability** event can be sent through your alert channels, grouped per device so a fresh scan does not flood anyone. What was already there when a scanner is first connected is not announced. The scanner plugins follow.

## 0.4.72 — 2026-10-18

### Added
- ★ **Alerts from Network health**: every half hour Netlens repeats the IPv4 and IPv6 checks and raises an event when a problem is still there on the next round (one blip of the internet is not an alert): *Network problem* (no gateway, the gateway does not answer, two devices with one address, an unapproved DHCP server, a range nearly full, the internet or names not working, ...), *Network warning* (a second router, a range filling up, devices in another subnet, ...) and *Network problem resolved* when it is gone. Each is announced once, and a warning that becomes a problem is announced again. Choose them under Settings → Alert channels → Tell me when (the problem is on by default); problems also show under Needs attention on the dashboard and go to log forwarding with the right severity.

## 0.4.71 — 2026-10-18

### Added
- ★ **Network health** (Analysis → Network health) has an **IPv4** tab next to the IPv6 one (which moved here from Network). It says in plain words whether the network is in good order: whether this computer has a proper address, the gateway and whether it answers, whether the internet and name lookups work, how full each scanned range is, two devices using the same address, devices that gave themselves a 169.254 address, addresses that keep moving between devices, and the DHCP servers (an unapproved one, two at once, or one that offers another gateway). Problems come first in both tabs.

### Changed
- The IPv6 health page is now the IPv6 tab of Network health; the old address still works.

## 0.4.70 — 2026-10-18

### Added
- ★ **IPv6 health** (Analysis → Network health): says in plain words whether IPv6 on your network works as it should. It shows where the addresses come from (your provider's range handed out by the router), the subnets in use, which devices announce themselves as routers, whether the internet and name lookups work over IPv6, and, with IPv6 discovery on, which devices have an address, which are in another subnet than this computer and which do not answer a ping. Every finding explains what it means, and a short guide explains the words (prefix, router advertisement, link-local, unique-local, global).

## 0.4.69 — 2026-10-18

### Added
- **Search** finds the devices of your remote sites too (by name, address, MAC or vendor) and opens the page of that site.

### Changed
- **Remote site page**: "Managed from here" is folded away until something is set up in it, so the devices come first, and the health tile says "1 warning" instead of "0 critical".

### Fixed
- A service check at a remote site that is already **down when it first appears** (for example one you just set up from the central Netlens) now raises the "service down" alert. Before, only a change from up to down did.

## 0.4.68 — 2026-10-18

### Fixed
- **Search** finds the places added or moved lately: n8n, OpenClaw, webhook and "forward events" lead to the alert channels, and IPv6, single sign-on, escalation, log forwarding, Digital engineer, Licence, the setup guide and the Settings page are searchable. Every installed plugin is found by its name and opens its own settings.

## 0.4.67 — 2026-10-18

### Added
- **OpenClaw**: a webhook channel can send in OpenClaw's own shapes: *wake* (`/hooks/wake`: `{text, mode, agentId}`) or *agent turn* (`/hooks/agent`: `{message, name, agentId, deliver}`), with the hook token as bearer token and a choice of agent.

## 0.4.66 — 2026-10-18

### Added
- ★ **Forward events to n8n, OpenClaw and other automation tools**: a webhook channel can now send **one message per event** (`{source, event: {kind, severity, label, name, ip, detail, group, ...}}`), which starts one run per event, and every webhook message carries a `severity`, a readable `label` and a `text`. Besides a bearer token it accepts an **extra header** (for example `X-API-Key: ...`). A failed delivery is retried from the event that failed, so nothing is lost or repeated.
- **Only when**: every notification channel can be narrowed to a **minimum severity** (everything, warnings and up, serious only) and to **chosen groups and devices**, on top of the events it asked for.

## 0.4.65 — 2026-10-18

### Changed
- **Map toolbar**: search, type, status, group and layout stay in the bar; links, labels, colours and containers are in a **View** menu and Add link, Delete link and Reset layout in an **Edit** menu.
- **Reports** has two tabs (monthly availability first, weekly report second), and a long month shows the ten worst devices and services with "Show all".
- Services, Health and Remote sites explain what to do when empty, with a button, like Backups and Smart home. Remote access no longer opens the long RDP/VNC setup guide by itself.

### Fixed
- The Infrastructure card showed the Sites line in red because a site was down, next to a certificate that still had weeks left. Sites and the next certificate are now separate lines, each coloured for its own reason.

## 0.4.64 — 2026-10-17

### Changed
- **What changed** shows a device that kept going up and down as one line a day ("went offline 3 times, back online now") and says in words what happened when no detail was kept.
- Forms and plugin pages put their buttons side by side (Save, Test, Sync now) instead of one wide bar each; the weekly report text scrolls instead of filling the page.

## 0.4.63 — 2026-10-17

### Changed
- ★ **A new look, the same everywhere**: every page now starts the same way (a title, one line of help, the page's actions on the right), cards, summary tiles, tables and empty states share one style, and event names read the same on every page ("Went offline", not `device_offline`).
- ★ **A new dashboard first view**: one line says whether everything is running normally or what needs attention, with the numbers that matter beside it (devices online, services up, uptime, last scan). The default cards are fewer and sharper: the four key figures, what needs attention, health, a new **Infrastructure** card (containers, virtual machines, sites and certificates, plugins, backups), disks running out, recent events and the map. The cards that left the default are still there under Customize. Dashboards you arranged yourself stay as they are.
- **New menus**: Network (Map, Devices, Hierarchy, DNS, Remote sites, Remote access), Monitoring (Uptime, Health, Services, Backups, Smart home), Analysis (Statistics, Reports, What changed, Speed tests, Scans & events) and Automation (Insights, Remediation, administrators only). Settings is grouped as Scanning, Display, Access, Notifications, Integrations, Connections, Data and System.
- **DNS has its own page** (Network → DNS): what Netlens would register, with what is already right out of the way and the settings folded away. The old address still works.
- **Statistics in tabs** (Overview, Network, Services & infrastructure, Scans & events, System) instead of one page with forty cards; rows of zeros are left out.
- **Scans & events** shows events first, with the device name and readable event names, and the scans on a second tab. **Speed tests** has tabs for the internet, your own network and all results. **Insights** puts the question box first and folds the long incident list and the settings. **Health** folds the warning limits. **Uptime** shows one compact line per device, least reliable first (response-time graphs are a tick box). **Services** keeps Run now and Graph on each row and moves Edit, Pause and Delete into a menu. A device page folds "Why this type?" while the answer is clear.

## 0.4.62 — 2026-10-17

### Fixed
- **Insights and the version question**: when "check for updates" is switched off (or has not worked for days), the answer no longer says "no update available" from an old cached answer; it says that checking is off or out of date and when the last answer was.

## 0.4.59 — 2026-10-17

### Added
- **Many more questions** on the Insights page, answered by the built-in logic and by a language model alike: devices by kind, manufacturer, operating system, group, tag or open port ("which devices have SSH open?", "which Apple devices are offline?", "how many devices per type?"), virtual machines and containers ("which are stopped?"), backups, certificates, speed tests, remote sites, smart home (batteries, unavailable devices), security (rogue DHCP, failed logins, unexpected ports), who changed which settings, what a device is connected to and what depends on it, Wi-Fi signal, maintenance windows, versions and updates, IPv6.
- **Choose how a question is answered**: Automatic, Built-in logic or Language model (a switch on the Ask card). The instructions to the language model were extended with an example for each kind of question.

## 0.4.58 — 2026-10-17

### Added
- **Current readings as a question**: "which machines are low on RAM?", the busiest processors, the fullest disks, temperatures and UPS batteries are answered from the newest readings of the monitored hosts. The language model had no tool for them and used the forecast of disks instead; the instructions now keep the two apart and the model check has an exam for it.

## 0.4.56 — 2026-10-17

### Added
- **Check the model** (Monitoring → Insights): six small exams with made-up data show whether the connected language model follows the instructions, copies names and numbers exactly, leaves nothing out of a list and does not invent what the data cannot tell. "What a trustworthy model needs" is listed in Settings → Digital engineer.
- **More ready-made questions**: service checks, and a kind of device ("how reliable are the printers?").

### Changed
- The instructions to the language model are stricter and have examples; a model that does not answer in the expected format, or answers without looking at the data, is told once before the plain answer takes over.

## 0.4.55 — 2026-10-17

### Fixed
- **Insights without a language model**: a question the ready-made answers do not cover (for example "which device has the highest average response time?") got the status overview as its answer. Response times are now a ready-made question, and an unrecognised question says that it cannot be answered without a model instead of answering something else.

## 0.4.54 — 2026-10-17

### Added
- ★ **Insights** (Monitoring → Insights): ask your network a question ("what happened last night?", "which devices were least available?"), see grouped alerts as one **incident** with a probable cause, see readings that are **unusual** for that device at that time of day (processor, memory, response times; raises an "Unusual reading" alert after two rounds), **predictions** (disks and memory use that keeps rising), and a **suggestion for devices without a type** with the reasons. Everything works from Netlens's own numbers; a language model (Settings → Digital engineer) is optional and only words the answers, chooses among read-only questions, or adds its opinion on a device. Names and addresses are anonymised before they reach it.
- **Weekly report summary**: the weekly report can start with two or three sentences about the week (switch off on the Insights page).
- **Look back** (Monitoring → Remediation, on every run): did the automatic fix work, and does the same problem keep coming back?

## 0.4.50 — 2026-10-17

### Added
- ★ **Restart a virtual machine** (Monitoring → Remediation, "Do this"): a rule can hard-reset, restart, shut down or start the virtual machine a device is, through the hypervisor plugin that reported it (Proxmox first; the plugin's token needs the VM.PowerMgmt privilege). Meant for a guest that freezes while it still answers ping: a service check notices, the rule resets it, with the usual cooldown and daily limit. Works with the Proxmox, Docker, Portainer, Incus, vSphere and Hyper-V plugins (update them in the Plugin store).

### Fixed
- **Proxmox and the ASUS router after the move to plugins**: an installation that had used the built-in version of Proxmox (a single address and login) lost those settings when the plugin was installed again. They are kept now. If you were affected, enter the server again under Settings → Integrations → Proxmox VE.

## 0.4.49 — 2026-10-17

### Fixed
- **Digital engineer with a thinking model**: a language model that reasons before it answers could run out of room and return nothing; it now gets far more room, and an empty answer is reported clearly.

## 0.4.48 — 2026-10-17

### Added
- ★ **Auto-remediation** (Monitoring → Remediation): rules say "when this event happens, do that": wake a device, call a web address (a Home Assistant webhook, n8n ...) or run one command over the device's SSH monitor login. Each rule can only suggest, ask for approval (it shows as an alert and on the dashboard), act at once, or leave the decision to the digital engineer. A cooldown, a daily and an hourly limit, maintenance windows and snoozes, and a pause switch keep it safe; every run, its result and whether the problem went away afterwards are listed.
- ★ **Digital engineer** (Settings → Digital engineer): connect any OpenAI-compatible language model (a local one or a hosted one). It reads an incident and recommends which of your rules would fix it; it never runs anything itself and never sees the commands. What is sent can be made anonymous.
- ★ **Single sign-on** (Settings → Single sign-on): sign in with your company account through any OpenID Connect provider (Entra ID, Keycloak, Authentik, Google, Okta ...). People are recognised by the provider's own id, never by their name; the first sign-in creates the Netlens user and the role follows the provider's groups at every sign-in.
- ★ **Log forwarding** (Settings → Log forwarding): events and the audit log are sent to a syslog server or SIEM (Graylog, Splunk, Wazuh, Elastic ...) as RFC 5424 over UDP or TCP; Netlens remembers what it has sent, so a server that is down only delays delivery.
- ★ **Escalation** (Settings → Escalation): an alert that nobody acknowledges is sent on to other channels after the time you set, in up to four levels, until somebody acknowledges it or the problem has gone.

## 0.4.47 — 2026-10-17

### Fixed
- Proxmox and the ASUS router are reinstalled from the Plugin store right after the upgrade even when Netlens still holds an older copy of the plugin list (it asks for a fresh one when the plugin is not in it).

## 0.4.46 — 2026-10-17

### Added
- ★ **Tiers view of the map**: a new choice next to the other layouts. The network is read top to bottom in bands (gateway, switches and access points, servers and storage, virtual machines and containers, everything else); every device is a tile with its status, and pointing at one lights up what it hangs on and what hangs on it, with the links drawn only for that device. Bands can be folded, and the view has the same search and online/offline filter.
- **IPv6 addresses can be hidden**: Settings → IPv6 has a switch for showing them; when on they also appear in the device list and the device search finds them.

## 0.4.44 — 2026-10-17

### Added
- ★ **Home Assistant plugin and a new plugin type, "inventory"**: the plugin reads the device registry of Home Assistant (manufacturer, model, area, firmware, protocol, battery, available or not, and for Zigbee the device it is paired through). Devices with a MAC address are matched to the devices Netlens found, and get a Smart home card on their page; all devices are listed on the new Smart home page (Monitoring menu), with events for devices that become unavailable and for low batteries, and a line in the dashboard's attention list.

### Changed
- ★ **Proxmox VE and the ASUS router are ordinary plugins now**: nothing is built into Netlens any more. If you used one of them, Netlens installs it from the Plugin store by itself after the upgrade, with your settings, and keeps it switched on (an event tells you; when the store cannot be reached it tries again every hour). New installations install them from the Plugin store like every other plugin.

## 0.4.43 — 2026-10-17

### Added
- ★ **IPv6 addresses (optional)**: Settings → IPv6. After a scan Netlens sends one multicast echo on the connected networks, reads which IPv6 addresses answer and attaches them to the devices it already knows (matched by MAC address). The device page lists them as global, private (ULA) or link-local. Off by default; devices that only have IPv6 are not added yet.

## 0.4.42 — 2026-10-17

### Added
- ★ **Backups of all remote sites in one table**: a remote site that has a backup plugin now reports its backup state (counts, filling stores, the backups that failed or are late), and the Backups page of the central Netlens lists every site with a link to it. A failed or late backup at a site also shows on the dashboard.
- The backup events (backup failed, late, recovered) can now be chosen as alert channel events.

## 0.4.38 — 2026-10-17

### Fixed
- **The spinner now shows right away on the first visit after an update**: the stylesheets used to hold back the first paint, so the screen stayed black until all of them had arrived. They now load below the spinner, which is shown until they are in.

## 0.4.37 — 2026-10-16

### Changed
- **A loading indicator**: the first visit after an update fetches the whole new version, which showed an empty (black) screen. The page now paints a spinner with "Loading Netlens…" at once (in the dark or light colours of your theme, with a note if it takes more than a few seconds), and every page shows a small spinner until its data is there.

## 0.4.36 — 2026-10-16

### Added
- **Leave a device out of the reports**: a tick box on the device's edit form. The weekly and monthly reports then neither count its outages nor name it as a new device.
- **Business hours and planned maintenance in the reports**: both reports can count only the business hours (days and hours you set, on the server's clock) and can leave out the time that falls in a planned maintenance window of the device. The monthly report page has both as switches; the weekly report and the monthly mail use the saved choice.
- **Monthly report by mail**: the availability of the last full month, in plain language, goes to the notification channels that tick the new *Monthly report* event, on the day and hour you choose, with an optional availability target. *Send it now* tries it out.
- **How many items the weekly text lists** (outages, disks, problems) is a setting (1 to 30; it was always 5).

## 0.4.35 — 2026-10-16

### Changed
- **Reports can be limited and tuned**: both reports can now cover **only the always-on devices** instead of every device. The weekly report has a *Covers* choice (all devices or always-on only) and tick boxes for its parts (service checks, new devices, health readings past a limit, disks filling up, remote sites), saved on the server and used for what is sent. The monthly availability report has a filter bar (always-on devices only, services on or off, one device group, only what had an outage, and an availability **target** in percent that marks everything below it); the choice is remembered in the browser, and the CSV download follows it.

## 0.4.34 — 2026-10-16

### Fixed
- **Containers reported the temperature of their host**: an LXC or Docker container sees the sensors of the machine it runs on, so every container monitored over SSH raised the same temperature warning as its host (for example `lxc-docker1: temperature on x86_pkg_temp is 84°C`). Netlens now notices that the target is a container and does not read temperatures there; an old temperature warning of such a guest clears by itself at the next read. Read the temperature on the host (or the Proxmox node), where it belongs.

## 0.4.31 — 2026-10-16

### Added
- ★ **Backups**: a new plugin kind, `backup`, and a first plugin for **Proxmox Backup Server**. The new *Backups* page (Monitoring) shows for every VM, container and host the newest backup, its age, the copies, the size and whether the last backup worked and was verified, the usage of each datastore with the date it is expected to be full, the results of the garbage collection, prune, verify and sync jobs, recent problems, and the **guests that have no backup**. Each backup is tied to its guest (by type and Proxmox VM id): the guest's device page gets a *Backup* card, the dashboard gets a *Guest backups* card and attention items, and Netlens raises events when a backup fails, when a guest is not backed up on time (more than 2.5 times its usual interval) and when a datastore is on course to fill up. `/metrics` carries `netlens_backup_*`.

## 0.4.29 — 2026-10-16

### Changed
- **Faster page loads over the internet** (behind a reverse proxy): the interface files are now served under an address with the version in it (`v/<version>/js/...`) and cached for a year, so a second visit fetches almost nothing but the data, and a new version still shows up at once. The page lists the scripts it needs up front, so the browser no longer finds them one import at a time. The dashboard asks for its data at the same time instead of one after another, and the "What's new" check no longer downloads the whole changelog on every page load. On a simulated internet connection (80 ms, 20 Mbit/s) the dashboard went from 2.1 s to 1.5 s on a first visit and to 1.0 s on a return visit.

## 0.4.28 — 2026-10-16

### Changed
- **Faster**: pages and lists are sent compressed (gzip, about a quarter of the size); the availability report and the weekly summary are about seven and three times faster (they parsed every check's timestamp); the uptime figures of the dashboard, statistics and `/metrics` read a covering index (about twice as fast, the old time index is replaced by it on the first start); open pages no longer refresh while their browser tab is hidden; SQLite refreshes its query statistics once an hour.

## 0.4.27 — 2026-10-16

### Added
- ★ **Auto-update for plugins**: a tick box *Auto-update* per plugin in the *Plugin manager* (off by default). Once an hour Netlens installs a newer version of that plugin by itself, but only when the release is *Reviewed* or *Verified*, never a *Community* one, never a version you rolled back from, and never over a plugin you uploaded by hand. Settings and the on/off state are kept; each update, refusal or failure is an event (*Plugin updated*, *Plugin update held back*, *Plugin update failed*).
- ★ **Warning when a Netlens update may have broken plugins**: after Netlens is upgraded, the *Plugin manager* (and the dashboard) list plugins that cannot be loaded, that the index says only support an older Netlens, or that started failing after the upgrade. Each has an *Update* button when a newer version supports this Netlens, and the text says how to go back to the earlier Netlens image. Plugin releases in the index may now name `max_netlens`, the last Netlens version they are known to work with.

## 0.4.25 — 2026-10-16

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
