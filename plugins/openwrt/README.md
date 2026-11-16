# Netlens plugin: OpenWrt

A `topology` plugin.

Reads an **OpenWrt router or access point**: the device as a network node, and every device it knows as a client: DHCP leases and neighbours (wired) and the Wi-Fi stations associated with each radio, with band, signal strength (RSSI) and link speed. Netlens uses this to place devices in the hierarchy and to show Wi-Fi signal history and roaming.

> **Status: tested against the real software in a lab** (OpenWrt 25.12.5 under QEMU (x86-64): login with root and with a read-only user made from the setup box, DHCP leases and neighbours, and the health readings and ports of 1.1.0. The router had no radio, so the Wi-Fi part (stations, band, signal, rates) follows the iwinfo documentation and is covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. On the router, install the packages and create the read-only login from the box at the top of the plugin's page (`apk add uhttpd-mod-ubus rpcd-mod-iwinfo luci-base`, an rpcd ACL file and a `netlens` login).
2. In Netlens install **OpenWrt**, add a line per device (`http://192.168.1.1`, user name, password). For an access point also fill in *Uplink* (the address of the router or node it is plugged into).
3. Test, enable.

## Health of the device (1.1.0)

Besides the clients, the plugin reports the device itself: processor, memory, load, temperature and uptime (they show on the device's Health card and on the HUD), the installed OpenWrt version, and the network devices as ports with link, speed, duplex and packet counters. The device the internet connection uses (the `wan` interface; the physical device under a PPPoE line) is named **WAN**, so the HUD traffic graph can draw the line to your provider. OpenWrt cannot say that a newer release exists, so no upgrade is flagged. Processor and temperature are read with `ubus file read` of `/proc/stat` and the thermal zones: the box at the top of the plugin's page has the two extra lines for the login; without them those two readings are left out, nothing fails. Everything is read-only; switch it off with *Read the health of the devices*.

## Wi-Fi channels, traffic per device and internet connections (1.2.0)

*Written from the documentation of iwinfo, mwan3 and nlbwmon and tested against simulated answers; the lab router has no radio, no mwan3 and no nlbwmon, so none of it is verified on real hardware yet. Please report what you see (Run diagnostic).*

- **Wi-Fi channels** (*Read the Wi-Fi channels*, on): the channel, width (from `htmode`), noise and number of clients of every radio (`iwinfo info` and `assoclist`, which the login already needed). Netlens shows them in the **Wi-Fi channels** card of the access point.
- **Neighbouring networks** (*Scan for neighbouring networks*, **off**): `iwinfo scan` on every radio, at most every 30 minutes (Netlens keeps the time). A scan takes the radio off its channel for a few seconds, which can drop a call, so it is your choice. It needs `"scan"` among the iwinfo permissions in the box at the top of the plugin's page; the box has been updated.
- **Traffic per device**: runs `/usr/sbin/nlbw -c json -g mac` (nlbwmon, when installed) through `ubus file exec`, only while Netlens' traffic statistics are on. It needs the exec permission for that one program (also in the box). Netlens works out the day's traffic from the growth of the counters; nlbwmon starts a new period now and then, which Netlens takes as a restart of the count.
- **Internet connections** (*Read the internet connections*, on): when mwan3 is installed with two or more interfaces, `ubus call mwan3 status` gives each interface's state; the interfaces that carry traffic in a policy are "in use", and a policy that shares the load between several makes the mode "load balancing". Needs `"mwan3": ["status"]` (in the box).


## Good to know

- A device with an active `wan*` interface is the gateway, any other device is an access point; override with *Role*.
- A station associated with a radio is `wifi`; every other device is `wired`, even when it is really behind a switch.
- The router's own MAC addresses are never reported as clients; the same device seen by two access points is reported by the one whose radio it is associated with.
