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

## Good to know

- A device with an active `wan*` interface is the gateway, any other device is an access point; override with *Role*.
- A station associated with a radio is `wifi`; every other device is `wired`, even when it is really behind a switch.
- The router's own MAC addresses are never reported as clients; the same device seen by two access points is reported by the one whose radio it is associated with.
