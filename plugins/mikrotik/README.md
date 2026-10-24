# Netlens plugin: MikroTik RouterOS

A `topology` plugin.

Reads a **MikroTik router, switch or access point (RouterOS 7.1+)**: the device as a network node, MikroTik neighbours (MNDP/LLDP) as child nodes, and every device it knows as a client with the bridge **port** it sits behind, its DHCP lease, ARP entry or Wi-Fi registration (band, signal, link speed). Netlens uses this to place devices in the hierarchy.

> **Status: tested against the real software in a lab** (RouterOS 7.12.1 CHR under QEMU: login with admin and with a read-only user made from the setup box, bridge hosts, ARP, DHCP leases, interfaces. Neighbours (MNDP), the wireless and wifi registration tables are covered by simulated answers only (the lab router has no radio and no neighbours).) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Health of the device (1.1.0)

Besides the topology the plugin reports the device's own health, read with a few extra GETs per device: the **processor** (`system/resource` `cpu-load`), **memory**, **uptime**, the **temperature** (`system/health`, the hottest sensor; devices without sensors, like a CHR, give none), the **firmware** (the installed version, and the newest one the router already knows of from `system/package/update`: the plugin never asks MikroTik's servers, so run *Check for updates* on the router to see a waiting version), the **ports** (`interface`: link, byte, packet and error counters; speed from `interface/ethernet`) and the **internet connection**: the interface of the default route is named *WAN* (it becomes the WAN line of the traffic graph on the HUD page). Netlens records them like a monitored device. Switch it off with *Read the health of the devices*. Tested on a real RouterOS 7.12.1 (CHR); the temperature and the speed of a physical port follow the documentation.

## Set-up

1. Create the read-only user and enable the REST API with the lines in the box at the top of the plugin's page (`www-ssl` on 443 or plain `www` on 80; limit the service to the Netlens machine).
2. In Netlens install **MikroTik RouterOS**, add a line per device (`https://192.168.88.1`, user name, password). For a switch or access point also fill in *Uplink*.
3. Test, enable.

## Good to know

- A device with a srcnat masquerade rule is the gateway, any other is a switch; override with *Role*.
- Only MikroTik neighbours (platform `MikroTik`) become nodes; other discovery entries are ignored.
- The bridge host table, ARP and DHCP leases are combined; an offline static lease is not a client. Wi-Fi stations come from `interface/wifi/registration-table` (wifi package) or `interface/wireless/registration-table`.
