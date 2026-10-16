# Netlens plugin: Pi-hole clients

A `topology` plugin.

Reads the **network table of Pi-hole v6**: every device that asked Pi-hole for a DNS answer, with its MAC address, current IP address, the host name Pi-hole resolved for it and the manufacturer it looked up. Netlens matches them to what it finds on the network by MAC address and uses the names and manufacturers as evidence. To register names *in* Pi-hole, use the **Pi-hole** DNS plugin instead.

> **Status: tested against the real software in a lab** (Pi-hole 6.4.3 in Docker; the lab only has one client behind the Docker bridge, so multi-address devices, names and manufacturers follow the recorded shape and are covered by simulated answers). Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. In Pi-hole: *Settings → Web interface / API → Configure app password*.
2. In Netlens install **Pi-hole clients**, add a line with the Pi-hole address (`http://192.168.0.2`) and the app password, **Test**, enable.

## Good to know

- Pi-hole learns a device's MAC address from the neighbour table, so only devices on the **same network segment** as Pi-hole have a real one. Devices behind a router appear with the router's MAC address (and are matched to the router).
- Rows without a MAC address (Pi-hole writes `ip-127.0.0.1`) and multicast addresses are left out, as are devices whose last query is older than the setting *Only devices seen in the last days* (30).
- The IPv4 address seen last is the device's address; the name is the first name Pi-hole resolved.
- Pi-hole does not know which switch a device is on, so the plugin gives names and manufacturers, not a place in the hierarchy.
