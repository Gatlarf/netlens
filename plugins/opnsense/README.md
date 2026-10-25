# Netlens plugin: OPNsense

A `topology` plugin.

Reads an **OPNsense firewall**: the firewall as the gateway node, and every device in its ARP table as a client with the manufacturer and host name OPNsense knows, enriched with names from the DHCP leases (Dnsmasq or Kea). Netlens uses this to place devices in the hierarchy under the firewall.

> **Status: tested against the real software in a lab** (OPNsense 26.7 under QEMU: API key of root and of a restricted user made from the setup box, interfaces, ARP, system information. The DHCP lease lists (Dnsmasq and Kea) were empty in the lab, so their row fields follow the documentation (the plugin accepts several spellings and the diagnostic lists the real field names).) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. In OPNsense make a group with the privileges listed in the box at the top of the plugin's page, a user in that group, and an API key for the user (*System → Access → Users → API keys +*).
2. In Netlens install **OPNsense**, add a line with the address (`https://192.168.1.1`), the key and the secret. Optionally limit the interfaces.
3. Test, enable.

## Health of the firewall (1.1.0)

The plugin also reports the firewall itself: processor, memory, load, temperature and uptime, the installed version and a waiting update, and the interfaces as ports with link, speed, duplex and counters. The interface of the internet connection (`wan`, or the one with a gateway) is named **WAN**, so the HUD traffic graph can draw your provider line. All read-only and optional: a reading the API key may not read is left out and never fails the sync. Switch the whole thing off with *Read the health of the firewalls*.

> **Status of the 1.1.0 parts:** the interface list, link and speed were checked against OPNsense 26.7 under QEMU. The lab key could not read the other endpoints (HTTP 403), so processor, memory, uptime, temperature, firmware and the counters follow the OPNsense API documentation and simulated answers. The privileges for them are not confirmed; *Run diagnostic* shows which reading is refused.

## Good to know

- The WAN interface is left out unless you list it; the firewall's own MAC addresses are never clients.
- OPNsense knows nothing about how a device is connected, so `medium` stays unknown.
- The restricted key cannot use `getArp` (403) but can use `search_arp`, which the plugin uses. A plain GET returns every row; if OPNsense says there are more, the plugin asks again for all of them.
