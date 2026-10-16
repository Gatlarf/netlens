# Netlens plugin: NetBox

A `topology` plugin.

Imports your **documented network from NetBox (4.x)**: devices with a network role (router, switch, access point ...) become network nodes, every other device a client, and the **cables between interfaces** decide who hangs below whom, including the port a device is plugged into. Netlens matches them to what it finds on the network by MAC address, so the hierarchy shows your documentation.

> **Status: tested in a lab** (NetBox 4.7.3 (netbox-docker): a router, switch, access point and server with interfaces, MAC addresses, IP addresses and cables. Sites, tags and virtual machines are not used.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Make a read-only user and API token (box at the top of the plugin's page).
2. In Netlens install **NetBox**, add a line with the address and the token (NetBox 4.5+: the whole `nbt_<key>.<token>`). Check *Network roles* (the device role slugs that count as network equipment) and optionally the sites.
3. Test, enable.

## Good to know

- A device with no MAC address on any interface cannot be matched by Netlens and is skipped (the test message counts them).
- The tree starts at the gateway (role router, firewall or gateway) and follows cables between network devices; a device cabled to several switches hangs below the one closer to the gateway.
- NetBox says nothing about Wi-Fi, so clients are `wired`.
