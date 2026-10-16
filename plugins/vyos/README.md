# Netlens plugin: VyOS

A `topology` plugin.

Reads a **VyOS router** (1.4 or newer): the router as a network node (host name, version, interface MAC addresses) and every device in its ARP table and DHCP server leases as a client. Netlens uses this to place devices in the hierarchy under the router.

> **Status: tested in a lab** (VyOS 2026.10 rolling (live ISO under QEMU): login, interfaces, ARP, source-NAT test, wrong key. The DHCP lease table was empty in the lab, so it follows the VyOS documentation.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Switch on the HTTPS API with a key (commands in the box at the top of the plugin's page) and let it listen on the management address only. **A VyOS API key can also configure the router**; VyOS has no read-only keys, so keep the key private and the port closed to everything but Netlens.
2. In Netlens install **VyOS**, add a line with the address (`https://192.168.1.1`) and the key. Test, enable.

## Good to know

- Only `show` and `showConfig` requests are sent. The text tables are read by looking for IPv4 and MAC addresses in each line, so a new column in a later release does not break it.
- A router with a source NAT rule is the gateway; override with *Role*. Neighbours in state FAILED or INCOMPLETE are skipped.
