# Netlens plugin: VMware ESXi / vCenter

A `hypervisor` plugin.

Shows **VMware ESXi hosts and vCenter inventories**: every host (connection state, management address) and every virtual machine as a guest of its host, with power state, MAC and IP addresses (from VMware Tools), guest operating system, CPUs and memory. Works with a standalone ESXi and with vCenter through VMware's SOAP web service (`/sdk`), read-only.

> **Status: tested in a lab** (the govmomi simulator vcsim (vCenter 6.5 API, 4 hosts, 4 virtual machines): login, inventory, properties. **No real ESXi or vCenter was available**: VMware Tools addresses, host management addresses and standalone ESXi follow the vSphere API documentation and are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Make a user with the built-in **Read-only** role on the root of the inventory.
2. In Netlens install **VMware ESXi / vCenter**, add a line per ESXi or (better) per vCenter with the address, user name and password. Test, enable.

## Good to know

- IP addresses and the Tools state come from VMware Tools; without Tools only the MAC addresses of the virtual network cards are known.
- For a vCenter list the vCenter only; it already knows all its hosts.
- Templates are left out. Every request is a read (`RetrieveServiceContent`, `CreateContainerView`, `RetrievePropertiesEx`); the session is logged out at the end.
