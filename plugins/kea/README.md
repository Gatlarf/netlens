# Netlens plugin: Kea DHCP

A `topology` plugin.

Reads the DHCP leases of ISC Kea through its Control Agent and gives Netlens the **host name** and **address** of every device that has a lease (and, if you want, every fixed reservation, so a device that is switched off keeps its name). Netlens matches them to the devices it finds by MAC address.

> **Status: tested against the real software in a lab** (Kea 2.6.3 on Debian 13: leases added with `lease4-add`, reservations in the configuration, a wrong password, the hook library missing). Real DHCP clients and a Kea with a database back end (MySQL/PostgreSQL) were not tried. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts only).

## Set-up

1. Kea needs the **Control Agent** (`kea-ctrl-agent`, port 8000) with an `authentication` block (type `basic`) and a user for Netlens. On Debian the password goes in `/etc/kea/kea-api-password`.
2. The DHCPv4 server needs the **lease_cmds** hook library in `hooks-libraries` (`libdhcp_lease_cmds.so`). Without it Netlens says so.
3. In Netlens install **Kea DHCP**, add a line with the address (`http://192.168.0.2:8000`), the user and the password, **Test**, enable.

## Good to know

- Only DHCPv4 is read. Expired, declined and reclaimed leases are left out.
- Netlens only sends `version-get`, `lease4-get-all` and `config-get`. It never adds or removes a lease.
- Kea does not know which switch a device is on, so the plugin gives names and addresses, not a place in the hierarchy.
- A reservation by client id or DUID (no MAC address) cannot be matched and is skipped.
- A lease with a host name wins over a reservation of the same MAC address.
