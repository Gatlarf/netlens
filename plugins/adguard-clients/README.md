# Netlens plugin: AdGuard Home clients

A `topology` plugin.

Reads what **AdGuard Home** knows about your devices: the **DHCP leases and static leases** (MAC address, IP address, host name) and the **clients you named** in AdGuard Home (a client with a MAC address among its identifiers), including the device type and operating system from AdGuard's tags (`device_tv`, `os_android` ...). Netlens matches them to what it finds on the network by MAC address and uses the names and types as evidence. To register names *in* AdGuard Home, use the **AdGuard Home** DNS plugin instead.

> **Status: tested against the real software in a lab** (AdGuard Home v0.107.79 in Docker: a named client with a MAC address, an IP address and a CIDR among its identifiers, a static DHCP lease, a wrong password). A running DHCP server with dynamic leases was not tried and follows the documented answer; it is covered by simulated answers. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts only).

## Set-up

1. In Netlens install **AdGuard Home clients**, add a line with the AdGuard Home address (`http://192.168.0.2:3000`), the user name and the password, **Test**, enable.
2. Optional: in AdGuard Home (*Settings → Client settings*) add the MAC address of a device to a named client's identifiers, and tag it (*TV*, *Phone* ...), to give Netlens a name and a device type for it.

## Good to know

- Only identifiers that are **MAC addresses** can be matched. A client that is identified by an IP address or a CIDR only is not reported. The runtime clients AdGuard Home builds itself (from `/etc/hosts`, reverse DNS) have no MAC address and are not used.
- The name you gave a client beats the host name in a lease. The address comes from the client's IP identifier, else from the lease.
- Tags map to Netlens device types (`device_tv` → TV, `device_laptop` and `device_pc` → computer, `device_phone`, `device_tablet`, `device_printer`, `device_camera`, `device_nas`, `device_audio` → speaker, `device_gameconsole` → console, `device_securityalarm` → IoT) and to an operating system (`os_windows` ...).
- AdGuard Home does not know which switch a device is on, so the plugin gives names and types, not a place in the hierarchy.
- Netlens only sends GET requests.
