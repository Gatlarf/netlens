# Netlens plugin: LibreNMS

A `topology` plugin.

Imports the network that **LibreNMS** has discovered over SNMP. Devices of type *network*, *firewall* and *wireless* become network nodes, the **LLDP/CDP links** between them decide who hangs below whom, every other LibreNMS device is a client attached to the switch it is linked to, and the **forwarding tables** (FDB) of the switches give every other MAC address the switch port it was learned on. Netlens matches all of them to the devices it finds by MAC address.

> **Status: tested against the real software in a lab** (LibreNMS 26.9.1 in Docker with two SNMP devices: devices, ports with MAC addresses, ARP, API token, a wrong token). The LLDP links and the forwarding-table rows were inserted into the LibreNMS database by hand, because the lab has no managed switch; the API answers have the real shape. Please report what you see on a real switch; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names only).

## Set-up

1. In LibreNMS make a read-only user (role *global-read*) and an API token for it (*API Settings*; on 26.x also `lnms api:token-create <user>`).
2. In Netlens install **LibreNMS**, add a line with the LibreNMS address and the token, **Test**, enable.
3. Check in LibreNMS that **Device > Edit > Type** is right (*network*, *firewall* or *wireless* for equipment). The setting *Device types that are network equipment* lists the types that count as nodes.

## Good to know

- A device without any MAC address on a polled port cannot be matched and is skipped. Disabled devices are skipped.
- A *firewall* is the gateway (only the first one; others are plain nodes), *wireless* is an access point, *network* a switch. The tree starts at the gateway, or at the first node if there is none.
- A MAC address learned on a port that has an LLDP/CDP link (an uplink) is not reported as a client of that switch: it sits further away.
- If LibreNMS has no FDB data (it needs a switch that answers the BRIDGE-MIB), only the devices LibreNMS manages are reported. You can also switch the FDB clients off.
- Multicast and all-zero MAC addresses are ignored. If two devices report the same MAC address the first one keeps it.
