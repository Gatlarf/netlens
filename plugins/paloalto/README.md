# Palo Alto Networks PAN-OS (topology plugin)

Reads a **Palo Alto Networks** firewall (PAN-OS 9.0 and later) through the XML API with a read-only API key.

## What you get

* The firewall as the **gateway** in the hierarchy and on the map, with its interfaces (link, speed).
* The devices behind it from the **DHCP leases** and the **ARP table**, with name and address.
* A **Firewall** card on the device page: software version and serial number, **high availability** (mode, state of this unit and its peer, whether the configuration is synchronised), **IPsec tunnels** up or down, **licences** with days left.
* Events you can be notified about: `firewall_ha` (a failover), `vpn_down` / `vpn_up`, `firewall_licence` (a licence ends within 30 days), `link_down` / `link_up`.

## Set up the firewall

Create an admin role that only has *XML API > Operational Requests*, an administrator with that role, and generate its API key (the plugin page shows how). The key is sent in the `X-PAN-KEY` header, not in the address.

## What you do not get

PAN-OS has no device inventory with operating systems, so clients carry a name and an address only. Point the plugin at the firewall itself, not at Panorama (Panorama support is not built). No policies or logs are read, and nothing is changed.

## Notes

* Only operational `show` commands are used. A command your PAN-OS version does not offer is skipped.
* Verify TLS is on by default. Untick it only while the firewall still has its self-signed certificate.

## Read-only and safe

Only reads. A refused login or token stops the automatic syncing until you save the settings or press **Sync now**, so a wrong key cannot lock the account. The key stays in Netlens' encrypted settings and is never written to the log.

## Status

Built from the public PAN-OS XML API documentation and tested against a simulated firewall (`tests/test_plugin_paloalto.py`). **Not yet tested on a real Palo Alto firewall.** Run **Run diagnostic** on the plugin page when something does not look right: it lists which fields the firewall answers with (no addresses, names, serial numbers or keys), and sending that report is the fastest way to get a field fixed.
