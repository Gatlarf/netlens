# Fortinet FortiGate (topology plugin)

Reads a **FortiGate** firewall (FortiOS 6.4 and later) through its REST API with a read-only token.

## What you get

* The firewall as the **gateway** in the hierarchy and on the map, with its interfaces (link, speed, packet counters: graphs and link-change events as for a switch).
* Every device behind it from the **DHCP leases**, the firewall's own **device inventory** (vendor, operating system, kind of device: printer, phone, camera ...) and the **ARP table**. Netlens uses this as evidence when it identifies a device.
* A **Firewall** card on the device page: firmware version and serial number, **high availability** (mode, which unit is primary, whether the pair is synchronised), **VPN tunnels** up or down, **licences and support** with days left.
* Events you can be notified about: `firewall_ha` (a failover), `vpn_down` / `vpn_up`, `firewall_licence` (a licence ends within 30 days), `link_down` / `link_up` (interfaces).

## Set up the FortiGate

Create a read-only administrator profile, a REST API administrator with a token, and trust only the Netlens machine (the plugin page shows the CLI lines). A firewall with several VDOMs: one line per VDOM, with the VDOM name. A high-availability pair answers on one address.

## What you do not get

No firewall rules or policies, no logs, no session table. The plugin never changes anything.

## Notes

* Field names differ a little between FortiOS versions; the plugin accepts what it knows and leaves out what it cannot find. Endpoints your profile or version does not offer are skipped.
* Verify TLS is on by default. Untick it only for the factory certificate.

## Read-only and safe

Only reads. A refused login or token stops the automatic syncing until you save the settings or press **Sync now**, so a wrong key cannot lock the account. The key stays in Netlens' encrypted settings and is never written to the log.

## Status

Built from the public FortiOS REST API documentation and tested against a simulated firewall (`tests/test_plugin_fortigate.py`). **Not yet tested on a real FortiGate.** Run **Run diagnostic** on the plugin page when something does not look right: it lists which fields the firewall answers with (no addresses, names, serial numbers or keys), and sending that report is the fastest way to get a field fixed.
