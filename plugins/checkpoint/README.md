# Check Point Management (topology plugin)

Reads a **Check Point management server** (R80.10 and later) through the Management API with a read-only administrator.

## What you get

* Every **security gateway, cluster, cluster member and server** the management server manages, as network nodes with address, model, operating system and **version** (in a **Firewall** card on the device page).
* A warning in *Test connection* when a gateway is not communicating with the management server (SIC).

## What you do not get

The management server knows its gateways but **has no ARP or DHCP tables**, so this plugin reports no devices behind a gateway, and the cluster state, VPN tunnels and licences are not read. For those, add the gateways to the **SNMP plugin** (the Check Point MIB and the standard MIBs). The objects are known by address only: Netlens matches them to the devices it scanned by IP address.

## Set up the management server

Create a read-only administrator (permission profile *Read Only All*), give it an API key or a password, and allow the Netlens machine under *Management API > Advanced Settings*. Netlens logs in with a **read-only session**, runs only `show-gateways-and-servers` and logs out again. On a Multi-Domain Server give the domain name.

## Notes

* Verify TLS is on by default. Untick it only while the server uses the certificate it was installed with.

## Read-only and safe

Only reads. A refused login or token stops the automatic syncing until you save the settings or press **Sync now**, so a wrong key cannot lock the account. The key stays in Netlens' encrypted settings and is never written to the log.

## Status

Built from the public Management API documentation and tested against a simulated server over TLS (`tests/test_plugin_checkpoint.py`). **Not yet tested on a real Check Point server.** Run **Run diagnostic** on the plugin page when something does not look right: it lists which fields the firewall answers with (no addresses, names, serial numbers or keys), and sending that report is the fastest way to get a field fixed.
