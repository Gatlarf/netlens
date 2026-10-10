# Netlens plugins

Plugins that are **not built into Netlens**. They are installed from *Settings → Integrations → Browse plugins* (they are listed in
[`plugin-index/`](../plugin-index/README.md)) or uploaded as a zip, and start switched off.

| Folder | Plugin | Reads | Status |
|---|---|---|---|
| [`omada/`](omada/README.md) | TP-Link Omada | Omada controller 5.1 or newer: gateway, switches, access points, clients | written from the public API, **testing started** (1.0.1 fixes a first controller error) |
| [`unifi/`](unifi/README.md) | Ubiquiti UniFi | UniFi Network on a UniFi OS console or a classic controller | written from the public API, **not yet tested on hardware** |
| [`snmp/`](snmp/README.md) | SNMP switches | managed switches over SNMP v1/v2c: the MAC address table (which device is on which port) and LLDP (how the switches are connected) | tested against simulated switches only |
| [`technitium/`](technitium/README.md) | Technitium DNS | registers devices in Technitium DNS (a `dns` plugin): A and PTR records, primary/secondary and cluster, never touches records it did not make | tested against a simulated Technitium server only |
| [`truenas/`](truenas/README.md) | TrueNAS | TrueNAS Community 25.04+: containers, VMs and apps as guests of the NAS (a `hypervisor` plugin) | tested on a real TrueNAS 25.10.6 (VMs with simulated data) |

Omada, UniFi and SNMP are `topology` plugins: they tell Netlens which switch or access point every device is connected to, and which device hangs
below which, so the hierarchy and the map show the real network position. They only read.

## Diagnostics

Every plugin here has a `diagnose(config)`: the plugin's page in Netlens shows a **Run diagnostic** button that produces an anonymised report (field names and types, which step failed) to copy or download and send to the maintainer. New plugins should include one too, see `app/plugins/PLUGINS.md`.

## Build a release zip

```
python plugins/build_zip.py omada      # writes plugins/dist/omada-<version>.zip and prints its SHA-256
python plugins/build_zip.py unifi
```

The zip holds only `plugin.json` and `plugin.py`. The README and the tests stay in the repository.
