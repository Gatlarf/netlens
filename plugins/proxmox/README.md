# Netlens plugin: Proxmox VE

A `hypervisor` plugin. Until Netlens 0.4.43 it was built in; since then it is installed from the **Plugin store** like the others. If you used it before, Netlens installs it again by itself after the upgrade, with your settings, and keeps it switched on.

Reads your Proxmox VMs and containers (read-only) so the map and the device pages show which devices run on which Proxmox host, with guest details.

## Set-up

Create an API token with the read-only **PVEAuditor** role (Datacenter → Permissions → API Tokens), or use a user and password. In Netlens open the plugin, add the address of the web interface (`https://192.168.0.10:8006`; port 8006 is assumed) and the token, **Test**, enable.
