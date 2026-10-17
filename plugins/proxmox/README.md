# Netlens plugin: Proxmox VE

A `hypervisor` plugin. Until Netlens 0.4.43 it was built in; since then it is installed from the **Plugin store** like the others. If you used it before, Netlens installs it again by itself after the upgrade, with your settings, and keeps it switched on.

Reads your Proxmox VMs and containers (read-only) so the map and the device pages show which devices run on which Proxmox host, with guest details.

## Set-up

Create an API token with the read-only **PVEAuditor** role (Datacenter → Permissions → API Tokens), or use a user and password. In Netlens open the plugin, add the address of the web interface (`https://192.168.0.10:8006`; port 8006 is assumed) and the token, **Test**, enable.

## Restarting a guest (auto-remediation)

Netlens can reset, reboot, shut down or start a guest when a remediation rule says so (Monitoring → Remediation, action "Restart the virtual machine"). Reading needs only PVEAuditor; **doing** needs one more privilege: give the API token the **VM.PowerMgmt** privilege (for example the *PVEVMAdmin* role on `/vms` or on one guest). If you use a token with "Privilege Separation" on, give the role to the token itself, not only to its user. A hard *reset* is the reset button; *reboot* and *shutdown* ask the guest's operating system (shutdown is forced after 60 seconds). Containers have no reset button, so a reset becomes a reboot.
