# Netlens plugin: Incus / LXD

A `hypervisor` plugin.

Shows an **Incus (or LXD) server or cluster**: the servers as hosts and every container and virtual machine as a guest, with state, MAC and IP addresses (when the instance sits on your LAN rather than behind NAT), image, CPU and memory limits, and autostart.

> **Status: tested in a lab** (Incus 6.0.4 (apt, Debian 13): containers (running and stopped), a NAT bridge, client-certificate login. Virtual machines, clusters and projects follow the Incus documentation and are covered by simulated answers only (the lab VM has no hardware virtualization).) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Make a client certificate and trust it as a restricted client (the commands are in the box at the top of the plugin's page); the server needs `core.https_address`.
2. In Netlens install **Incus / LXD**, add a line with the address (`https://192.168.0.20:8443`) and paste the whole text of the certificate and the key. Test, enable.

## Good to know

- An instance on a NAT'd managed network (the default `incusbr0`) keeps its internal addresses to itself; one on a bridge, macvlan or physical NIC reports its LAN addresses. MAC addresses are always reported (a stopped instance's generated MAC comes from its config).
- A cluster is read through one member; the members become hosts and each instance is a guest of its member.
- The certificate and key are stored encrypted with the other plugin settings and are written to a private temporary file only for the moment the TLS library loads them.

## Restarting a guest (auto-remediation)

Netlens can reset, restart, shut down or start a guest from a remediation rule (Monitoring → Remediation, action "Restart the virtual machine"). Reading needs only read access; **doing** needs the right to change power state. The client certificate must be a full client (not restricted to read-only). *Reset* is a forced restart, *restart* and *shutdown* ask the instance (60 s). If the action is refused, Netlens shows why in the run's result.
