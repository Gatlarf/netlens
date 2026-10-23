# Netlens plugins

Plugins that are **not built into Netlens**. They are installed from *Settings → Integrations → Plugin store* (they are listed in
[`plugin-index/`](../plugin-index/README.md)) or uploaded as a zip, and start switched off.

| Folder | Plugin | Reads | Status |
|---|---|---|---|
| [`proxmox/`](proxmox/README.md) | Proxmox VE | VMs and containers and the host each runs on (a `hypervisor` plugin; was built into Netlens before 0.4.44) | in daily use on the maintainer's cluster |
| [`asus/`](asus/README.md) | ASUS router (AiMesh) | which device is connected to which AiMesh node, with Wi-Fi signal and roaming, and the router's Traffic Analyzer: traffic per application and device (a `topology` plugin; was built in before 0.4.44) | tested on an ASUS RT-AX92U |
| [`homeassistant/`](homeassistant/README.md) | Home Assistant | the device registry: area, model, battery, availability (an `inventory` plugin) | tested on a real Home Assistant 2026.7.1 |
| [`omada/`](omada/README.md) | TP-Link Omada | Omada controller 5.1 or newer: gateway, switches and their ports, access points, clients, the switch port of each wired client, and (with an Open API client) application statistics | written from the public API, **testing started** (1.0.1 fixes a first controller error) |
| [`unifi/`](unifi/README.md) | Ubiquiti UniFi | UniFi Network on a UniFi OS console or a classic controller | written from the public API, **not yet tested on hardware** |
| [`snmp/`](snmp/README.md) | SNMP switches | managed switches over SNMP v1, v2c or v3: the MAC address table (which device is on which port, for Cisco per VLAN) and LLDP or Cisco CDP (how the switches are connected) | verified against a real device (v3 also against a real net-snmp agent; the Cisco parts only against a simulated Catalyst) |
| [`technitium/`](technitium/README.md) | Technitium DNS | registers devices in Technitium DNS (a `dns` plugin): A and PTR records, primary/secondary and cluster, never touches records it did not make | tested against a simulated Technitium server only |
| [`synology/`](synology/README.md) | Synology | a Synology NAS (DSM 7): Container Manager containers, Virtual Machine Manager machines and packages as guests (a `hypervisor` plugin) | tested against a simulated DSM only |
| [`truenas/`](truenas/README.md) | TrueNAS | TrueNAS Community 25.04+: containers, VMs and apps as guests of the NAS (a `hypervisor` plugin) | tested on a real TrueNAS 25.10.6 (VMs with simulated data) |
| [`redfish/`](redfish/README.md) | Redfish (server BMC) | Dell iDRAC, HPE iLO, Lenovo XClarity, Supermicro, Cisco CIMC and other DMTF Redfish BMCs: server health, drives, RAID volumes, power supplies and fans (a `storage` plugin) | run against the official DMTF Redfish Mockup Server |
| [`netapp-ontap/`](netapp-ontap/README.md) | NetApp ONTAP | ONTAP 9.8+ clusters: nodes, aggregates, volumes, LUNs, disks and the NFS clients of a volume (a `storage` plugin) | simulator only |
| [`ceph/`](ceph/README.md) | Ceph | Ceph clusters through the dashboard API: health, hosts, pools, OSDs, CephFS and RBD (a `storage` plugin) | tested on a real Ceph 19.2.7 (cephadm) |
| [`openmediavault/`](openmediavault/README.md) | OpenMediaVault | an OpenMediaVault NAS (6, 7, 8): Docker containers (openmediavault-compose) and virtual machines (openmediavault-kvm) as guests (a `hypervisor` plugin) | tested on a real OpenMediaVault 8.5.12 (containers); virtual machines only against a simulator |
| [`unraid/`](unraid/README.md) | Unraid | an Unraid server (7.2+): Docker containers and virtual machines as guests, through the Unraid GraphQL API (a `hypervisor` plugin) | written from the published schema, simulated API only; **not yet tested on a real Unraid** |
| [`rockstor/`](rockstor/README.md) | Rockstor | a Rockstor 5 NAS: the Docker containers of installed Rock-ons as guests (a `hypervisor` plugin) | written from Rockstor's source, simulated API only; **not yet tested on a real Rockstor** |
| [`qnap/`](qnap/README.md) | QNAP | a QNAP NAS with Container Station 3: Docker and LXD containers as guests (a `hypervisor` plugin) | written from QNAP's login documentation and an open-source client, simulated API only; **not yet tested on a real QNAP** |
| [`ugreen/`](ugreen/README.md) | UGREEN | a UGREEN NAS (UGOS): Docker containers as guests, through the community-documented UGOS web API (a `hypervisor` plugin) | simulated API only; **not yet tested on a real UGREEN** |
| [`pihole/`](pihole/README.md) | Pi-hole | registers devices in Pi-hole v6's Local DNS (a `dns` plugin) | tested on a real Pi-hole 6.4.3 (Docker) |
| [`adguard/`](adguard/README.md) | AdGuard Home | registers devices as AdGuard Home DNS rewrites (a `dns` plugin) | verified on a real installation (and tested on AdGuard Home 0.107.79 in Docker) |
| [`portainer/`](portainer/README.md) | Portainer | every Docker environment a Portainer manages: containers as guests (a `hypervisor` plugin) | tested on a real Portainer 2.45.2 (local environment) |
| [`kubernetes/`](kubernetes/README.md) | Kubernetes | nodes as hosts, pods as guests (a `hypervisor` plugin) | tested on a real k3s 1.36 (one node) |
| [`nomad/`](nomad/README.md) | HashiCorp Nomad | client nodes as hosts, allocations as guests (a `hypervisor` plugin) | tested on a real Nomad 2.0.7 (dev mode) |
| [`traefik/`](traefik/README.md) | Traefik | the sites a Traefik v2/v3 publishes (a `proxy` plugin) | tested on a real Traefik 3.7.15 (Docker provider) |
| [`caddy/`](caddy/README.md) | Caddy | the reverse-proxy sites of a Caddy 2 (a `proxy` plugin) | tested on a real Caddy 2.11.7 |
| [`openwrt/`](openwrt/README.md) | OpenWrt | router/access point and its clients over ubus (a `topology` plugin) | tested on OpenWrt 25.12.5 (QEMU, no Wi-Fi radio) |
| [`mikrotik/`](mikrotik/README.md) | MikroTik RouterOS | router/switch, neighbours and clients over the REST API (a `topology` plugin) | tested on RouterOS 7.12.1 CHR (QEMU, no radio) |
| [`opnsense/`](opnsense/README.md) | OPNsense | the firewall as gateway and its ARP/DHCP clients (a `topology` plugin) | tested on OPNsense 26.7 (QEMU) |
| [`powerdns/`](powerdns/README.md) | PowerDNS Authoritative | registers devices in PowerDNS 4.x through its API, with comments as marker (a `dns` plugin) | tested on a real PowerDNS 4.9.17 (Docker) |
| [`bind/`](bind/README.md) | BIND 9 | registers devices by RFC 2136 dynamic update, zones read by AXFR, TSIG-signed (a `dns` plugin) | tested on a real BIND 9.20 (Docker) |
| [`swarm/`](swarm/README.md) | Docker Swarm | swarm nodes as hosts, tasks as guests (a `hypervisor` plugin) | tested on a real swarm (one manager) |
| [`incus/`](incus/README.md) | Incus / LXD | servers and their containers and VMs (a `hypervisor` plugin) | tested on a real Incus 6.0.4 (containers only) |
| [`vsphere/`](vsphere/README.md) | VMware ESXi / vCenter | hosts and virtual machines over SOAP (a `hypervisor` plugin) | tested against the vcsim simulator only |
| [`kong/`](kong/README.md) | Kong Gateway | routes and upstreams (a `proxy` plugin) | tested on a real Kong 3.9.4 (DB-less) |
| [`haproxy/`](haproxy/README.md) | HAProxy | backends and their servers from the statistics page (a `proxy` plugin) | tested on a real HAProxy 3.4.7 |
| [`vyos/`](vyos/README.md) | VyOS | router, ARP and DHCP clients over the HTTPS API (a `topology` plugin) | tested on a VyOS rolling live ISO (QEMU) |
| [`fortigate/`](fortigate/README.md) | Fortinet FortiGate | the firewall as the gateway with its interfaces, the devices behind it (DHCP leases, device inventory, ARP) and its health: high availability, VPN tunnels, firmware and licence expiry (a `topology` plugin; needs Netlens 0.4.152) | simulated firewall only; **not yet tested on a real FortiGate** (Community) |
| [`paloalto/`](paloalto/README.md) | Palo Alto Networks PAN-OS | the firewall as the gateway with its interfaces, the devices behind it (DHCP leases, ARP) and its health: high availability, IPsec tunnels, software and licence expiry (a `topology` plugin; needs Netlens 0.4.152) | simulated firewall only; **not yet tested on a real firewall** (Community) |
| [`checkpoint/`](checkpoint/README.md) | Check Point Management | the gateways, clusters and servers a management server manages, with version and operating system (a `topology` plugin; needs Netlens 0.4.152; devices behind a gateway and the cluster state come from the SNMP plugin) | simulated server only; **not yet tested on a real server** (Community) |
| [`tplink-easysmart/`](tplink-easysmart/README.md) | TP-Link Easy Smart switch | the switch as a node with the state, speed and packet counters of every port, from its web pages (a `topology` plugin; needs Netlens 0.4.139) | tested on a real TL-SG1016PE (hardware 3.0, firmware 1.0.0 Build 20210825); **Verified** in the plugin store; link-change events and the 24-hour error counts tested with simulated data |
| [`pbs/`](pbs/README.md) | Proxmox Backup Server | what is backed up per guest, its age and state, datastore usage and job results (a `backup` plugin) | tested on a real Proxmox Backup Server 4.2 |
| [`netbox/`](netbox/README.md) | NetBox | the documented devices and cables as nodes, clients and the tree (a `topology` plugin) | tested on a real NetBox 4.7.3 (Docker) |
| [`kea/`](kea/README.md) | Kea DHCP | DHCP leases and reservations as clients with names (a `topology` plugin) | tested on a real Kea 2.6.3 (leases added with the API; no real DHCP clients) |
| [`librenms/`](librenms/README.md) | LibreNMS | devices, LLDP/CDP links and switch forwarding tables as nodes, clients and the tree (a `topology` plugin) | tested on a real LibreNMS 26.9.1 (Docker); links and forwarding table rows inserted by hand |
| [`envoy/`](envoy/README.md) | Envoy | virtual hosts and TCP proxies with their upstreams (a `proxy` plugin) | tested on a real Envoy 1.32.13 (Docker, file configuration); xDS from documentation |
| [`apisix/`](apisix/README.md) | Apache APISIX | routes, upstreams, services and certificate expiry (a `proxy` plugin) | tested on a real APISIX 3.11.0 (Docker); stream routes from documentation |
| [`consul/`](consul/README.md) | HashiCorp Consul | catalog nodes as hosts and service instances with their health as guests (a `hypervisor` plugin) | tested on a real Consul 1.20.6 (Docker, dev mode) |
| [`pihole-clients/`](pihole-clients/README.md) | Pi-hole clients | the devices Pi-hole has seen, with names and manufacturers (a `topology` plugin) | tested on a real Pi-hole 6.4.3 (Docker); only one client in the lab |
| [`adguard-clients/`](adguard-clients/README.md) | AdGuard Home clients | DHCP leases and named clients with device types (a `topology` plugin) | tested on a real AdGuard Home v0.107.79 (Docker); static leases only |
| [`greenbone/`](greenbone/README.md) | Greenbone (OpenVAS) | the findings of the scanner per host: severity, CVE numbers, score, port, advice (a `vulnerability` plugin) | tested on a real Greenbone Community 22.7 (GMP over TLS; one host scanned, no CVE references in that scan) |
| [`nessus/`](nessus/README.md) | Tenable Nessus | the findings of the latest completed scans per host (a `vulnerability` plugin) | written from the API documentation, **not yet tested on a real Nessus** |
| [`insightvm/`](insightvm/README.md) | Rapid7 InsightVM | the vulnerabilities of the assets per host (a `vulnerability` plugin) | written from the API documentation, **not yet tested on a real console** |

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
