# Netlens plugin: HashiCorp Consul

A `hypervisor` plugin.

Lists what is registered in a **Consul service catalog**: the nodes become hosts (with their address, and offline when the agent's `serfHealth` check fails) and every registered service instance becomes a guest of its node, with its **health** (`running` = passing, `warning`, `critical`), tags and port. Netlens ties the nodes and services to the devices it found by address, so a failing service shows up on the device page.

> **Status: tested against the real software in a lab** (Consul 1.20.6 in Docker, dev mode: nodes and services registered through the catalog API, passing, warning and critical checks). ACL tokens, several datacenters and Connect/mesh services follow the documentation and are covered by simulated answers only. Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts only).

## Set-up

1. Without ACLs nothing is needed. With ACLs make a token that can read the catalog:
   ```hcl
   node_prefix "" { policy = "read" }
   service_prefix "" { policy = "read" }
   ```
2. In Netlens install **HashiCorp Consul**, add a line with the HTTP address (`http://192.168.0.4:8500`) and the token. Test, enable.

## Good to know

- Netlens only sends GET requests to `/v1/agent/self`, `/v1/catalog/*` and `/v1/health/state/any`.
- The worst check of a service instance decides its status. An instance without checks counts as running.
- A guest's address is the service address, else the node's. Loopback addresses (a dev agent) are not reported.
- Every server registers itself as the service `consul`; it is hidden by default.
- Two datacenters with the same node names are both kept (the second gets the address of the agent added to its ids).
