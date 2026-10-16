# Netlens plugin: HashiCorp Nomad

A `hypervisor` plugin.

Shows a **Nomad cluster** as hosts and guests: the client nodes as hosts with their address and state, the allocations (running tasks of your jobs) as guests of the node they run on, with namespace, job, image, published ports, restarts and start time.

> **Status: tested against the real software in a lab** (Nomad 2.0.7 in dev mode with a Docker job (2 allocations). ACL-protected clusters, several namespaces and multi-node clusters follow the documentation and are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. Without ACLs nothing is needed. With ACLs, apply the read-only policy from the box at the top of the plugin's page and create a token for it.
2. In Netlens install **HashiCorp Nomad**, add a line with the address of any server or client (`http://192.168.0.10:4646`) and the token.
3. Test, enable.

## Good to know

- Finished allocations and ones Nomad has already replaced are left out.
- Allocations share their node's address; the ports they publish are reported on the guest (and appear in the host's *Open ports*).
