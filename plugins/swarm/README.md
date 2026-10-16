# Netlens plugin: Docker Swarm

A `hypervisor` plugin.

Shows a **Docker Swarm** cluster: every node as a host (role, availability, state, address) and every task (a running copy of a service) as a guest of the node it runs on, with service name, stack, image, published ports and state.

> **Status: tested in a lab** (Docker 26.1.5 swarm mode (one manager node, a replicated service with a published port). Multi-node swarms, drained nodes and stacks follow the Docker API documentation and are covered by simulated answers only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. On **one manager node** add the read-only socket proxy from the box at the top of the plugin's page (`tecnativa/docker-socket-proxy` with `INFO`, `NODES`, `SERVICES` and `TASKS` on, `POST` off).
2. In Netlens install **Docker Swarm**, add a line with the proxy address (`http://192.168.0.189:2375`). Test, enable.

## Good to know

- Only a manager knows the cluster: pointing at a worker gives a clear message.
- Do **not** switch `SWARM=1` on in the proxy for this plugin: the `/swarm` answer contains the join tokens. The plugin reads `/info` instead.
- Tasks that were replaced (desired state shutdown) are left out. Overlay addresses are inside the cluster and are not reported; a port published through the routing mesh is shown on every task.
- Use the Docker plugin on the same hosts if you also want plain containers with health and restart counts.
