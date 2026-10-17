# Netlens plugin: Portainer

A `hypervisor` plugin.

Shows every **Docker environment a Portainer manages** (local socket, Portainer agents, Edge agents) as a host, with its containers as guests: state, health, restarts, image, compose project, published ports and containers with their own LAN address (macvlan/ipvlan). One connection covers all your Docker hosts without opening each host's Docker port. Kubernetes and Azure environments are skipped.

> **Status: tested against the real software in a lab** (Portainer CE 2.45.2 with its local Docker environment (6 containers); agent, Edge and Kubernetes environments from the Portainer documentation only.) Please report what you see; *Run diagnostic* on the plugin's page makes an anonymised report (counts and field names, never names or addresses).

## Set-up

1. In Portainer: your account → *My account → Access tokens → Add access token*. For a read-only view make a separate user with the Standard user or Read-only role on the environments and a token for that user.
2. In Netlens install **Portainer**, add a line with the address (`https://192.168.0.5:9443`) and the token. If Portainer runs on the Docker host it manages through the local socket, also give *Portainer host's own address*.
3. Test, enable.

## Good to know

- Everything goes through Portainer's own proxy to the Docker API with GET requests only; the token's user decides what is visible.
- `/api/system/status` answers without a login, so the test uses `/api/endpoints`, which refuses a wrong token.
- A stopped environment (Status 2) is shown as an offline host. An Edge agent's address is unknown to Portainer, so Netlens may not find its device on the map.
- If you already use the Docker plugin for the same hosts, use one or the other: the two would list the same containers.

## Restarting a guest (auto-remediation)

Netlens can reset, restart, shut down or start a guest from a remediation rule (Monitoring → Remediation, action "Restart the virtual machine"). Reading needs only read access; **doing** needs the right to change power state. The user behind the access token must be allowed to start, stop and restart containers in that environment (a standard user with access to it is enough). Reset and restart are a restart (kill after 5 / 10 seconds). If the action is refused, Netlens shows why in the run's result.
