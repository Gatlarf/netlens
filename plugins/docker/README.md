# Docker hosts plugin

Shows your Docker hosts with their containers in Netlens (kind `hypervisor`, like Proxmox and TrueNAS). Read-only: it only
sends `GET` requests (`/info`, `/networks`, `/containers/json`, `/containers/<id>/json`).

## What you get

* every container as a guest of its host: state (running, exited, restarting), health check, restart count, image, compose project
  and service, start time, exit code;
* how old each container's image is (when the proxy allows `IMAGES=1`; Netlens flags images older than a year),
* the ports each container **publishes**, and a mark when a port is published on all interfaces (reachable from the whole network);
* on the host's device page the *Open ports* table names the container behind each port;
* containers on a **macvlan** or **ipvlan** network have their own address on your LAN: Netlens matches them to the device its scans
  found (macvlan by MAC address, ipvlan by IP address), so a container is one device, linked to its host;
* containers on a bridge network (`172.x.x.x`) only exist inside their host: they are listed under the host with their published
  ports, but never matched to a LAN device.

## Connecting: use a read-only socket proxy

Docker's API gives full control of a host (whoever can reach it can start a privileged container, which is root). So never open the
Docker TCP port (2375) to your network. Run a small proxy that only lets `GET` requests for containers, networks and info through:

```yaml
services:
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy
    restart: unless-stopped
    environment:
      CONTAINERS: 1   # list and inspect containers
      NETWORKS: 1     # which network is macvlan / ipvlan
      INFO: 1         # the host's name
      IMAGES: 1       # optional: lets Netlens show how old each container's image is
      POST: 0         # nothing that changes anything
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - 192.168.0.189:2375:2375     # the host's LAN address (or 127.0.0.1 when Netlens runs on the same host with network_mode: host)
```

Everything else (images, volumes, exec, secrets, ...) is refused with HTTP 403. Bind the port to the host's LAN address only, and
let your firewall allow it from the Netlens machine only if you can.

Then add a line for every Docker host in the plugin's settings (`http://<host address>:2375`; **+ Add server** adds a line, **Test** on a line tests that host) and turn it on.
If Netlens runs on the Docker host itself and reaches the proxy as `127.0.0.1`, fill in *Host's own address* under *More* (for example `192.168.0.189`) so Netlens can find the host's device.

## Privacy

A container's inspect data contains its environment variables, which often hold passwords. The plugin reads that data to get the
health and restart count, but **only keeps** image, compose labels, network, ports, health, restarts and start time; nothing else is
stored or sent anywhere. The diagnostic report contains counts only.
