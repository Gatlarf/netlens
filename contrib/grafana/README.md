# Grafana dashboard for Netlens

`netlens-dashboard.json` shows what Netlens exports at `/metrics`: the network health score, devices and uptime, internet speed and connections, Wi-Fi (airtime, neighbouring networks, signal, clients per radio), services and certificates, containers and virtual machines, backups, Netlens itself, and (for devices with an SNMP or SSH health monitor) traffic, link utilisation, errors, processor, memory, disk and temperature.

## The quick way: one command

```sh
cd contrib/grafana/stack
cp .env.example .env                                  # choose the Grafana password
echo -n "nl_your_token_here" > prometheus/netlens.token   # a read-only API token: Netlens -> Settings -> Users & tokens
$EDITOR prometheus/prometheus.yml                     # put the address of Netlens in "targets"
docker compose up -d
```

Open `http://<this host>:3000`. Prometheus collects the numbers, Grafana opens on the Netlens dashboard.

## The manual way

1. Create a **read-only API token** in Netlens (Settings -> Users & tokens -> New API token -> read-only).
2. Add Netlens to Prometheus (see `prometheus/prometheus.yml`, or `../prometheus/prometheus.yml` for the alert rules).
3. In Grafana: Dashboards -> New -> Import -> upload `netlens-dashboard.json` and pick your Prometheus data source.

Interface and sensor panels need a health monitor (SNMP or SSH) on the device; the *Monitored device* list at the top picks which. Wi-Fi channel panels need an access-point plugin that reports its radios (UniFi, Omada, OpenWrt, ASUS); the internet connection panels need a gateway plugin that reports them.

## Changing the dashboard

The file is generated: edit `build_dashboard.py`, run `python contrib/grafana/build_dashboard.py`, commit both.
