# Grafana dashboard for Netlens

`netlens-dashboard.json` shows the numbers Netlens exports at `/metrics`: devices, uptime, events, Wi-Fi, services, certificates, backups and internet speed, and (for devices with an SNMP or SSH health monitor) traffic, link utilisation and errors per network interface plus processor, memory, disk and temperature.

1. Create a **read-only API token** in Netlens (Settings -> Users & tokens -> New API token -> read-only).
2. Add Netlens to Prometheus:

   ```yaml
   scrape_configs:
     - job_name: netlens
       metrics_path: /metrics
       scrape_interval: 60s
       authorization:
         type: Bearer
         credentials: nl_your_token_here
       static_configs:
         - targets: ["netlens.example.com:8080"]
   ```
3. In Grafana: Dashboards -> New -> Import -> upload `netlens-dashboard.json` and choose your Prometheus data source.

Interface and sensor graphs need a health monitor (SNMP or SSH) on the device. Use the *Device* drop-down at the top to pick devices.
