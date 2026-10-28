# Prometheus (host metrics)

Reads the **processor, memory, swap, disks, network traffic, load and uptime** of hosts from a **Prometheus**, **VictoriaMetrics**, **Mimir** or **Thanos Query** that already
scrapes them, and records them in Netlens like those of any monitored host: graphs, limits and alerts, the dashboard, reports, Ask, the assistant and MCP. A plugin of kind
`metrics` (needs Netlens 0.4.304).

Use it when a host cannot be probed (no SSH, WinRM or SNMP, no stored login) and your company already has a metrics stack: no second agent is needed. For hosts with no stack at all,
Netlens can receive the readings from a collector instead (*Host agents*, Enterprise edition, see `HOST-AGENTS.md`).

## Set up

1. In Netlens: Settings → Plugin store → *Prometheus (host metrics)* → install and open its settings.
2. **Address**: the base address of the Prometheus API, for example `https://prometheus.example.com:9090` (a path prefix such as `/prometheus` is fine). HTTPS is assumed when
   you leave the scheme out. Plain `http://` is refused unless you switch on **Allow plain http** (a lab, or a store on the same machine).
3. **Login**: a **bearer token**, or a user name and password (basic), if your store needs one. Use a read-only user or token: the plugin only calls `/api/v1/query` and
   `/api/v1/query_range`. A self-signed certificate: paste its SHA-256 **fingerprint** (exactly that certificate is then trusted), or turn off *Verify TLS certificate*.
4. **Test**. The message says how many Linux (node_exporter) and Windows (windows_exporter) hosts it found.
5. Optional: **Only these jobs** limits the hosts to some Prometheus job names (`node, windows`).

## What it reads

| Reading | node_exporter (Linux, BSD, macOS) | windows_exporter |
|---|---|---|
| `cpu_pct` | `node_cpu_seconds_total{mode="idle"}` | `windows_cpu_time_total{mode="idle"}` |
| `load1` | `node_load1` | |
| `mem_pct` | `node_memory_MemAvailable_bytes` / `MemTotal_bytes` | `windows_os_physical_memory_free_bytes` / `windows_cs_physical_memory_bytes` |
| `swap_pct` | `node_memory_SwapFree_bytes` / `SwapTotal_bytes` | |
| `disk_pct`, `disk_free_b` per mount point | `node_filesystem_avail_bytes` / `_size_bytes` (virtual file systems and tiny ones skipped) | `windows_logical_disk_free_bytes` / `_size_bytes` |
| `net_rx_bps`, `net_tx_bps` per interface | `node_network_receive/transmit_bytes_total` (loopback, docker, veth and similar skipped) | `windows_net_bytes_received/sent_total` |
| `uptime_s` | `node_boot_time_seconds` | `windows_system_boot_time_timestamp_seconds` |

The queries are fixed in the plugin. The only thing typed in a query is a job name, which may hold only letters, digits and `_ . : -`, so it cannot change the query.

The host's name comes from `node_uname_info` / `windows_cs_hostname`, its address from the `instance` label when that is an IP address. Netlens matches a host to a device by **IP address,
then MAC, then name**; a name shared by two devices is never guessed. A device that is **monitored another way** (SNMP, SSH, WinRM, a host agent, another plugin) is left alone.

**History:** each sync also takes the store's own readings of the last *History to take over* minutes (default 20, step 60 s), so the graphs are as dense as the store's even
when Netlens syncs every few minutes; samples that are already stored are overwritten, so a window that repeats does no harm. Set it to 0 to read only the newest value. Keep it longer than
the time between syncs, or there will be gaps.

## Security

- **Read-only**: only `GET` requests to `/api/v1/...`. Nothing is sent to the hosts.
- **HTTPS by default**; plain http only with *Allow plain http*. Certificate verification or **pinning by fingerprint**. The token or password is never written to a log or a
  diagnostic report, and a refused login pauses the plugin (so a wrong token cannot lock an account).
- Settings are checked before anything is sent. At most 2000 hosts, 40 disks and 20 interfaces per host, 30 MB per answer.
- The plugin runs in the Netlens plugin runner, which holds no secrets of Netlens.

## Diagnostic

*Run diagnostic* on the plugin's page makes a report with field names, types and counts only: no host names, addresses, labels or secrets.

## What was tested

- Against a **real Prometheus 3.15.1 scraping a real node_exporter** on Debian 13: every reading above except swap on a host without swap, with history; the recorded answers
  (anonymised) are the test fixtures.
- The TLS transport (certificate pinning, verification, refusal) against a local HTTPS server; the bearer and basic login; the refusal paths; the job filter (including hostile
  input); the contract and the way Netlens records the readings (matching, history, repeated windows, devices monitored another way, limits and alerts).
- **Not tested on a real system:** windows_exporter (the Windows answers in the tests are written from its documentation; metric names changed between versions: the uptime query
  tries both names), VictoriaMetrics, Mimir, Thanos, a store behind a reverse proxy with a path prefix, and an authenticated store.
