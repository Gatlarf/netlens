# Host agents: monitoring hosts that cannot be reached from Netlens

*Enterprise edition and the free trial. Settings → Host agents.*

The host probes and the SNMP, SSH and WinRM monitors all **connect to** the host. In a locked-down zone that is exactly what the firewall forbids, and the security
team does not want a login for a monitoring system on every machine. What such a zone usually allows is **one outbound connection to a collector**.

A **host agent** is that outbound path. A standard collector that your company already trusts (the OpenTelemetry Collector or Telegraf) runs on the host and **pushes**
its readings to Netlens over HTTPS, proving who it is with a client certificate. Netlens only listens and answers. It never sends a command, a setting or an update to
a host, and it holds no login for it.

* [When to use which way of monitoring](#when-to-use-which-way-of-monitoring)
* [How it works](#how-it-works)
* [Security model](#security-model)
* [Set up Netlens](#set-up-netlens)
* [Enrol a host](#enrol-a-host)
* [Set up the collector](#set-up-the-collector) — Debian/Ubuntu, RHEL family, SUSE, Windows Server, Telegraf, FreeBSD, AIX, Solaris and other Unix, containers, gateways
* [Certificates: renewal, revocation, your own CA](#certificates)
* [What you see in Netlens](#what-you-see-in-netlens)
* [Troubleshooting](#troubleshooting)
* [Reference](#reference)
* [What was tested](#what-was-tested)

## When to use which way of monitoring

| | Host probes / SSH / WinRM / SNMP | Host agent (this page) |
|---|---|---|
| Direction | Netlens connects to the host | the host connects to Netlens |
| Needs on the host | an open port (22, 5986, 161) and a login or community | an outbound rule to Netlens and a collector |
| Stored on Netlens | a login or key per host (encrypted) | nothing that can log in anywhere: only a CA and per-host certificate *fingerprints* |
| What you get | the full picture: the nine read-only probes (storage, SMART, RAID, services, logins, updates, ports ...) | the numbers: processor, memory, swap, disks, network traffic, load, uptime, with the same limits, alerts, graphs and AI as any other monitored host |
| Good for | hosts you may log in to | locked-down hosts, DMZs, regulated zones, hosts the security team will not give a login |

**If the company already runs Prometheus** (or VictoriaMetrics, Mimir, Thanos), you may not need an agent at all: the *Prometheus (host metrics)* plugin reads the readings of the hosts that `node_exporter` and `windows_exporter` already report, with no new listener in Netlens and nothing installed on the hosts (see `plugins/prometheus`). The host agents on this page are for hosts with no such stack.

The two are not mixed on one device: a device is monitored one way. Link a device to an agent and remove its other monitor first (Netlens refuses otherwise, and says so).

## How it works

```
 locked-down host                                   Netlens
 ┌──────────────────────┐   HTTPS, client cert    ┌─────────────────────────────┐
 │ collector            │ ─────────────────────▶  │ :4318  readings (mTLS only) │
 │ (OTel Collector or   │   POST /v1/metrics      │ :4319  enrolment (window)   │
 │  Telegraf)           │   POST /telegraf        └─────────────────────────────┘
 └──────────────────────┘
        nothing flows the other way: no command, no setting, no update
```

1. In Netlens you add an **agent** and link it to the device it reports for. You get a **one-time token**.
2. On the host you make a key pair (the private key never leaves the host), and send a certificate request with the token to the **enrolment port**, which is open only
   during an **enrolment window** you start. Netlens answers with a certificate (valid 30 days).
3. The collector connects to the **readings port** with that certificate. A connection without a valid certificate ends in the TLS handshake, before any request is read.
4. Netlens turns the readings into the ones it already knows (processor, memory, disk ...) and handles them like any other monitor: graphs, limits, alerts, the
   dashboard, reports, Ask, the assistant and MCP.
5. If the host stops sending, Netlens says so (**agent silent**). If the certificate is about to end, Netlens says so too.

## Security model

The feature was designed so that the new listener is as small a risk as possible. What follows is what Netlens does, and what it deliberately does not do.

| Principle | How it is done |
|---|---|
| **Outbound only from the host** | Netlens never connects to a host, never answers with a command, setting or update. A compromised Netlens cannot use this channel to reach the hosts. |
| **Off by default, licence-gated** | Nothing listens until an administrator switches it on (and has the Enterprise edition or trial). Switching it off closes both ports. |
| **Identity from the certificate, never from the data** | Who sent a request is decided by the client certificate, looked up on every request (so revoking works on open connections too). The host name inside the data is ignored for an agent linked to one device. |
| **No anonymous access to any parser** | The readings port requires a client certificate (mutual TLS, TLS 1.2 or newer). Without one the handshake fails and nothing is read. |
| **Short-lived, per-host certificates** | A certificate made by Netlens is valid 30 days, belongs to one agent and can be revoked at once. The private key is made on the host and never exists on Netlens. |
| **A dedicated CA** | The CA that signs agent certificates is used for nothing else (not for the SSH CA of the host probes). It signs only client-authentication certificates. Its key is stored encrypted like the other secrets. |
| **One-time, short enrolment** | A token works once, ends after 24 hours, is stored only as a hash and is shown once. The enrolment port is open only during a window (5 to 240 minutes) that you start. Every refusal gets the same generic answer; attempts are rate limited. |
| **The request cannot choose the certificate** | Netlens builds the certificate from the public key only. The subject, extensions and validity in the request are ignored. Only strong keys are accepted (EC P-256/384/521, Ed25519, RSA from 3072 bits). |
| **Accept as little as possible** | JSON only (no protobuf or gRPC). Only a short allow-list of numeric metrics is used; everything else is ignored. Every label is limited to 40 safe characters; numbers must be plausible; timestamps must be within the last day or five minutes ahead. |
| **Nothing the sender writes is stored or shown** | Names of hosts, devices, mounts and so on come from Netlens or from a strict alphabet. Free text from a sender never reaches the database, a screen, an alert or the AI, so it cannot be used to manipulate them. |
| **Hard limits** | 1 MiB per request (also after decompression: a gzip bomb is refused), nesting depth, 2000 data points and 200 hosts per request, request rate per agent, 4 connections per agent and 64 in all, timeouts for slow clients. |
| **Audit and events** | Switching on and off, enrolment windows, tokens, certificates issued/renewed/revoked and every refusal go to the audit log (and to your SIEM through log forwarding). Repeated refusals from one address are written once a minute so a flood cannot flood the log. |
| **Can not be driven by an assistant** | The settings, tokens and certificates are for administrators on the local network only; an AI assistant token can never use them (it can read the status). |
| **Keys stay out of reach** | The CA key and the server key are encrypted in the database and never returned by the API. |

### Threats considered

| Threat | Effect | What limits it |
|---|---|---|
| Stolen client key | false readings **for that one host** | 30-day certificates, revoke at once, the key stays on the host with restricted rights |
| Leaked enrolment token | an attacker enrols as that host | works once, 24 h, window needed; the real host's own enrolment then fails visibly and the agent shows "enrolled" |
| Compromised host | false readings for itself only | identity-bound, allow-list, limits; no way to other hosts or into Netlens |
| Compromised Netlens | cannot push anything to the hosts | there is no channel back |
| Anonymous probing or flooding | tries to exhaust the listener | mutual TLS before any parsing, connection caps, timeouts, separate ports so the web interface is not affected |
| Hostile or malformed data | parser crash, memory use | JSON only, size/depth/point limits, decompression cap, type-safe parsing, fuzz-tested |
| Prompt injection through data | the AI is manipulated | no free text from a sender is accepted at all |
| A proxy that terminates TLS | the client certificate is lost | do not put an HTTP proxy in front; use TCP passthrough ([below](#network-and-reverse-proxies)) |

### What Netlens does not do (limits you should know)

* A certificate from **your own CA** is not checked against a revocation list; revoke the agent in Netlens instead (the record is what is checked on each request).
* A client that fails the TLS handshake (wrong CA, expired certificate) is rejected by the TLS layer and **not** logged one by one; a known agent that stops this way
  shows up as *silent* and, before that, as *certificate ending*.
* Strict X.509 validation (`X509_STRICT`) is not enforced, so certificates from older enterprise CAs work.
* The password-less private keys of the hosts are protected by file permissions only; use the rights shown in the examples.

## Set up Netlens

Settings → **Host agents (locked-down hosts)**.

1. **Name or address the collectors connect to:** every name or IP address that a collector uses to reach Netlens, comma separated. It goes into the server certificate,
   and a collector refuses a name that is not in it.
2. **Listen on / ports:** `0.0.0.0` listens on every interface; give one address to listen on a single one. **4318** is the standard OTLP/HTTP port; **4319** is the
   enrolment port (open only during a window). Change them if they are taken.
3. Tick **Receive readings from host agents** and **Save**. The status line shows *Listening on ...*.
4. **Download the CA certificate (ca.pem).** Every host needs it to recognise Netlens.

### Network and reverse proxies

* **Firewall:** allow the hosts to reach Netlens on TCP 4318 (always) and 4319 (while enrolling). Nothing inbound to the hosts is needed.
* **Docker:** with the default `network_mode: host` the ports are reachable at once. Without host networking, publish them (`ports: ["4318:4318", "4319:4319"]`).
* **Reverse proxy:** client certificates **cannot** pass through a proxy that ends TLS (the proxy would see the certificate, Netlens would not), and Netlens never trusts a
  header that claims who the client is. Expose the ports directly, or use **TCP passthrough**:

  ```nginx
  # nginx, stream context: pass the TLS connection through untouched
  stream {
      server { listen 4318; proxy_pass netlens.internal:4318; }
      server { listen 4319; proxy_pass netlens.internal:4319; }
  }
  ```
  HAProxy: `mode tcp` frontends and backends. A cloud load balancer must be a layer-4 (TCP) one.
* **Server certificate:** by default Netlens makes one from the names you gave, signed by its ingest CA (the hosts trust `ca.pem`). To use a certificate from your
  company CA instead, paste it with its key under *Server certificate* (the hosts then trust your CA).

## Enrol a host

1. Settings → Host agents → **Open an enrolment window** (default 30 minutes).
2. **Add an agent:** a name, the device it reports for, how often it sends (default 60 s). Netlens shows the **token once**, with the commands below filled in.
3. On the host, make a key and a certificate request, and enrol. The private key stays on the host.

**Linux, BSD and other Unix** (as root; `ca.pem` is the file downloaded from Netlens):

```sh
install -d -m 0750 /etc/netlens-agent && cd /etc/netlens-agent
# put ca.pem here
openssl ecparam -name prime256v1 -genkey -noout -out agent.key && chmod 600 agent.key
openssl req -new -key agent.key -subj "/CN=$(hostname)" -out agent.csr
curl --fail --cacert ca.pem -H "Authorization: Bearer nlt_THE_TOKEN" --data-binary @agent.csr \
     https://NETLENS:4319/enrol -o agent.crt
openssl x509 -in agent.crt -noout -subject -enddate      # CN=netlens-agent-<id>, ends in 30 days
```

**Windows Server**, in an elevated PowerShell. With **PowerShell 7.4 or newer** no extra software is needed:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\netlens-agent | Out-Null; cd C:\ProgramData\netlens-agent
# put ca.pem here
$key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$env:COMPUTERNAME", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
Set-Content agent.key $key.ExportPkcs8PrivateKeyPem(); Set-Content agent.csr $req.CreateSigningRequestPem()
icacls agent.key /inheritance:r /grant:r "SYSTEM:(R)" "BUILTIN\Administrators:(F)"
curl.exe --fail --cacert ca.pem -H "Authorization: Bearer nlt_THE_TOKEN" --data-binary "@agent.csr" https://NETLENS:4319/enrol -o agent.crt
```

(`curl.exe` is part of Windows 10 and Server 2019 and newer.) Windows PowerShell 5.1 cannot export the key; use OpenSSL for Windows instead
(`openssl ecparam ... / openssl req ...` exactly as in the Linux example).

The window can be closed at any time (Close the window now); it closes by itself when it runs out. A token that was not used ends after 24 hours; *Enrol again* makes
a new one and cancels the old certificate at once.

**With a certificate from your own CA** no token is needed: upload your CA certificate (*Your own certificate authority*), add the agent with its **identity**
(`dns:web01.example.com`, `uri:spiffe://example/web01` or `cn:web01`, as it appears in the certificate), and let the collector use that certificate. A certificate that
chains to your CA but whose identity matches no agent is refused. Revoke an agent in Netlens to stop it even though the certificate itself is still valid.

## Set up the collector

Every example sends the same readings. Replace `NETLENS` with a name from the server certificate. The OpenTelemetry Collector must be the **contrib** distribution
(`otelcol-contrib`), which has the `hostmetrics` receiver.

### The configuration (OpenTelemetry Collector)

```yaml
receivers:
  hostmetrics:                       # newer versions call it host_metrics; the old name still works there
    collection_interval: 60s
    scrapers:
      cpu: {}
      memory: {}
      load: {}
      paging: {}
      filesystem: {}
      network: {}
      system: {}                     # uptime
processors:
  batch:
    timeout: 10s
exporters:
  otlphttp:                          # newer versions: otlp_http
    endpoint: https://NETLENS:4318
    encoding: json                   # required: Netlens accepts JSON only
    compression: gzip
    tls:
      ca_file: /etc/otelcol-contrib/netlens/ca.pem
      cert_file: /etc/otelcol-contrib/netlens/agent.crt
      key_file: /etc/otelcol-contrib/netlens/agent.key
service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [batch]
      exporters: [otlphttp]
```

`otelcol-contrib components` lists the names your version knows. The `batch` processor groups the readings; the `resource` or `host.name` settings are not needed for an
agent linked to one device (the name in the data is ignored).

### Debian and Ubuntu

```sh
curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.164.0/otelcol-contrib_0.164.0_linux_amd64.deb
sudo dpkg -i otelcol-contrib_0.164.0_linux_amd64.deb         # creates the user and the service "otelcol-contrib"
sudo install -d -m 0750 -o root -g otelcol-contrib /etc/otelcol-contrib/netlens
sudo cp /etc/netlens-agent/{ca.pem,agent.crt,agent.key} /etc/otelcol-contrib/netlens/
sudo chown root:otelcol-contrib /etc/otelcol-contrib/netlens/*; sudo chmod 0640 /etc/otelcol-contrib/netlens/agent.key
sudoedit /etc/otelcol-contrib/config.yaml                    # the configuration above
sudo systemctl enable --now otelcol-contrib
journalctl -u otelcol-contrib -f                             # no errors; in Netlens the agent shows "last data a moment ago"
```

Use `_linux_arm64.deb` on ARM. Pick the current version from the [releases page](https://github.com/open-telemetry/opentelemetry-collector-releases/releases).

### Red Hat Enterprise Linux, Rocky, AlmaLinux, Oracle Linux, Amazon Linux, Fedora

```sh
curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.164.0/otelcol-contrib_0.164.0_linux_amd64.rpm
sudo dnf install ./otelcol-contrib_0.164.0_linux_amd64.rpm   # (yum on RHEL 7)
# then exactly as on Debian: certificate folder, chown/chmod, config.yaml, and
sudo systemctl enable --now otelcol-contrib                  # the package does not enable the service by itself on RPM systems
```

With **SELinux enforcing** keep the files under `/etc/otelcol-contrib/` as shown; the collector runs unconfined. (The package install and the file locations were checked
on Rocky Linux 9; SELinux enforcing was not.) `s390x` and `ppc64le` packages exist for IBM Z and Power.

### SUSE Linux Enterprise and openSUSE

```sh
curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.164.0/otelcol-contrib_0.164.0_linux_amd64.rpm
sudo zypper --no-gpg-checks install ./otelcol-contrib_0.164.0_linux_amd64.rpm
# certificate folder, chown/chmod and config.yaml as on Debian, then
sudo systemctl enable --now otelcol-contrib
```

The package is not signed, hence `--no-gpg-checks`; verify the download against the checksum published with the release instead.

### Windows Server

1. Download `otelcol-contrib_<version>_windows_x64.msi` from the releases page and install it (`msiexec /i otelcol-contrib_0.164.0_windows_x64.msi /qn`). It installs
   to `C:\Program Files\OpenTelemetry Collector\` and registers the service **otelcol-contrib** (starts automatically, runs as *LocalSystem*).
2. Enrol the host as shown above; the files are in `C:\ProgramData\netlens-agent\` (readable for SYSTEM and Administrators only, which is who the service runs as).
3. Replace `C:\Program Files\OpenTelemetry Collector\config.yaml` with the configuration above, using these paths:

   ```yaml
       tls:
         ca_file: C:\ProgramData\netlens-agent\ca.pem
         cert_file: C:\ProgramData\netlens-agent\agent.crt
         key_file: C:\ProgramData\netlens-agent\agent.key
   ```
4. `Restart-Service otelcol-contrib`. Errors are in the Windows *Application* event log (source `otelcol-contrib`).
5. Outbound: allow TCP 4318 from the server to Netlens. Nothing inbound is needed.

*(The MSI's service name, install folder and default configuration were read from the package itself; the collector was not run on Windows here. The PowerShell enrolment
and renewal were run on PowerShell 7.4.)*

### Telegraf (Linux, Windows, FreeBSD, macOS)

Telegraf is often already installed. It sends its **JSON** output to `/telegraf` on the same port. Add to `telegraf.conf`:

```toml
[agent]
  interval = "60s"
  flush_interval = "60s"

[[inputs.cpu]]
  percpu = false
  totalcpu = true
[[inputs.mem]]
[[inputs.swap]]
[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]
[[inputs.net]]
[[inputs.system]]

[[outputs.http]]
  url = "https://NETLENS:4318/telegraf"
  method = "POST"
  data_format = "json"            # required
  use_batch_format = true
  content_encoding = "gzip"
  tls_ca   = "/etc/netlens-agent/ca.pem"
  tls_cert = "/etc/netlens-agent/agent.crt"
  tls_key  = "/etc/netlens-agent/agent.key"
  [outputs.http.headers]
    Content-Type = "application/json"
```

* **Linux:** install the Telegraf package from your repository or from the vendor (`telegraf`), put the files where the `telegraf` user can read them, `systemctl enable --now telegraf`.
* **Windows:** unpack `telegraf-<version>_windows_amd64.zip`, then `telegraf.exe --service install --config "C:\Program Files\Telegraf\telegraf.conf"` and
  `telegraf.exe --service start`; use the certificate paths under `C:\ProgramData\netlens-agent\`.
* **FreeBSD:** `pkg install telegraf`, put the config in `/usr/local/etc/telegraf.conf`, `sysrc telegraf_enable=YES`, `service telegraf start`. Telegraf is the supported
  collector there (the OpenTelemetry Collector has no FreeBSD build).
* **macOS:** `brew install telegraf` (or the OpenTelemetry Collector `darwin` tarball).

Telegraf measurements used: `cpu` (the `cpu-total` row), `mem`, `swap`, `disk`, `net`, `system`. Others are ignored.

### AIX, Solaris, HP-UX and other Unix

* **AIX:** an `otelcol-contrib_<version>_aix_ppc64.tar.gz` build exists on the releases page. Unpack it and use the configuration above with a service or `inittab`
  entry of your choice. *We could not run it on AIX; which `hostmetrics` scrapers deliver data there is up to the collector, so check the result in Netlens.*
* **Solaris, HP-UX and anything else without a collector:** use the small shell script `contrib/netlens-push.sh`. It is plain POSIX `sh`, read-only, and sends load,
  uptime and disk usage with `curl` and the host's certificate. Run it from cron every minute:

  ```sh
  * * * * * NETLENS_URL=https://NETLENS:4318/telegraf NETLENS_DIR=/etc/netlens-agent /opt/netlens/netlens-push.sh
  ```

  Check what it would send first: `NETLENS_DRY_RUN=1 NETLENS_URL=x ./netlens-push.sh`. The script is tested on Linux (dash, bash, busybox). On Solaris set
  `NETLENS_DF=/usr/xpg4/bin/df`; on HP-UX `df -P` may need adapting. To send more (processor, memory, network), add objects in the [format below](#the-json-format-for-your-own-sender)
  from `vmstat`, `sar` or `kstat` of that system.

### Containers and Kubernetes

Run the collector as a DaemonSet (or a sidecar for one container) with the contrib image and the `hostmetrics` receiver with `root_path: /hostfs` and the node's root
mounted read-only at `/hostfs`. In Kubernetes the usual design is a **gateway** (below): node collectors send to one gateway collector, which holds the certificate.

### Gateways: one collector for many hosts

A central collector (or Prometheus-style gateway) can forward for many hosts, so the individual hosts need no route to Netlens at all. Give the gateway **one** agent
that is linked to **several devices**, and for each device the host name the data carries (the OpenTelemetry resource attribute `host.name`, or the `host` tag of Telegraf):

* add the agent, tick several devices, and under *Names in the data* write `device name = name in the data`, one per line;
* only those hosts are accepted; data about any other host is dropped and counted;
* the gateway's certificate and key are the only ones in play. This is the one case where a name from the data is used, and only to choose among the devices you listed.

## Certificates

* A certificate made by Netlens is valid for **30 days**. The collectors do **not** renew it by themselves: schedule the renewal script. Without it the host goes
  silent when the certificate ends. Netlens warns 7 days before (an event, and a problem on the dashboard).
* **Renewal** presents the current certificate and a new request to `https://NETLENS:4318/renew`; the answer is the new certificate followed by the CA certificate(s) Netlens uses, which the scripts merge into `ca.pem`. The old certificate keeps working for at most 7 more days, so a failed
  restart does not lose the host. A certificate that has already ended cannot renew: enrol again. At most one renewal per hour.

  Linux (`contrib/netlens-renew.sh`, needs `openssl` and `curl`), once a day from cron or a timer:

  ```sh
  0 3 * * * NETLENS_RENEW_URL=https://NETLENS:4318/renew NETLENS_DIR=/etc/otelcol-contrib/netlens NETLENS_OWNER=root:otelcol-contrib \
            NETLENS_RESTART="systemctl restart otelcol-contrib" /opt/netlens/netlens-renew.sh
  ```

  It does nothing until fewer than 20 days are left (`NETLENS_RENEW_DAYS`).

  Windows (`contrib/netlens-renew.ps1`, PowerShell 7.4+), as a scheduled task running as SYSTEM once a day:

  ```powershell
  pwsh -File C:\ProgramData\netlens-agent\netlens-renew.ps1 -RenewUrl https://NETLENS:4318/renew -Service otelcol-contrib
  ```

  With the certificate in `C:\ProgramData\netlens-agent\` as in the examples.
* **Revoke** (Settings → Host agents → Revoke): refused from the next request on, including on connections that are already open. **Enrol again** makes a new token and
  cancels the current certificate. **Delete** removes the agent and the monitor it fed; the stored readings stay.
* **Server certificate:** the one Netlens makes lasts about 13 months and is renewed when you change the names. Replace it with your own under *Server certificate*.
* **CA lifetime and rotation:** the ingest CA lasts 10 years. Netlens reports it in its last year (an event and a problem on the dashboard), and you can rotate it at any
  time (Settings → Host agents → **Rotate the CA**) without losing a host:
  1. A new CA is made. New and renewed certificates come from it. The **old CA stays trusted** and keeps signing the server certificate, because the hosts still trust only
     the old one.
  2. **Every host renews.** The renewal brings the new CA: the renewal scripts add it to `ca.pem` (the old one stays, so the host trusts Netlens before and after).
     Run the script with `NETLENS_RENEW_DAYS=40` (PowerShell: `-RenewDays 40`) to renew at once; with the daily schedule every host renews by itself within about ten days.
  3. The panel lists the agents that still hold a certificate from the old CA. When it says every agent has one from the new CA, press **Finish the rotation**. Netlens
     stops trusting the old CA and signs the server certificate with the new one.
  4. **Finish anyway** locks out the agents still on the old CA until they are enrolled again (Netlens asks first and writes it to the audit log). **Cancel the rotation**
     is possible until the first agent has a certificate from the new CA.

  Certificates from your own CA are not affected.
* **Your own CA:** certificates are checked against the CA certificates you uploaded; renew them with your own tooling; see [above](#enrol-a-host).

## What you see in Netlens

* The device shows the readings like any other monitored host (Health, graphs, limits). The method is **agent**; the monitor cannot be edited by hand, and a device
  that is monitored another way cannot be linked.
* **Settings → Host agents** lists each agent: state (*enrolled*, *waiting for enrolment*, *revoked*, **silent**), when it last sent, from which address, readings
  accepted/dropped, requests refused, days left on the certificate.
* **Events and alerts:** *Agent silent* (no data for three times the sending interval, at least three minutes, or an hour for an agent that never sent anything; once, and *Agent sending again* when it recovers),
  *Agent certificate ending* (7 days before, once a day), *Agent enrolled*. They go to your alert channels and log forwarding like other events, and the silent agent and
  the ending certificate are on the dashboard's list of problems. Silence is not the same as the host being down: the network or the collector may be the cause,
  so combine it with a ping or service check.
* **Audit log:** every change and every refusal, as described under [Security model](#security-model).
* **AI:** the Ask question "which agents are silent?", the MCP tool `get_agent_status` and `GET /api/agent-status` give the status without secrets; the readings are
  available to Ask, the assistant, reports and the investigation like those of any other host.

## Troubleshooting

| What you see | Likely cause and fix |
|---|---|
| The collector logs `x509: certificate is valid for ..., not NETLENS` | the name in `endpoint` is not in the server certificate. Add it under *Name or address the collectors connect to* and save. |
| `x509: certificate signed by unknown authority` | `ca_file` is not the `ca.pem` of this Netlens (or you uploaded your own server certificate: trust your CA). |
| `remote error: tls: bad certificate` or the connection is closed right after the handshake | the client certificate is expired, not from a CA Netlens trusts, or no `cert_file`/`key_file` is set. Check `openssl x509 -in agent.crt -noout -dates -issuer`. |
| HTTP **403** `certificate not known to any agent` | the certificate is valid but no agent owns it: it was replaced by *Enrol again*, deleted, or (own CA) the identity does not match. |
| HTTP **403** `agent is revoked` | revoked in Netlens. *Enrol again* (Netlens certificate) or *Allow again* (own CA). |
| HTTP **415** | the exporter sends protobuf. Set `encoding: json` (OTel) or `data_format = "json"` (Telegraf). |
| HTTP **429** | more than about 12 requests a minute from one agent. Raise the batch timeout / interval. |
| HTTP **413** | a request over 1 MiB or too many data points. Send less often with fewer scrapers, or split the host's collector. |
| Enrolment says `enrolment refused` | the token is wrong, used or older than 24 hours; make a new one. The answer is deliberately the same for every cause. |
| Enrolment: connection refused | no enrolment window is open (open one), or port 4319 is blocked. |
| Enrolment says `3072` | the key is too weak. Use `ecparam -name prime256v1` as shown. |
| Data arrives but the device shows nothing | the device is monitored another way (remove that monitor), or the readings are on another device (check the linked device). Note that CPU needs two rounds before it is shown. |
| The agent shows *silent* | the collector stopped, the host is down, the network or a firewall blocks 4318, or the certificate ended. Look at the collector's log first. |
| The clock | certificates and readings are time-bound: keep the host clock correct (NTP). A reading more than a day old or five minutes ahead is dropped. |
| `partialSuccess` warnings in the collector log | some readings were not usable (for example for a host that is not linked). Metrics Netlens does not use are ignored without a warning. |

## Reference

### Endpoints

| Port | Path | Needs | Purpose |
|---|---|---|---|
| 4318 | `POST /v1/metrics` | client certificate | OTLP/HTTP, JSON body (`Content-Type: application/json`, optional `Content-Encoding: gzip`) |
| 4318 | `POST /telegraf` | client certificate | Telegraf JSON format (also for your own sender) |
| 4318 | `POST /renew` | client certificate | body: a PEM certificate request; answer: a new certificate |
| 4319 | `POST /enrol` | `Authorization: Bearer <token>`, window open | body: a PEM certificate request; answer: the certificate and the CA certificate |

Answers: `200`, `400` unusable body, `403` unknown/revoked, `404`, `405`, `413` too large, `415` wrong format, `429` too many requests, `503` switched off.

### What is used from the OpenTelemetry metrics

| OpenTelemetry metric (attributes) | Becomes |
|---|---|
| `system.cpu.time` (`state`, `cpu`) — two requests are compared | `cpu_pct` (or `system.cpu.utilization` with `state=idle`) |
| `system.cpu.load_average.1m` | `load1` |
| `system.memory.usage` (`state`: used, free, cached ...) | `mem_pct` (used ÷ everything) |
| `system.paging.usage` (`state`: used, free) | `swap_pct` |
| `system.filesystem.usage` (`mountpoint`, `type`, `state`: used, free) | `disk_pct`, `disk_free_b` per mount point; virtual file systems (tmpfs, overlay, /proc ...) are skipped |
| `system.network.io` (`device`, `direction`) — two requests are compared | `net_rx_bps`, `net_tx_bps` per interface (loopback, docker, veth and similar skipped) |
| `system.uptime` | `uptime_s` |

### The JSON format for your own sender

The format Telegraf produces; any script can send it. One object, a list, or `{"metrics": [...]}`; `timestamp` in seconds.

```json
{"metrics": [
  {"name": "cpu",    "tags": {"cpu": "cpu-total"}, "fields": {"usage_idle": 87.5},                   "timestamp": 1790000000},
  {"name": "mem",    "tags": {},                   "fields": {"used_percent": 41.2},                 "timestamp": 1790000000},
  {"name": "swap",   "tags": {},                   "fields": {"total": 1073741824, "used_percent": 3},"timestamp": 1790000000},
  {"name": "disk",   "tags": {"path": "/", "fstype": "xfs"}, "fields": {"used_percent": 61.0, "free": 52000000000}, "timestamp": 1790000000},
  {"name": "net",    "tags": {"interface": "eth0"}, "fields": {"bytes_recv": 123456789, "bytes_sent": 98765432}, "timestamp": 1790000000},
  {"name": "system", "tags": {},                   "fields": {"load1": 0.42, "uptime": 86400},      "timestamp": 1790000000}
]}
```

`net` counters grow; Netlens turns them into a rate from two requests. Mount points and interface names: letters, digits and `_ . : / \ @ + ( ) [ ] -` and spaces, up to 40 characters.

### Limits

| Limit | Value |
|---|---|
| Request size | 1 MiB (also after decompression) |
| Data points per request | 2000 (more is refused with 413) |
| Hosts (resources) per request | 200 |
| Disks per host | 80; interfaces per host 64 |
| Request rate per agent | burst 10, then one every 5 seconds |
| Connections | 4 per agent, 64 in all; idle connections close after 60 s; 200 requests per connection |
| Timestamps | not older than 24 hours, not more than 5 minutes ahead |
| Token | 24 hours, once; certificate 30 days; renewal overlap up to 7 days, once per hour |
| Enrolment window | 5 to 240 minutes |
| Silence | no data for 3× the sending interval (at least 3 minutes); an agent that has never sent anything is reported after an hour |

### Settings API (administrators, local network)

`GET/PUT /api/ingest`, `POST/DELETE /api/ingest/window`, `GET /api/ingest/ca.pem`, `POST /api/ingest/ca/rotate|finish|cancel`, `PUT /api/ingest/own-ca`, `PUT /api/ingest/server-certificate`,
`POST /api/ingest/agents`, `PUT/DELETE /api/ingest/agents/{id}`, `POST /api/ingest/agents/{id}/token|revoke|reinstate`. Read-only for everyone who may view:
`GET /api/agent-status`. An AI assistant token cannot use `/api/ingest`.

## What was tested

* **Automatically (every release):** enrolment (one-time token, expiry, generic refusal, weak key, rate limit, closed window), mutual TLS (no certificate, foreign CA,
  unknown certificate, revoked on an open connection, re-enrolment), the limits (size, gzip bomb, nesting, points, content type), identity (host name in the data ignored,
  gateway mapping), your own CA (identity matching, refused leaf and expired CAs), renewal and overlap, CA rotation from start to finish (with the real renewal script and a forced finish), silence and expiry events, the licence gate, the API, the
  encrypted CA key, nothing from a sender stored, and a fuzz test of the parsers.
* **With the real software:** OpenTelemetry Collector 0.164.0 (as a process and as the Debian package under systemd) and Telegraf 1.40.2 against a running Netlens;
  enrolment with `openssl` and `curl` and with PowerShell 7.4; the RPM installs on Rocky Linux 9 and openSUSE Leap 15.6; the shell sender and both renewal scripts.
* **Not tested here:** Windows (the MSI facts were read from the package; the PowerShell scripts ran on PowerShell 7.4 on Linux), AIX, Solaris, HP-UX, FreeBSD,
  macOS, SELinux enforcing, Kubernetes, and certificates from a real enterprise CA. The documentation says so where it matters.
