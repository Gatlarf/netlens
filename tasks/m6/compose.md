Create docker-compose.yml (Compose specification, no "version:" key) for service "netlens":
- build: . ; image: netlens:latest; container_name: netlens; restart: unless-stopped.
- network_mode: host (needed for ARP/L2 discovery and mDNS/SSDP); a comment says the app then listens on NETLENS_BIND (default 0.0.0.0:8080) on the Docker host.
- cap_drop: [ALL]; cap_add: [NET_RAW, NET_ADMIN]. Do NOT set security_opt no-new-privileges (comment: it would disable the file capabilities on nmap).
- read_only: true; tmpfs: ["/tmp"]; volumes: ["netlens-data:/data"].
- environment (values from the .env file with defaults): NETLENS_TOKEN: ${NETLENS_TOKEN:?Set NETLENS_TOKEN in .env (a long random string)}; NETLENS_RANGES: ${NETLENS_RANGES:-}; NETLENS_QUICK_INTERVAL: ${NETLENS_QUICK_INTERVAL:-900}; NETLENS_DEEP_INTERVAL: ${NETLENS_DEEP_INTERVAL:-86400}; NETLENS_TERMINAL: ${NETLENS_TERMINAL:-on}; NETLENS_SNMP_COMMUNITY: ${NETLENS_SNMP_COMMUNITY:-}; NETLENS_BIND: ${NETLENS_BIND:-0.0.0.0:8080}.
- A top-level volumes: netlens-data: {}.
- Add comments on each non-obvious line. Output only the YAML.
