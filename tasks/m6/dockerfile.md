Create the file Dockerfile for the Netlens app (Python 3.12). Requirements, in this order:
- FROM python:3.12-slim. ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 NETLENS_DATA_DIR=/data NETLENS_BIND=0.0.0.0:8080 NMAP_PRIVILEGED=1.
- One RUN layer: apt-get update; apt-get install -y --no-install-recommends nmap iproute2 libcap2-bin ca-certificates; then give the nmap binary file capabilities so a non-root user can do raw scans: setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f "$(command -v nmap)")"; then rm -rf /var/lib/apt/lists/*.
- Create a non-root system user and group "netlens" with uid/gid 10001, home /app, shell /usr/sbin/nologin; create /data owned by netlens (mode 0750).
- WORKDIR /app; COPY requirements.txt .; RUN pip install -r requirements.txt; COPY app ./app (this includes app/static).
- USER netlens; VOLUME ["/data"]; EXPOSE 8080.
- HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 using python -c to GET http://127.0.0.1:<port>/api/health where <port> comes from the part after the last colon of the NETLENS_BIND environment variable (default 8080); exit code 1 on any failure or non-200.
- CMD ["python", "-m", "app.main"].
Add short comments explaining the setcap line and why --no-new-privileges must not be used with file capabilities. Output only the Dockerfile.
